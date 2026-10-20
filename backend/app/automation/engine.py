"""
The automation engine: runs each watcher on its own timer in a background thread.

    uvicorn starts  ->  start_all()  ->  one thread per watcher
                                          every N seconds: watcher.check()  ->  new items analysed
                                          -> saved like a manual scan -> alert if risky
    uvicorn stops   ->  stop_all()

* On/off switches and each watcher's "where was I" bookmark (last email ID, files already seen ...)
  are kept in backend/automation_state.json, so a restart neither re-scans nor misses things.
* A watcher that fails (wrong password, no permission ...) only records the error in its status;
  it never crashes the backend and it tries again on the next round.
* Everything here only READS (emails, logs, files). Nothing is deleted, moved, opened or run.
"""
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger("cyberguard.automation")
STATE_FILE = os.environ.get("AUTOMATION_STATE_FILE") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "automation_state.json")
_state_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_state() -> dict:
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    # On Windows, antivirus / search indexing can hold a just-written file open for a moment, and then the
    # swap fails with "Access is denied" (WinError 5). That is temporary, so wait briefly and try again.
    for attempt in range(10):
        try:
            os.replace(tmp, STATE_FILE)
            return
        except PermissionError:
            if attempt == 9:
                raise
            time.sleep(0.05 * (attempt + 1))


def update_state(name: str, **values) -> dict:
    with _state_lock:
        state = load_state()
        state.setdefault(name, {}).update(values)
        save_state(state)
        return state[name]


def get_state(name: str) -> dict:
    with _state_lock:
        return dict(load_state().get(name, {}))


class Watcher:
    """Base class. Subclasses set name/title/what and implement configured() and check()."""
    name = "watcher"
    title = "Watcher"
    what = ""
    modules: list[str] = []
    technology = ""
    interval_seconds = 60

    def __init__(self):
        self.status = {"running": False, "lastCheck": None, "lastError": None, "checked": 0, "threats": 0,
                       "lastFinding": None, "note": "", "recent": []}
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._busy = threading.Lock()

    def record(self, item: str, score: int, classification: str) -> None:
        """Remember one checked item (shown under 'Recently checked' in Settings) and print it in the terminal."""
        entry = {"at": _now_iso(), "item": item[:160], "score": int(score), "classification": classification}
        self.status["recent"] = ([entry] + self.status.get("recent", []))[:10]
        logger.info("[automation:%s] checked %s -> %s (score %s)", self.name, item[:120], classification, score)

    # -- to implement -------------------------------------------------------------------------
    def configured(self) -> tuple[bool, str]:
        """(True, '') when it can run, else (False, 'what the user must set up')."""
        return True, ""

    def check(self) -> dict:
        """Look for new items and analyse them. Return {'checked': n, 'threats': n, 'finding': str|None, 'note': str}."""
        raise NotImplementedError

    # -- engine ---------------------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return bool(get_state(self.name).get("enabled", True))

    def set_enabled(self, value: bool) -> None:
        update_state(self.name, enabled=bool(value))
        if value:
            self._wake.set()

    def run_once(self) -> dict:
        """One round, used by the timer and by the 'Check now' button. Never raises."""
        ok, why = self.configured()
        if not ok:
            self.status.update(lastCheck=_now_iso(), lastError=None, note=why)
            return self.status
        if not self._busy.acquire(blocking=False):
            return self.status                    # a round is already running
        try:
            out = self.check() or {}
            self.status["checked"] += int(out.get("checked", 0))
            self.status["threats"] += int(out.get("threats", 0))
            if out.get("finding"):
                self.status["lastFinding"] = out["finding"]
            self.status.update(lastCheck=_now_iso(), lastError=None, note=out.get("note", ""))
        except Exception as exc:  # noqa: BLE001 -- a watcher must never take the backend down
            logger.warning("automation %s failed: %s", self.name, exc)
            self.status.update(lastCheck=_now_iso(), lastError=str(exc)[:300])
        finally:
            self._busy.release()
        return self.status

    def _loop(self) -> None:
        self.status["running"] = True
        time.sleep(3)                               # let the web server finish starting
        while not self._stop.is_set():
            if self.enabled:
                self.run_once()
            self._wake.wait(self.interval_seconds)
            self._wake.clear()
        self.status["running"] = False

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name=f"automation-{self.name}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def describe(self) -> dict:
        ok, why = self.configured()
        state = ("off" if not self.enabled else "needs setup" if not ok else
                 "error" if self.status["lastError"] else "active")
        return {"name": self.name, "title": self.title, "what": self.what, "modules": self.modules,
                "technology": self.technology, "intervalSeconds": self.interval_seconds,
                "enabled": self.enabled, "configured": ok, "setupHint": why, "state": state, **self.status}


def owner_user_id(db) -> str | None:
    """The CyberGuard account that receives automatic findings (AUTOMATION_USER_EMAIL, else the first account)."""
    from app.core.config import get_settings
    from app.db.models import User
    email = get_settings().AUTOMATION_USER_EMAIL.strip().lower()
    q = db.query(User)
    user = q.filter(User.email == email).first() if email else None
    user = user or q.order_by(User.created_at.asc()).first()
    return user.id if user else None


def save_and_alert(*, module_id: str, subtopic_id: str, subtopic_title: str, result: dict, target: str,
                   target_type: str, source: str, metadata: dict | None = None, min_score: int = 26) -> str | None:
    """Save an automatic finding like a manual scan and send the usual alert. Returns the scan id (or None)."""
    from app.db.database import SessionLocal
    from app.services import notifier, scan_store
    if result.get("riskScore", 0) < min_score:
        return None
    db = SessionLocal()
    try:
        uid = owner_user_id(db)
        if not uid:
            return None
        scan = scan_store.save_result(db, user_id=uid, module_id=module_id, subtopic_id=subtopic_id,
                                      subtopic_title=subtopic_title, result=result, target=target,
                                      target_type=target_type, metadata={"automatic": True, **(metadata or {})},
                                      source=f"automation:{source}")
        db.commit()
        scan_id = scan.id
    finally:
        db.close()
    if result["riskScore"] >= notifier.ALERT_FLOOR:              # the owner's alert sensitivity decides
        notifier.alert_for_scan(scan_id)
    return scan_id
