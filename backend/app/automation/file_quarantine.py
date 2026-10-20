"""
Real, REVERSIBLE quarantine for dangerous downloads.

When the Downloads watcher finds a new file scoring FILE_QUARANTINE_MIN_SCORE or more, the file is MOVED (never
deleted) into QUARANTINE_DIR as  <id>.quarantined  -- the new extension means a double-click cannot run it.
Next to it  <id>.json  records where it came from, its SHA-256, the risk score and why, and every action.
"Restore" moves the file back to exactly where it was (a " (restored)" suffix is added only if a file with the
same name has appeared there meanwhile). A restored file is remembered by its SHA-256 so it is not quarantined
again. Every move is written to the audit log. Switched off with FILE_QUARANTINE=false in backend/.env.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import get_settings

_ID = re.compile(r"^[0-9a-f]{32}$")
_lock = threading.Lock()
MAX_RESTORED = 500


class QuarantineError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def quarantine_dir() -> Path:
    d = Path(os.path.expandvars(os.path.expanduser(get_settings().QUARANTINE_DIR))).resolve()
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _meta_path(qid: str) -> Path:
    if not _ID.match(qid or ""):
        raise QuarantineError("unknown quarantine id")
    return quarantine_dir() / f"{qid}.json"


def _read(qid: str) -> dict:
    p = _meta_path(qid)
    if not p.exists():
        raise QuarantineError("unknown quarantine id")
    return json.loads(p.read_text(encoding="utf-8"))


def _write(meta: dict) -> None:
    p = _meta_path(meta["id"])
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def quarantine_file(path: Path | str, *, sha256: str, score: int, reason: str, scan_id: str | None) -> dict:
    """Move a file into quarantine. The file must still be the one that was scanned (same SHA-256)."""
    path = Path(path)
    with _lock:
        if not path.is_file():
            raise QuarantineError("the file is gone")
        if sha256 and _sha256(path) != sha256:
            raise QuarantineError("the file changed after it was scanned; it was left in place")
        qid = uuid.uuid4().hex
        target = quarantine_dir() / f"{qid}.quarantined"
        meta = {"id": qid, "name": path.name, "originalPath": str(path.resolve()), "size": path.stat().st_size,
                "sha256": sha256, "score": int(score), "reason": (reason or "")[:500], "scanId": scan_id,
                "status": "quarantined", "quarantinedAt": _now(), "restoredAt": None, "restoredTo": None,
                "history": [{"action": "quarantined", "by": "CYBERGUARD (automatic)", "at": _now(),
                             "note": f"Moved out of {path.parent} (not deleted)"}]}
        _write(meta)                                  # record first: a crash mid-move still leaves a trace
        try:
            shutil.move(str(path), str(target))
        except OSError as exc:
            _meta_path(qid).unlink(missing_ok=True)
            raise QuarantineError(f"could not move the file ({exc})") from exc
        return public(meta)


def restore(qid: str, by: str) -> dict:
    """Move a quarantined file back to where it came from."""
    with _lock:
        meta = _read(qid)
        if meta.get("status") != "quarantined":
            raise QuarantineError("this file is not in quarantine any more")
        src = quarantine_dir() / f"{qid}.quarantined"
        if not src.exists():
            raise QuarantineError("the quarantined copy is missing from the quarantine folder")
        dest = Path(meta["originalPath"])
        dest.parent.mkdir(parents=True, exist_ok=True)
        n = 1
        while dest.exists():
            stem, suffix = Path(meta["name"]).stem, Path(meta["name"]).suffix
            dest = dest.with_name(f"{stem} (restored{'' if n == 1 else f' {n}'}){suffix}")
            n += 1
        shutil.move(str(src), str(dest))
        meta.update(status="restored", restoredAt=_now(), restoredTo=str(dest))
        meta["history"] = list(meta.get("history", [])) + [{"action": "restored", "by": by, "at": _now(),
                                                            "note": f"Moved back to {dest}"}]
        _write(meta)
        remember_restored(meta.get("sha256", ""))
        return public(meta)


def set_scan_id(qid: str, scan_id: str) -> None:
    with _lock:
        try:
            meta = _read(qid)
            meta["scanId"] = scan_id
            _write(meta)
        except (QuarantineError, OSError, ValueError):
            pass


def list_files(status: str = "quarantined") -> list[dict]:
    out = []
    for p in quarantine_dir().glob("*.json"):
        try:
            meta = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if status == "all" or meta.get("status") == status:
            out.append(public(meta))
    return sorted(out, key=lambda m: m.get("quarantinedAt") or "", reverse=True)


def public(meta: dict) -> dict:
    keys = ("id", "name", "originalPath", "size", "sha256", "score", "reason", "scanId", "status",
            "quarantinedAt", "restoredAt", "restoredTo", "history")
    return {k: meta.get(k) for k in keys}


def audit(action: str, actor: str, target: str, detail: dict, success: bool = True) -> None:
    """Audit-log row for a file quarantine action (never raises)."""
    try:
        from types import SimpleNamespace

        from app.automation.engine import owner_user_id
        from app.db.database import SessionLocal
        from app.services import audit as audit_log
        db = SessionLocal()
        try:
            owner = owner_user_id(db)                 # shown in the owner's Activity log
            audit_log.log(db, action=action, user=SimpleNamespace(id=owner, email="") if owner else None,
                          actor=actor, target=target, detail=detail, success=success, commit=True)
        finally:
            db.close()
    except Exception:
        pass


def remember_restored(sha256: str) -> None:
    from app.automation.engine import get_state, update_state
    if not sha256:
        return
    hashes = [h for h in (get_state("downloads").get("restoredHashes") or []) if h != sha256]
    update_state("downloads", restoredHashes=(hashes + [sha256])[-MAX_RESTORED:])


def was_restored(sha256: str) -> bool:
    from app.automation.engine import get_state
    return bool(sha256) and sha256 in (get_state("downloads").get("restoredHashes") or [])
