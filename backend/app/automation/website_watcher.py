"""
Watcher 7 (6 Nov) -- every GET / POST that reaches your website, checked every minute (Module 6: API abuse and
unusual application logs).

ASKS FIRST: it starts OFF and runs only after the owner switches it on in Settings (that switch is the permission).

Two sources, both read-only:
  1. CyberGuard's own website / API: the backend notes each request in memory (app/services/request_log.py: method,
     path, status, address, browser name; never bodies, cookies or passwords; secret-looking values masked).
  2. Optional: the access log of another website you run on this computer (nginx / Apache / IIS "combined" format),
     set in backend/.env as WEBSITE_ACCESS_LOGS=C:\\path\\access.log (several: separate with ';'). Only lines added
     since the last round are read.
Each round the new lines go through the same log check as a manual "Log analysis" scan (attack payloads incl.
Shellshock in headers, vulnerability scans, attack tools, web shells, password guessing ...). One finding per kind of
attack and attacker address; the same one is reported again only after a day.
"""
import os
from datetime import datetime, timedelta, timezone

from app.automation.engine import Watcher, get_state, save_and_alert, update_state
from app.detectors import log_incidents
from app.detectors.base import build_result
from app.services import request_log

MAX_READ_BYTES = 5_000_000          # per log file per round
REPEAT_HOURS = 24
SCORE = {"critical": 92, "high": 86, "medium": 71}


def _paths() -> list[str]:
    from app.core.config import get_settings
    raw = getattr(get_settings(), "WEBSITE_ACCESS_LOGS", "") or ""
    return [p.strip() for p in raw.replace(",", ";").split(";") if p.strip()]


def read_new_lines(path: str, offsets: dict) -> list[str]:
    """Lines added to a log file since the last round (a shorter file = it was rotated: start again)."""
    size = os.path.getsize(path)
    start = offsets.get(path, size if path not in offsets else 0)   # first time: start at the END (no history)
    if size < start:
        start = 0
    with open(path, "rb") as f:
        f.seek(start)
        data = f.read(MAX_READ_BYTES)
    cut = data.rfind(b"\n") + 1 if len(data) == MAX_READ_BYTES else len(data)
    offsets[path] = start + cut
    return data[:cut].decode("utf-8", errors="replace").splitlines()


def incident_result(inc: dict, where: str) -> dict:
    sev = inc["severity"]
    ind = {"id": f"IND_web_{inc['category']}", "label": inc["label"], "description": inc["description"],
           "severity": "critical" if sev in ("critical", "high") else "medium", "weight": inc.get("weight", 30),
           "triggered": True}
    who = ", ".join(inc.get("sources", [])[:5]) or "unknown address"
    result = build_result(indicators=[ind], base_score=SCORE.get(sev, 51), confidence=85,
                          engine_name="CyberGuard website monitor (request log + CyberGuard log check)",
                          threat_type=f"{inc['label']} against {where}",
                          explanation=f"{inc['label']} from {who} against {where}. {inc['description']}",
                          extra_recommendations=[f"Block {who} in your firewall / hosting panel if it is not yours.",
                                                 "Check the requested pages in your web server log around that time."])
    result["mitre"] = [inc["mitre"]] if inc.get("mitre") else []
    return result


class WebsiteWatcher(Watcher):
    name = "website"
    title = "Your website's requests (every GET / POST)"
    what = ("Every minute: each request that reached CyberGuard's website / API (and the access log of another site "
            "you run on this PC, if set) goes through the log check: attack payloads, vulnerability scans, attack "
            "tools, web shells, password guessing.")
    modules = ["cyber-threat"]
    technology = "In-memory request record (no bodies / cookies) + optional access-log files + CyberGuard log check"
    interval_seconds = 60
    default_enabled = False
    permission = ("Note each request to this website (address, method, page, status, browser name - never bodies, "
                  "cookies or passwords) in memory and check them every minute; read new lines of the access logs "
                  "listed in WEBSITE_ACCESS_LOGS.")

    def set_enabled(self, value: bool) -> None:
        """Switching on (again) starts from NOW: requests from before the permission (or from a pause) are not read."""
        if value:
            offsets = {}
            for p in _paths():
                try:
                    offsets[p] = os.path.getsize(p)
                except OSError:
                    pass
            update_state(self.name, seq=request_log.last_seq(), offsets=offsets)
        super().set_enabled(value)

    def check(self) -> dict:
        st = get_state(self.name)
        if "seq" not in st:                        # never switched on through Settings: start from now as well
            update_state(self.name, seq=request_log.last_seq())
            st = get_state(self.name)
        seq = int(st.get("seq", 0))
        if seq > request_log.last_seq():           # the backend restarted: its memory starts again at 1
            seq = 0
        entries = request_log.since(seq)
        sources = []
        if entries:
            sources.append(("this website (CyberGuard)", request_log.as_access_log(entries).split("\n")))
        offsets = dict(st.get("offsets", {}))
        errors = []
        for p in _paths():
            try:
                lines = read_new_lines(p, offsets)
                if lines:
                    sources.append((os.path.basename(p), lines))
            except OSError as exc:
                errors.append(f"{p}: {exc.strerror or exc}")
        now = datetime.now(timezone.utc)
        reported = st.get("reported", {})
        threats, finding, checked = 0, None, 0
        for where, lines in sources:
            checked += len(lines)
            summary = log_incidents.analyze("\n".join(lines)) if len(lines) >= 3 else None
            for inc in (summary or {}).get("incidents", []):
                if inc["severity"] not in SCORE:
                    continue
                sig = f"{where}|{inc['category']}|{','.join(sorted(inc.get('sources', [])[:5]))}"
                last = reported.get(sig)
                if last and now - datetime.fromisoformat(last) < timedelta(hours=REPEAT_HOURS):
                    continue
                result = incident_result(inc, where)
                self.record(f"{inc['label']} ({where})", result["riskScore"], result["classification"])
                scan_id = save_and_alert(module_id="cyber-threat", subtopic_id="api-abuse",
                                         subtopic_title="Automatic website monitoring", result=result,
                                         target=f"{where}: {', '.join(inc.get('sources', [])[:3])}", target_type="log",
                                         source="website", metadata={"category": inc["category"],
                                                                     "lines": inc.get("lines")}, min_score=51)
                reported[sig] = now.isoformat()
                if scan_id:
                    threats += 1
                    finding = f"{inc['label']} from {', '.join(inc.get('sources', [])[:2])} ({where})"
        reported = {k: v for k, v in reported.items() if now - datetime.fromisoformat(v) < timedelta(days=7)}
        update_state(self.name, seq=entries[-1]["seq"] if entries else seq, offsets=offsets, reported=reported)
        if errors and not checked:
            raise RuntimeError("Could not read: " + "; ".join(errors)[:250])
        return {"checked": checked, "threats": threats, "finding": finding,
                "note": f"{checked} new request(s) checked" + (f"; could not read {len(errors)} log file(s)" if errors else "")}
