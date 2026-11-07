"""
(6 Nov) In-memory record of the requests that reach this website / API, for the automatic website watcher.

Kept: time, client address, method, path, query (secret-looking values masked), status, user agent, referrer.
NEVER kept: request bodies (passwords, uploads), cookies, Authorization headers. Memory only (the newest MAX_ENTRIES),
nothing is written to disk; a restart forgets it.
"""
import re
import threading
import time
from collections import deque

MAX_ENTRIES = 20000
_SECRET_KEYS = re.compile(r"(?i)(^|[&?])((?:access_|refresh_|id_)?token|code|otp|password|passwd|pwd|secret|key|"
                          r"apikey|api_key|session|sig|signature|auth)=([^&]*)")
_entries: deque = deque(maxlen=MAX_ENTRIES)
_lock = threading.Lock()
_seq = 0


def _mask(query: str) -> str:
    return _SECRET_KEYS.sub(lambda m: f"{m[1]}{m[2]}=***", query or "")[:600]


def record(ip: str, method: str, path: str, query: str, status: int, user_agent: str, referrer: str) -> None:
    global _seq
    with _lock:
        _seq += 1
        _entries.append({"seq": _seq, "ts": time.time(), "ip": (ip or "-")[:64], "method": (method or "-")[:10],
                         "path": (path or "/")[:600], "query": _mask(query), "status": int(status or 0),
                         "ua": (user_agent or "")[:400], "ref": (referrer or "")[:400]})


def since(seq: int) -> list[dict]:
    with _lock:
        return [e for e in _entries if e["seq"] > seq]


def last_seq() -> int:
    with _lock:
        return _seq


def as_access_log(entries: list[dict]) -> str:
    """Apache 'combined' lines (the format a real web server writes), for the log check."""
    def esc(v: str) -> str:
        return (v or "-").replace("\\", "\\\\").replace('"', '\\"')
    out = []
    for e in entries:
        t = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(e["ts"]))
        target = e["path"] + (f"?{e['query']}" if e["query"] else "")
        out.append(f'{e["ip"]} - - [{t}] "{e["method"]} {esc(target)} HTTP/1.1" {e["status"]} 0 '
                   f'"{esc(e["ref"])}" "{esc(e["ua"])}"')
    return "\n".join(out)
