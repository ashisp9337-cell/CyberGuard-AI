"""
Whole-log-file analysis (module 6, "System & Application Log Analysis"): read EVERY line of a pasted or uploaded log,
find attack INCIDENTS and summarise them (what, who / which IP, how many lines, from when to when, example lines).

Why incidents and not a per-line model: in the AIT attack data most attack steps cannot be seen in one line - one
"authentication failure" looks exactly like a user mistyping a password; only a BURST of them from one source is a
password attack. A per-line model trained on AIT was tested and rejected: perfect on held-out AIT servers but it flagged
40-100% of the lines of normal logs from other systems (LogHub). So the decisions here are made on bursts and on a few
very specific signatures, and every burst size ("threshold") is chosen from real data by
app/ml/training/train_log_analysis.py: the largest burst seen in NORMAL traffic (the AIT servers' normal days and real
website logs) + 1, never below 5, checked on a held-out AIT server and on 16 other real systems' logs. The chosen values
are stored in app/ml/models/log_analysis.json; the defaults below are the same values, used if that file is missing.

Works on any text log: Linux syslog / auth.log / secure, Apache / Nginx access and error logs, Exim / Postfix mail logs,
Dovecot, Horde, Suricata fast.log, JSON lines with a timestamp. Nothing is executed, nothing leaves the computer.
"""
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "models", "log_analysis.json")
MAX_LINES = 300_000
WINDOW_S = 600                     # bursts are counted in 10-minute windows
DEFAULTS = {"brute_force": 5, "web_scan": 15, "probe": 5, "enumeration": 5}   # = log_analysis.json values

_MON = {m: i + 1 for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split())}
_TS = [   # (regex, function(match) -> datetime)
    (re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"),
     lambda m: datetime(int(m[1]), int(m[2]), int(m[3]), int(m[4]), int(m[5]), int(m[6]))),
    (re.compile(r"\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})"),
     lambda m: datetime(int(m[3]), _MON[m[2].lower()], int(m[1]), int(m[4]), int(m[5]), int(m[6]))),
    (re.compile(r"\[[A-Za-z]{3} ([A-Za-z]{3}) (\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)? (\d{4})\]"),
     lambda m: datetime(int(m[6]), _MON[m[1].lower()], int(m[2]), int(m[3]), int(m[4]), int(m[5]))),
    (re.compile(r"\b(\d{2})/(\d{2})/(\d{4})-(\d{2}):(\d{2}):(\d{2})"),
     lambda m: datetime(int(m[3]), int(m[1]), int(m[2]), int(m[4]), int(m[5]), int(m[6]))),
    (re.compile(r"^\s*(?:<\d+>)?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})"),     # syslog (no year)
     lambda m: datetime(2000, _MON[m[1].lower()], int(m[2]), int(m[3]), int(m[4]), int(m[5]))),
]


def timestamp(line: str) -> float | None:
    for rx, fn in _TS:
        m = rx.search(line[:120])
        if m:
            try:
                return fn(m).replace(tzinfo=timezone.utc).timestamp()
            except (ValueError, KeyError):
                return None
    return None


_IP = r"((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]*:[0-9a-f:]+)"
# ---- events ---------------------------------------------------------------------------------------------------
#  each: (category, regex, how to get the source key from the match)
AUTH_FAIL = [
    re.compile(rf"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from {_IP}", re.I),
    re.compile(rf"Invalid user (?P<user>\S+) from {_IP}", re.I),
    re.compile(r"authentication failure;.*?rhost=(?P<ip>\S*)(?:.*?\buser=(?P<user>\S+))?", re.I),
    re.compile(rf"FAILED LOGIN (?:\(\d+\) on \S+ )?(?:for|FROM) (?P<user>\S+)\s*\(?{_IP}?", re.I),
    re.compile(r"auth failed[^\n]*?user=<(?P<user>[^>]*)>[^\n]*?rip=(?P<ip>[\d.]+)", re.I),
    re.compile(rf"authenticator failed for [^\n]*?\[{_IP}\]", re.I),
    re.compile(rf"(?:SASL \w+ authentication failed|Login failed|login failure)[^\n]*?{_IP}?", re.I),
    re.compile(r"An account failed to log on|EventID[=: ]+4625\b", re.I),
]
PROBE = re.compile(rf"(?:(?:no auth attempts in \d+ secs|disconnected before auth was ready, waited \d+ secs)\)[^\n]*?rip={_IP}|Did not receive identification string from {_IP}|"
                   rf"Bad protocol version identification [^\n]*? from {_IP}|"
                   rf"(?:Connection closed|Connection reset|Disconnected) by (?:invalid user \S+ )?{_IP} port \d+ \[preauth\])", re.I)
ENUM = re.compile(rf"(?:VRFY|EXPN) failed for (?P<user>\S+)[^\n]*?\[{_IP}\]|rejected RCPT[^\n]*?\[{_IP}\][^\n]*?unknown user", re.I)
ACCESS = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]+) (?P<target>\S+)[^"]*" (?P<status>\d{3}) \S+'
                    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?')   # Apache writes " as \"
SCANNER_UA = re.compile(r"nikto|sqlmap|nmap|masscan|zgrab|nuclei|wpscan|dirbuster|\bdirb\b|gobuster|ffuf|wfuzz|"
                        r"acunetix|nessus|openvas|w3af|arachni|hydra|medusa|havij|commix|jaeles|feroxbuster", re.I)
WEBSHELL = re.compile(r"system\(\): Cannot execute|(?:shell_exec|passthru|proc_open)\(\)|"
                      r"/(?:evil|shell|cmd|c99|r57|wso|b374k|webshell)\.php\b|"
                      r"\.php\?(?:cmd|exec|command|execute)=|\$\{run\{|/bin/(?:ba)?sh -[ci] |\bnc(?:at)? -e /bin/|"
                      r"bash -i >& /dev/tcp/", re.I)
PRIV = re.compile(r"sudo:[^\n]*(?:authentication failure|incorrect password attempts|NOT in sudoers)|"
                  r"\buseradd\[\d+\]|new user: name=|\busermod\[\d+\]|\bgpasswd\[\d+\]|"
                  r"COMMAND=/bin/(?:ba)?sh\b|log file (?:was )?(?:cleared|deleted)|EventID[=: ]+1102\b", re.I)

CATEGORY = {
    "brute_force": ("Password brute-force attack", "critical", 40, "T1110",
                    "Many failed logins from one source in a short time: someone is guessing passwords."),
    "web_scan": ("Web vulnerability scan", "high", 35, "T1595.002",
                 "One address sent a flood of requests the server rejected or could not find - an automated scanner "
                 "probing for weaknesses."),
    "scanner_tool": ("Attack / scanning tool identified", "high", 35, "T1595",
                     "The request identifies a known attack or scanning tool (e.g. Nikto, sqlmap, Hydra)."),
    "web_attack": ("Web attack payloads", "critical", 40, "T1190",
                   "Requests carried attack code (SQL injection, XSS, path traversal, command injection ...)."),
    "webshell": ("Web shell / remote command execution", "critical", 50, "T1505.003",
                 "Traces of a web shell or of commands run through the web server - the server may be compromised."),
    "enumeration": ("Account enumeration", "high", 30, "T1087",
                    "Someone is testing which user names exist (e.g. mail VRFY), a step before password attacks."),
    "probe": ("Service probing / port scan", "medium", 20, "T1046",
              "Connections that open and close without logging in - typical of a port or service scan."),
    "privilege": ("Privilege / account change", "medium", 20, "T1078",
                  "sudo failures, new or changed accounts, a root shell, or a cleared log - check these were expected."),
}


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            saved = json.load(f).get("thresholds", {})
        cfg.update({k: int(v) for k, v in saved.items() if k in DEFAULTS and int(v) > 0})
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return cfg


def _ip_of(m) -> str | None:
    for v in (m.groupdict().get("ip"),) + tuple(g for g in m.groups() if g):
        if v and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]*:[0-9a-f:]+", v, re.I) and ":" not in v[:1]:
            return v
    return None


# Cheap pre-checks: the detailed patterns only run on lines that contain one of these words (most lines do not).
# Plain "word in lower-case line" tests: same result as the patterns' own words, many times faster than regexes.
_PRE_AUTH = ("fail", "invalid user", "4625")
_PRE_PROBE = ("no auth attempts", "before auth was ready", "identification", "preauth")
_PRE_ENUM = ("vrfy", "expn", "rejected rcpt")
_PRE_SHELL = ("system(", "_exec", "passthru", "proc_open", ".php", "${run", "/bin/", "nc ", "ncat", "/dev/tcp")
_PRE_PRIV = ("sudo", "useradd", "new user", "usermod", "gpasswd", "command=", "log file", "1102")


def _has(low: str, words) -> bool:
    return any(w in low for w in words)


def events(lines):
    """Every security-relevant event: (category, line_number, timestamp or None, source key, line)."""
    from app.detectors import api_abuse
    out = []
    for i, line in enumerate(lines, 1):
        if len(line) > 4000:
            line = line[:4000]
        t = None
        m = ACCESS.match(line) if '"' in line and " [" in line else None
        if m:
            ip, status, target, ua = m["ip"], int(m["status"]), m["target"], m["ua"] or ""
            t = timestamp(line)
            if 400 <= status < 500 and status != 401:
                out.append(("web_scan", i, t, ip, line))
            if SCANNER_UA.search(ua):
                out.append(("scanner_tool", i, t, ip, line))
            path, _, query = target.partition("?")
            if api_abuse.attack_types(api_abuse.decode(api_abuse.request_text(path, query)).lower()) \
                    or api_abuse.header_attack_types(ua + "\n" + (m["ref"] or "")):   # (6 Nov) Shellshock in headers
                out.append(("web_attack", i, t, ip, line))
        low = line.lower()
        if _has(low, _PRE_AUTH):
            for rx in AUTH_FAIL:
                a = rx.search(line)
                if a:
                    ip = _ip_of(a)
                    user = (a.groupdict().get("user") or "").strip("<>")
                    key = ip if ip and not ip.startswith("127.") and ip != "::1" else (f"user {user}" if user else "local")
                    out.append(("brute_force", i, t if t is not None else timestamp(line), key, line))
                    break
        if _has(low, _PRE_PROBE):
            p = PROBE.search(line)
            if p:
                out.append(("probe", i, timestamp(line), _ip_of(p) or "?", line))
        if _has(low, _PRE_ENUM):
            e = ENUM.search(line)
            if e:
                out.append(("enumeration", i, timestamp(line), _ip_of(e) or "?", line))
        if _has(low, _PRE_SHELL) and WEBSHELL.search(line):
            ipm = re.search(r"\[client ((?:\d{1,3}\.){3}\d{1,3})|^((?:\d{1,3}\.){3}\d{1,3}) ", line)
            out.append(("webshell", i, timestamp(line), (ipm[1] or ipm[2]) if ipm else "?", line))
        if _has(low, _PRE_PRIV) and PRIV.search(line):
            out.append(("privilege", i, timestamp(line), "host", line))
    return out


def _max_window(items):
    """Largest number of events inside any WINDOW_S window (events without a time count together)."""
    times = sorted(t for t in (x[2] for x in items) if t is not None)
    best, j = 0, 0
    for k in range(len(times)):
        while times[k] - times[j] > WINDOW_S:
            j += 1
        best = max(best, k - j + 1)
    return max(best, sum(1 for x in items if x[2] is None))


def incidents(lines, cfg: dict | None = None, evs: list | None = None) -> list[dict]:
    cfg = cfg or load_config()
    by = defaultdict(list)
    for ev in (evs if evs is not None else events(lines)):
        by[(ev[0], ev[3])].append(ev)
    found, below = [], []
    for (cat, key), items in by.items():
        burst = _max_window(items)
        need = cfg.get(cat)
        times = [x[2] for x in items if x[2] is not None]
        inc = {"category": cat, "source": key, "count": len(items), "burst": burst,
               "first": min(times) if times else None, "last": max(times) if times else None,
               "lines": [x[1] for x in items[:3]], "examples": [x[4][:220] for x in items[:3]]}
        (below if need is not None and burst < need else found).append(inc)
    # Smaller bursts (e.g. a quick port scan leaves only one "disconnected before login" line) are NOT incidents on their
    # own - normal clients do that too. They are reported only for an address that also carried out a high / critical
    # attack in the same log: then they are the earlier steps of that attack.
    attackers = {f["source"] for f in found if CATEGORY[f["category"]][1] in ("high", "critical")}
    found += [dict(f, linked=True) for f in below if f["source"] in attackers]
    order = list(CATEGORY)
    found.sort(key=lambda f: (order.index(f["category"]), -f["count"]))
    return found


_FORMATS = [   # (name, test on one line) - the kinds of log the incident rules above were written for
    ("web server access log (Apache / Nginx)", lambda ln: '"' in ln and " [" in ln and ACCESS.match(ln) is not None),
    ("web server error log (Apache)", lambda ln: _TS[2][0].search(ln) is not None),
    ("Suricata IDS alert log", lambda ln: "[**]" in ln and _TS[3][0].search(ln) is not None),
    ("Linux system / SSH log (syslog)", lambda ln: _TS[4][0].match(ln) is not None),
    ("mail server log (Exim)", lambda ln: _EXIM.match(ln) is not None),
    ("Windows Security event log", lambda ln: _WINDOWS.search(ln) is not None),
]
_EXIM = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? (?:[+-]\d{4} )?(?:\[\d+\] )?"
                   r"(?:[0-9A-Za-z]{6}-[0-9A-Za-z]{6}-[0-9A-Za-z]{2}\b|(?:SMTP|VRFY|EXPN|H=|no host name|unexpected disconnection))")
_WINDOWS = re.compile(r"Microsoft-Windows-Security-Auditing|EventID[=: ]+\d{4}\b|Event ID[=: ]+\d{4}\b|"
                      r"An account (?:was|failed)|Special privileges assigned|The audit log was cleared", re.I)
FORMAT_SHARE = 0.2      # a format counts as recognised when it fits at least 1 line in 5 (pasted logs can be mixed)


def log_format(lines) -> str | None:
    """Which supported kind of log this is (the name), or None when no supported format fits enough lines.
    Looks at up to 2,000 lines from the start and end; only reads them."""
    sample = list(lines[:1000]) + list(lines[-1000:] if len(lines) > 1000 else [])
    if not sample:
        return None
    counts = {name: sum(1 for ln in sample if test(ln[:4000])) for name, test in _FORMATS}
    name, best = max(counts.items(), key=lambda kv: kv[1])
    return name if best >= max(1, FORMAT_SHARE * len(sample)) else None


def _when(ts):
    if ts is None:
        return ""
    d = datetime.fromtimestamp(ts, timezone.utc)
    return d.strftime("%H:%M:%S") if d.year == 2000 else d.strftime("%Y-%m-%d %H:%M:%S")


def analyze(text: str, cfg: dict | None = None) -> dict | None:
    """Summary of a whole log, or None when it is too short to be a log (fewer than 3 lines).
    cfg: thresholds to use (default: the saved / default ones)."""
    lines = (text or "").replace("\r\n", "\n").split("\n")
    lines = [ln for ln in lines if ln.strip()][:MAX_LINES]
    if len(lines) < 3:
        return None
    cfg = cfg or load_config()
    inc = incidents(lines, cfg)
    stamped = [t for t in (timestamp(ln) for ln in lines[:2000] + lines[-2000:]) if t is not None]
    groups = defaultdict(list)
    for f in inc:
        groups[f["category"]].append(f)
    summary = []
    for cat, fs in groups.items():
        label, sev, weight, mitre, desc = CATEGORY[cat]
        total = sum(f["count"] for f in fs)
        srcs = ", ".join(f["source"] for f in fs[:4]) + (f" and {len(fs) - 4} more" if len(fs) > 4 else "")
        span = [f for f in fs if f["first"] is not None]
        when = (f" between {_when(min(f['first'] for f in span))} and {_when(max(f['last'] for f in span))}"
                if span else "")
        ex = fs[0]
        linked = (" Fewer lines than an attack usually needs, but the same address also attacked in this log, so this "
                  "is an earlier step of that attack." if any(f.get("linked") for f in fs) else "")
        summary.append({"category": cat, "label": label, "severity": sev, "weight": weight, "mitre": mitre,
                        "description": f"{desc} {total:,} line(s) from {srcs}{when}.{linked} Line {ex['lines'][0]}: "
                                       f"{ex['examples'][0][:180]}",
                        "lines": total, "sources": [f["source"] for f in fs][:20]})
    return {"linesRead": len(lines), "truncated": len(lines) >= MAX_LINES, "format": log_format(lines),
            "timeRange": [_when(min(stamped)), _when(max(stamped))] if stamped else None,
            "incidents": summary, "details": inc[:50], "thresholds": cfg}
