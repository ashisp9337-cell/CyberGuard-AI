"""
API abuse / web-attack requests (module 6, "API Abuse Detection"; also used for any pasted web / API log).

ONE implementation used by training (app/ml/training/train_api_abuse.py) and scanning (app/detectors/cyber_threat.py),
so they can never drift apart.

What it judges: each HTTP request found in the pasted text (raw requests, web-server access-log lines, or "GET /path"
lines) - its path, query string and form body. It answers "is this request an attack?" (SQL injection, cross-site
scripting, path traversal, command injection, server-side request forgery, scanner probes ...).

Why "request shape" and not the raw text: a model trained on the words of one website learns that website (tested: AUC
0.99 on its own data but 0.63 on another site's traffic). Here every ordinary word becomes a placeholder (w / W) and only
attack syntax and security keywords stay visible ('  "  <  >  ;  ../  union select  <script  %00 ...), so the model learns
what attacks look like, not what one shop's product names look like.
"""
import os
import re
from urllib.parse import unquote_plus, urlsplit

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "models", "api_abuse.joblib")
BUNDLE_KIND, BUNDLE_VERSION = "cyberguard-api-abuse", 1
MAX_REQUESTS = 500

# Words that carry attack meaning stay visible; every other word becomes w (short) or W (6+ letters).
KEYWORDS = frozenset("""select union insert update delete drop from where and or not null like having group order by
sleep benchmark waitfor delay exec execute xp_cmdshell declare cast convert char nchar varchar concat substring ascii
count information_schema table tables column columns database schema version user load_file outfile dumpfile into
values true false script javascript vbscript alert prompt confirm onerror onload onmouseover onfocus onclick svg img
iframe src href document cookie eval expression style body frame object embed base64 fromcharcode window location etc
passwd shadow win ini boot system32 cmd exe bin sh bash wget curl nc ping cat ls echo whoami id uname net dir type php
include require file http https ftp data input filter expect phpinfo localhost admin root jndi ldap rmi dns""".split())
_TOKEN = re.compile(r"[^\W\d_]+|\d+|\s|_|[^\w\s]")


def decode(s: str) -> str:
    """URL-decode twice (attackers double-encode). UTF-8 first; old sites' Latin-1 (%F3 = ó) as fallback."""
    for _ in range(2):
        try:
            s = unquote_plus(s, encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            s = unquote_plus(s, encoding="latin-1")
    return s


def shape(request_text: str) -> str:
    out = []
    for t in _TOKEN.findall(decode(request_text).lower()[:4000]):
        if t[0].isalpha():
            out.append(t if t in KEYWORDS else ("w" if len(t) < 6 else "W"))
        elif t[0].isdigit():
            out.append("0")
        elif t.isspace():
            out.append(" ")
        else:
            out.append(t)
    return " ".join(out)


def request_text(path: str, query: str = "", body: str = "") -> str:
    """What the model sees: path + query + form body (the method, host and headers are left out on purpose - in the
    training data they say how the data was collected, not whether a request is an attack)."""
    return (path or "/") + ("?" + query if query else "") + ("&" + body if body else "")


# ---- attack types (plain-language explanations; each one checked for false alarms on real traffic) -------------
#      (name, regex on the decoded lower-case request, MITRE technique, explanation)
ATTACK_TYPES = [
    ("SQL injection", re.compile(
        r"union(\s|/\*.*?\*/|\+)+(all(\s|\+)+)?select\b|['\"`]\s*(or|and)\s+['\"\w]+\s*(=|like)\s*['\"\w]|"
        r"['\"`]\s*(or|and)\s+\d+\s*=\s*\d+|;\s*(drop|delete|insert|update|exec|shutdown|declare)\s|"
        r"\b(sleep|benchmark|pg_sleep)\s*\(\s*\d|waitfor\s+delay\s+'|information_schema\.|xp_cmdshell|"
        r"\bselect\b[^&]{1,80}\bfrom\b[^&]{1,80}\bwhere\b|'\s*(--|#)|\border\s+by\s+\d+\s*(--|#)"), "T1190",
     "The request carries database commands inside a parameter, trying to make the server's database run them."),
    ("Cross-site scripting (XSS)", re.compile(
        r"<\s*script|javascript\s*:|\bon(error|load|mouseover|focus|click|toggle|animationstart)\s*=|"
        r"<\s*(img|svg|iframe|body|details|video|audio|object|embed)\b[^>]*\bon\w+\s*=|document\.cookie|"
        r"\balert\s*\(|<\s*iframe\b"), "T1189",
     "The request carries browser script, trying to run code in other users' browsers through this site."),
    ("Path traversal / sensitive file", re.compile(
        r"(\.\.[/\\]){2,}|/etc/(passwd|shadow|hosts)\b|\bwin\.ini\b|\bboot\.ini\b|\x00|"
        r"\b(wp-config|web\.config|\.env|\.git/config|id_rsa)\b(?!\w)"), "T1083",
     "The request tries to climb out of the web folder (../../) or read system / secret files."),
    ("Command injection", re.compile(
        # (6 Nov) a command word followed by "=" is a parameter NAME ("&&ID=SERP" in every Bing search click), not a command
        r"(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|uname|wget|curl|nc|ncat|ping|bash|sh|powershell|cmd)\b(?!\s*=)[^&]{0,60}|"
        r"\b(cmd|exec|command|run)=[^&]*(\||;|`|\$\()"), "T1059",
     "The request tries to make the server run operating-system commands."),
    ("Server-side request forgery (SSRF)", re.compile(
        r"=\s*(https?|gopher|file|dict|ftp)://(127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|169\.254\.169\.254|"
        r"metadata\.google\.internal|\[::1?\])|=\s*file:///"), "T1090",
     "The request asks the server to fetch an internal address (cloud metadata, localhost) on the attacker's behalf."),
    ("Log4Shell / template injection", re.compile(r"\$\{\s*jndi\s*:|\$\{\s*(env|sys|lower|upper|date)\s*:|\{\{\s*\d+\s*\*\s*\d+\s*\}\}|"
                                                  r"\$\{\s*\d+\s*\*\s*\d+\s*\}"), "T1190",
     "The request carries a template / lookup expression that makes vulnerable servers run attacker code (e.g. Log4Shell)."),
    ("Header / response splitting", re.compile(r"(%0d%0a|\r\n)\s*(set-cookie|location|content-type)\s*:"), "T1190",
     "Line breaks are injected to add the attacker's own headers to the server's response."),
]


def attack_types(decoded_lower: str) -> list[tuple[str, str, str]]:
    return [(name, mitre, desc) for name, rx, mitre, desc in ATTACK_TYPES if rx.search(decoded_lower)]


# (6 Nov) Attacks hidden in request HEADERS (User-Agent, Referer, Cookie ...), which the checks above never see. Found
# on real WRCCDC 2018 traffic: 804 Shellshock requests whose URLs were ordinary, in two variants ("() { ignored; };" and
# "() { _; } >_[$($())] {"). A bash function definition "() { ... }" in a header is never sent by real browsers or apps.
SHELLSHOCK = ("Shellshock (bash CVE-2014-6271)", re.compile(r"\(\)\s*\{[^}]{0,200}\}"), "T1190",   # also the 6278 variant
              "A request header starts with a bash function definition '() { ...; };' followed by a command - the "
              "Shellshock attack, which makes old bash-based web scripts (CGI) run the attacker's command.")


def header_attack_types(headers: str) -> list[tuple[str, str, str]]:
    """Attack types found in request header values (raw headers, a User-Agent or a Referer)."""
    name, rx, mitre, desc = SHELLSHOCK
    return [(name, mitre, desc)] if headers and rx.search(headers[:8000]) else []


# ---- finding requests in pasted text -------------------------------------------------------------------------
_METHODS = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"
_RAW_LINE = re.compile(rf"^\s*({_METHODS})\s+(\S+)\s+HTTP/\d(?:\.\d)?\s*$")
_LOG_LINE = re.compile(rf"\"({_METHODS})\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?\"")
_BARE = re.compile(rf"(?:^|\s|\[|\"|')({_METHODS})\s+((?:https?://)\S+|/\S*)")


def _split_target(target: str) -> tuple[str, str]:
    if "://" in target:
        u = urlsplit(target)
        return (u.path or "/"), u.query
    path, _, query = target.partition("?")
    return (path or "/"), query.split("#", 1)[0]


def extract_requests(text: str) -> list[dict]:
    """HTTP requests found in pasted text: raw requests (request line, headers, blank line, form body), web-server
    access-log lines ("GET /x?y HTTP/1.1" 200 ...) and plain "POST /api/login?..." lines."""
    lines = (text or "").replace("\r\n", "\n").split("\n")
    out, i = [], 0
    while i < len(lines) and len(out) < MAX_REQUESTS:
        line = lines[i]
        m = _RAW_LINE.match(line)
        if m:
            method, target = m.groups()
            i += 1
            head_start = i
            while i < len(lines) and lines[i].strip() and not _RAW_LINE.match(lines[i]):
                i += 1                                              # headers
            headers = "\n".join(lines[head_start:i])[:8000]
            body = ""
            if method in ("POST", "PUT", "PATCH"):
                j = i
                while j < len(lines) and not lines[j].strip():
                    j += 1
                if j < len(lines) and j - i <= 2 and not _RAW_LINE.match(lines[j]) and not _LOG_LINE.search(lines[j]) \
                        and ":" not in lines[j].split("=", 1)[0]:
                    body, i = lines[j].strip()[:4000], j + 1
            path, query = _split_target(target)
            out.append({"method": method, "path": path, "query": query, "body": body, "line": line.strip()[:300],
                        "headers": headers})
            continue
        m = _LOG_LINE.search(line) or _BARE.search(line)
        if m:
            path, query = _split_target(m.group(2))
            out.append({"method": m.group(1), "path": path, "query": query, "body": "", "line": line.strip()[:300]})
        i += 1
    return out


# ---- model ---------------------------------------------------------------------------------------------------
_cache: dict = {}


def load_model():
    if not os.path.exists(MODEL_PATH):
        _cache.clear()
        return None
    mtime = os.path.getmtime(MODEL_PATH)
    if _cache.get("mtime") != mtime:
        try:
            import joblib
            b = joblib.load(MODEL_PATH)
            ok = isinstance(b, dict) and b.get("kind") == BUNDLE_KIND and b.get("version") == BUNDLE_VERSION
            _cache.update(mtime=mtime, bundle=b if ok else None)
        except Exception:
            _cache.update(mtime=mtime, bundle=None)
    return _cache.get("bundle")


def assess(text: str) -> dict | None:
    """None when the text holds no HTTP request. Otherwise the riskiest request and what was found."""
    reqs = extract_requests(text)
    if not reqs:
        return None
    b = load_model()
    texts = [request_text(r["path"], r["query"], r["body"]) for r in reqs]
    probs = list(b["model"].predict_proba(b["vectorizer"].transform([shape(t) for t in texts]))[:, 1]) if b else \
        [None] * len(reqs)
    scored = []
    for r, t, p in zip(reqs, texts, probs):
        types = attack_types(decode(t).lower()) + header_attack_types(r.get("headers", ""))
        level = None if p is None else "high" if p >= b["thr_alert"] else "medium" if p >= b["thr_verify"] else "low"
        scored.append({**{k: v for k, v in r.items() if k != "headers"},   # headers may hold cookies / tokens: not kept
                       "probability": None if p is None else float(p), "level": level, "attackTypes": types})
    rank = {"high": 2, "medium": 1, "low": 0, None: 0}
    top = max(scored, key=lambda s: (len(s["attackTypes"]) > 0, rank[s["level"]], s["probability"] or 0))
    found = {}
    for s in scored:
        for name, mitre, desc in s["attackTypes"]:
            found.setdefault(name, {"mitre": mitre, "description": desc, "count": 0, "example": s["line"]})["count"] += 1
    return {"requests": len(scored), "top": top, "attackTypes": found,
            "flaggedByModel": sum(1 for s in scored if s["level"] in ("high", "medium")),
            "alertByModel": sum(1 for s in scored if s["level"] == "high"),
            "thrAlert": b["thr_alert"] if b else None, "thrVerify": b["thr_verify"] if b else None,
            "trainedAt": b.get("trained_at") if b else None, "modelAvailable": b is not None}
