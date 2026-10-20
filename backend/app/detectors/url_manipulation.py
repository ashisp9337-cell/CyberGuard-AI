"""
URL manipulation detection: tricks hidden in the STRUCTURE of a link.

    http://paypal.com@185.22.4.9/login            '@' trick - everything before @ is ignored by the browser
    http://3232235777/  or  http://0xC0A80101/     IP address written as one number / in hex
    http://site.com/%2e%2e/%2e%2e/etc/passwd       encoded "../" (path traversal), %252e (double encoding)
    http://site.com/redirect?u=http://evil.xyz      a second link hidden inside the first
    http://site.com/a/b/c/d/e/f/x9f8a7s6d5f4...      very deep / long random paths, long base64 blobs
    http://host:8080/...,  http://xn--...            odd ports, punycode

How it works
  * The link is normalised first: the scheme (http/https) and a leading "www." are removed, because in the
    public datasets they say more about WHERE a link was collected than whether it is malicious.
  * ~40 numbers describe the host, path, query and the encoding tricks.
  * A model trained on real links (app/ml/training/train_url_manipulation.py) gives a probability, and the
    explicit tricks above are also reported as plain-language findings.

The same feature code is used for training and for scanning.
"""
from __future__ import annotations

import math
import os
import re
from collections import Counter
from urllib.parse import unquote

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "models", "url_manipulation.joblib")

_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]{0,15}:/{0,3}", re.I)
_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_ODD_IP = re.compile(r"^(0x[0-9a-f]+|\d{8,10}|0[0-7]+(\.0?[0-7]+){0,3}|(0x[0-9a-f]{1,2}\.){3}0x[0-9a-f]{1,2})$", re.I)
_PCT = re.compile(r"%[0-9a-f]{2}", re.I)
_EMBEDDED = re.compile(r"(https?:|https?%3a|www\.|%2f%2f|//[a-z0-9\-]+\.[a-z]{2,})", re.I)
_B64 = re.compile(r"[A-Za-z0-9+/_\-]{40,}={0,2}")
_HEX = re.compile(r"[0-9a-f]{24,}", re.I)
_EXEC = re.compile(r"\.(exe|scr|bat|cmd|msi|apk|jar|vbs|ps1|dll|bin|sh|arm\d?|mips|x86|i686)$", re.I)
_ARCHIVE = re.compile(r"\.(zip|rar|7z|gz|tar|iso|img)$", re.I)
_SCRIPT_PAGE = re.compile(r"\.(php|asp|aspx|jsp|cgi|pl)$", re.I)
_REDIRECT_KEYS = {"url", "redirect", "redirect_uri", "redirecturl", "next", "continue", "return", "returnurl",
                  "return_to", "target", "dest", "destination", "goto", "link", "u", "r", "to", "out", "uri",
                  "adurl", "rurl", "redir", "forward", "location", "go"}

FEATURES = [
    "url_len", "path_len", "query_len", "fragment_len",
    "host_is_ipv4", "host_odd_ip", "host_punycode", "has_port", "odd_port", "userinfo_at", "at_anywhere",
    "path_depth", "path_double_slash", "dot_segments", "encoded_dot_segments", "pct_count", "pct_ratio",
    "double_encoding", "encoded_alnum", "encoded_slash_or_dot", "params", "redirect_param_with_url",
    "embedded_url", "longest_token", "path_digit_ratio", "path_entropy", "query_entropy", "base64_blob",
    "hex_blob", "exec_download", "archive_download", "script_page", "special_chars", "tilde", "semicolon",
    "uppercase_ratio", "non_ascii", "subdomain_count", "host_len", "host_dots", "hidden_domain_in_host",
]
_TLD_WORDS = {"com", "net", "org", "gov", "edu", "www", "http", "https", "co", "cgi", "bin"}


def normalise(url: str) -> str:
    """Drop the scheme and a leading 'www.' -- they are collection artefacts in the public datasets."""
    u = (url if isinstance(url, str) else "").strip().strip("\"'<>")
    u = _SCHEME.sub("", u, count=1) if "://" in u[:20] else u
    return re.sub(r"^www\d?\.", "", u, flags=re.I)


def split(u: str):
    """-> authority, host, port, path, query, fragment from a normalised URL."""
    frag = ""
    if "#" in u:
        u, frag = u.split("#", 1)
    query = ""
    if "?" in u:
        u, query = u.split("?", 1)
    authority, _, path = u.partition("/")
    path = "/" + path if path or u.endswith("/") else ""
    host_port = authority.rsplit("@", 1)[-1]
    port = ""
    if host_port.startswith("["):                       # [ipv6]:port
        host, _, rest = host_port.partition("]")
        host += "]"
        port = rest[1:] if rest.startswith(":") else ""
    elif ":" in host_port:
        host, port = host_port.rsplit(":", 1)
    else:
        host = host_port
    return authority, host.lower().rstrip("."), port, path, query, frag


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def manipulation_features(url: str):
    """-> (features, findings) -- findings are plain-language descriptions of explicit tricks."""
    u = normalise(url)
    authority, host, port, path, query, frag = split(u)
    findings = []
    low = u.lower()
    pct = _PCT.findall(u)
    decoded_once = unquote(u)
    encoded_alnum = sum(1 for p in pct if chr(int(p[1:], 16)).isalnum())
    enc_slash_dot = sum(1 for p in pct if p.lower() in ("%2f", "%2e", "%5c"))
    dot_segments = len(re.findall(r"(^|/)\.\.?(/|$)", path))
    enc_dot_segments = len(re.findall(r"(%2e|\.)(%2e|\.)(%2f|/|%5c|\\)", low)) - dot_segments
    double = len(re.findall(r"%25[0-9a-f]{2}", low))
    is_ipv4 = bool(_IPV4.match(host)) and all(int(x) < 256 for x in _IPV4.match(host).groups())
    odd_ip = bool(_ODD_IP.match(host)) and not is_ipv4
    userinfo = "@" in authority
    params = [p for p in query.split("&") if p]
    redirect_with_url = 0
    for p in params:
        k, _, v = p.partition("=")
        if k.lower() in _REDIRECT_KEYS and _EMBEDDED.search(unquote(v)):
            redirect_with_url += 1
    rest = u[len(authority):]
    embedded = len(_EMBEDDED.findall(rest))
    tokens = re.split(r"[/?&=._\-+;,:]", path + "?" + query)
    longest = max((len(t) for t in tokens), default=0)
    last = path.rsplit("/", 1)[-1]
    labels = [x for x in host.split(".") if x]
    hidden = 0.0
    if len(labels) >= 4 and not is_ipv4:
        from app.detectors.lookalike_domain import split_domain
        reg = split_domain(host)[0]
        sub = host[: -len(reg)].rstrip(".").split(".") if reg and host.endswith(reg) else []
        hidden = float(len(sub) >= 2 and any(x in _TLD_WORDS for x in sub[1:]))
    feats = {
        "url_len": len(u) - len(host), "path_len": len(path), "query_len": len(query),
        "fragment_len": len(frag), "host_is_ipv4": float(is_ipv4), "host_odd_ip": float(odd_ip),
        "host_punycode": float("xn--" in host), "has_port": float(bool(port)),
        "odd_port": float(bool(port) and port not in ("80", "443")), "userinfo_at": float(userinfo),
        "at_anywhere": float("@" in rest), "path_depth": float(path.count("/")),
        "path_double_slash": float("//" in path), "dot_segments": float(dot_segments),
        "encoded_dot_segments": float(max(enc_dot_segments, 0)), "pct_count": float(len(pct)),
        "pct_ratio": len(pct) * 3 / max(len(u), 1), "double_encoding": float(double),
        "encoded_alnum": float(encoded_alnum), "encoded_slash_or_dot": float(enc_slash_dot),
        "params": float(len(params)), "redirect_param_with_url": float(redirect_with_url),
        "embedded_url": float(embedded), "longest_token": float(longest),
        "path_digit_ratio": sum(c.isdigit() for c in path) / max(len(path), 1),
        "path_entropy": _entropy(path), "query_entropy": _entropy(query),
        "base64_blob": float(bool(_B64.search(path + "?" + query))), "hex_blob": float(bool(_HEX.search(path + query))),
        "exec_download": float(bool(_EXEC.search(last))), "archive_download": float(bool(_ARCHIVE.search(last))),
        "script_page": float(bool(_SCRIPT_PAGE.search(last))),
        "special_chars": float(sum(u.count(c) for c in "!*'(),$|^{}[]<>\\`")), "tilde": float("~" in u),
        "semicolon": float(";" in u), "uppercase_ratio": sum(c.isupper() for c in path + query) / max(len(path + query), 1),
        "non_ascii": float(not decoded_once.isascii()), "subdomain_count": float(max(len(labels) - 2, 0)),
        "host_len": float(len(host)), "host_dots": float(host.count(".")), "hidden_domain_in_host": hidden,
    }
    # plain-language findings for the explicit tricks
    if userinfo:
        fake = authority.rsplit("@", 1)[0]
        findings.append(f"'@' trick: the browser ignores '{fake[:40]}' and actually goes to {host}")
    if odd_ip:
        findings.append(f"IP address disguised as '{host}' (a number / hex / octal form of an IP)")
    elif is_ipv4:
        findings.append(f"link points to a bare IP address ({host}) instead of a name")
    if dot_segments or feats["encoded_dot_segments"]:
        findings.append("'../' path tricks (directory traversal / path confusion)")
    if double:
        findings.append(f"double encoding ({double}x '%25..') to slip past filters")
    if encoded_alnum >= 3:
        findings.append(f"{encoded_alnum} ordinary letters/digits written as %-codes (hides words from filters)")
    if redirect_with_url:
        findings.append("a parameter carries a second link (the page can forward you elsewhere)")
    elif embedded:
        findings.append("another web address is hidden inside the path or query")
    if feats["odd_port"]:
        findings.append(f"unusual port :{port}")
    if feats["host_punycode"]:
        findings.append("punycode (xn--) host: letters from another alphabet")
    if feats["exec_download"]:
        findings.append(f"link downloads a program file ({last[-12:]})")
    if feats["base64_blob"] or feats["hex_blob"]:
        findings.append("long encoded / random-looking blob in the link (tracking a victim or hiding data)")
    if hidden:
        findings.append(f"a domain-looking name is hidden in front of the real site ({host[:60]})")
    if feats["path_double_slash"]:
        findings.append("'//' inside the path")
    return [float(feats[n]) for n in FEATURES], findings


def has_structure(url: str) -> bool:
    """Only links with a real path or query are judged by the model: a bare 'site.com' has no link
    structure to manipulate (the domain models judge the name)."""
    _, _, _, path, query, _ = split(normalise(url))
    return path.strip("/") != "" or query != ""


# tricks with no innocent use in a link someone sends you -> always "high"
UNAMBIGUOUS = ("'@' trick", "IP address disguised")
# server-attack tricks (path traversal) that are rare in the phishing datasets -> at least "check carefully"
AT_LEAST_VERIFY = ("'../' path tricks",)

# ---------------------------------------------------------------------------
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
            ok = isinstance(b, dict) and b.get("kind") == "cyberguard-url-manipulation" and list(b["features"]) == FEATURES
            b = b if ok else None
        except Exception:
            b = None
        _cache.update(mtime=mtime, bundle=b)
    return _cache.get("bundle")


def assess(url: str):
    """-> dict with probability, level and the explicit tricks found, or None if there is no model."""
    b = load_model()
    if b is None or not (url or "").strip():
        return None
    feats, findings = manipulation_features(url)
    out = {"thrAlert": b["thr_alert"], "thrVerify": b["thr_verify"], "findings": findings, "url": normalise(url)[:200]}
    if has_structure(url):
        p = float(b["model"].predict_proba([feats])[0][1])
        level = "high" if p >= b["thr_alert"] else "medium" if p >= b["thr_verify"] else "low"
    else:
        p, level = 0.0, "low"
        out["noPath"] = True
    if any(f.startswith(UNAMBIGUOUS) for f in findings):
        p, level = max(p, b["thr_alert"]), "high"
        out["unambiguousTrick"] = True
    elif level == "low" and any(f.startswith(AT_LEAST_VERIFY) for f in findings):
        p, level = max(p, b["thr_verify"]), "medium"
    return {**out, "probability": p, "level": level}
