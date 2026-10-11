"""
URL features v2 — scheme-agnostic, deterministic, no network calls.

Why this exists
---------------
The v1 features in url_features.py include `has_https`. In the training CSVs
that ship with the project, every benign URL has no scheme and most malicious
URLs do, so the models learned "has https -> malicious" and flagged
google.com. v2 removes the scheme entirely: every URL is parsed as if it had
the same neutral scheme, so a model can never learn from it.

v2 also adds features that describe *how a phishing URL is built* (brand name
in a domain that is not the brand's, open-redirect parameters, shorteners,
digit runs, token structure) instead of only counting characters.

The same function is used by the training script and by the live detector, so
training and inference can never drift apart.
"""
import math
import re
from urllib.parse import urlparse, parse_qsl, unquote

from app.detectors.url_features import SUSPICIOUS_TLDS, IP_RE

FEATURE_NAMES_V2 = [
    "url_len", "host_len", "path_len", "query_len",
    "host_dots", "host_hyphens", "host_digits", "host_digit_ratio",
    "num_subdomains", "path_depth", "num_params", "num_pct_enc",
    "has_ip", "has_port", "has_at", "has_punycode",
    "tld_suspicious", "tld_len", "host_entropy", "path_entropy",
    "host_longest_token", "host_num_tokens", "is_shortener",
    "brand_in_host_mismatch", "brand_in_path_mismatch",
    "sensitive_words_host", "sensitive_words_path",
    "redirect_param", "has_double_slash_path", "long_digit_run",
    "upper_ratio", "non_ascii", "registered_domain_len", "subdomain_len",
]

# Public link shorteners: the destination is hidden until the link is opened.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "ow.ly",
    "buff.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "t.ly", "v.gd",
    "s.id", "bl.ink", "soo.gd", "lnkd.in", "goo.gl", "tr.im",
}

# Dynamic-QR services: the printed code points at the service, and the owner
# can change the real destination afterwards. Extend this list as you learn more.
DYNAMIC_QR_SERVICES = {"qrco.de", "me-qr.com"}

# Two-part public suffixes so registered_domain() works without a big library.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "ac.in", "gov.in", "nic.in", "edu.in", "res.in",
    "co.jp", "ne.jp", "or.jp", "com.br", "com.mx", "com.ar", "com.cn", "net.cn",
    "co.za", "com.sg", "com.tr", "co.nz", "com.pk", "com.bd", "co.id", "com.my",
    "com.ph", "com.vn", "co.kr", "com.hk", "com.tw", "co.il", "com.ng", "co.ke",
}

# Official registrable domains per brand. A brand word in a host whose
# registered domain is NOT in this set is treated as a mismatch. The list is
# deliberately incomplete (regional domains you don't see here can produce a
# false "mismatch") — extend it for the brands your users care about.
BRAND_DOMAINS = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "office365.com", "microsoftonline.com",
                  "outlook.com", "azure.com", "windows.com", "bing.com", "msn.com", "xbox.com",
                  "sharepoint.com", "onedrive.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "google.co.in", "google.co.uk", "google.de", "google.ca", "google.fr",
               "google.com.au", "google.co.jp", "gmail.com", "youtube.com", "gstatic.com",
               "googleusercontent.com", "googleapis.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazon.ca",
               "amazon.fr", "amazon.it", "amazon.es", "amazon.com.au", "amazon.com.br", "amazon.com.mx",
               "amazon.ae", "amazon.sg", "amazonaws.com", "amazon.jobs"},
    "netflix": {"netflix.com", "nflxext.com"},
    "facebook": {"facebook.com", "fb.com", "fb.me", "messenger.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "twitter": {"twitter.com", "x.com", "t.co"},
    "telegram": {"telegram.org", "t.me"},
    "snapchat": {"snapchat.com"},
    "spotify": {"spotify.com"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebay.in", "ebay.de"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com"},
    "zoom": {"zoom.us", "zoom.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "metamask": {"metamask.io"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "irs": {"irs.gov"},
    "chase": {"chase.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "hdfcbank": {"hdfcbank.com", "hdfcbank.net", "hdfc.bank.in"},
    "icicibank": {"icicibank.com", "icici.bank.in"},
    "axisbank": {"axisbank.com", "axis.bank.in"},
    "onlinesbi": {"onlinesbi.sbi", "onlinesbi.com", "sbi.co.in", "sbicard.com", "sbi.bank.in"},
    "paytm": {"paytm.com", "paytmbank.com", "paytmmoney.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"},
    # --- more Indian brands that phishing targets (short names only match as a whole word) -------
    "sbi": {"onlinesbi.sbi", "onlinesbi.com", "sbi.co.in", "sbicard.com", "sbi.bank.in", "sbilife.co.in",
            "sbimf.com", "sbigeneral.in", "yonobusiness.sbi", "yonosbi.com"},
    "hdfc": {"hdfcbank.com", "hdfcbank.net", "hdfc.com", "hdfclife.com", "hdfcergo.com", "hdfcfund.com",
             "hdfcsec.com", "hdfc.bank.in"},
    "icici": {"icicibank.com", "icicidirect.com", "icicilombard.com", "iciciprulife.com", "icici.bank.in"},
    "kotak": {"kotak.com", "kotaksecurities.com", "kotaklife.com", "kotak.bank.in"},
    "irctc": {"irctc.co.in", "irctc.com", "irctctourism.com"},
    "airtel": {"airtel.in", "airtel.com"},
    "jio": {"jio.com", "jiomart.com", "jiocinema.com", "jiosaavn.com"},
    "uidai": {"uidai.gov.in"},
    "aadhaar": {"uidai.gov.in"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in"},
    "epfo": {"epfindia.gov.in"},
    "indiapost": {"indiapost.gov.in"},
    "npci": {"npci.org.in"},
    "bhim": {"bhimupi.org.in"},
    "bput": {"bput.ac.in"},
    "myntra": {"myntra.com"},
    "swiggy": {"swiggy.com"},
    "zomato": {"zomato.com"},
}

# Nicknames that clearly mean a brand (matched as whole words only).
BRAND_ALIASES = {
    "m365": "microsoft", "o365": "microsoft", "office365": "microsoft", "msoffice": "microsoft",
    "onedrive": "microsoft", "sharepoint": "microsoft", "outlook": "microsoft", "hotmail": "microsoft",
    "icloud": "apple", "appleid": "apple", "gmail": "google", "gdrive": "google", "fb": "facebook",
    "insta": "instagram", "yono": "sbi", "sbionline": "sbi", "netflx": "netflix", "amzn": "amazon",
    "phonepay": "phonepe", "gpay": "google", "paytmbank": "paytm",
}

# Only government / regulated registrars can hand out names under these suffixes, so a brand word
# there is not impersonation (e.g. uidai.gov.in; Indian banks are moving to <bank>.bank.in).
CONTROLLED_SUFFIXES = (".gov.in", ".nic.in", ".bank.in", ".gov")

SENSITIVE_WORDS = (
    "login", "signin", "verify", "secure", "account", "update", "confirm", "password",
    "wallet", "banking", "support", "billing", "invoice", "recovery", "suspend", "alert",
)

REDIRECT_PARAMS = {
    "url", "redirect", "redirect_uri", "redirecturl", "next", "continue", "return",
    "returnurl", "return_to", "target", "dest", "destination", "goto", "link", "u",
    "q", "r", "to", "out", "uri", "adurl", "rurl", "redir",   # only counts when the value is a full link
}

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def split_url(url: str) -> dict:
    """Parses a URL as if it always had the same scheme. Never raises."""
    u = (url or "").strip()
    if "://" not in u:
        u = "http://" + u.lstrip("/")
    try:
        p = urlparse(u)
        host = (p.hostname or "").lower().rstrip(".")
        has_port = 1 if p.port else 0
        return {"host": host, "path": p.path or "", "query": p.query or "",
                "has_port": has_port, "has_at": 1 if "@" in p.netloc else 0}
    except ValueError:
        return {"host": "", "path": "", "query": "", "has_port": 0, "has_at": 1 if "@" in "".join(u.split("/")[2:3]) else 0}


def registered_domain(host: str) -> str:
    """Best-effort registrable domain (example.co.uk, example.com). IPs are returned unchanged."""
    if not host or IP_RE.match(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _leet_normalize(token: str) -> str:
    return token.translate(_LEET).replace("rn", "m").replace("vv", "w")


def _within_one_edit(a: str, b: str) -> bool:
    """One typo apart: one letter changed, added, removed, or two neighbours swapped (hdfcbnak)."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]:
            return True
        return len(diff) == 1
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    i = 0
    while i < len(short) and short[i] == long_[i]:
        i += 1
    return short[i:] == long_[i + 1:]


def _token_matches_brand(token: str, brand: str, allow_substring: bool) -> bool:
    if not token:
        return False
    t = _leet_normalize(token)
    if t == brand or token == brand:
        return True
    if len(brand) >= 6:
        if _within_one_edit(t, brand):
            return True
        if allow_substring and brand in t:
            return True
    return False


def brand_in_host(host: str) -> str | None:
    """Returns the brand name if the host uses a brand word but is not one of that brand's domains."""
    reg = registered_domain(host)
    if host.endswith(CONTROLLED_SUFFIXES):
        return None
    tokens = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    for brand, official in BRAND_DOMAINS.items():
        if reg in official or host in official:
            continue
        if any(_token_matches_brand(t, brand, allow_substring=True) for t in tokens):
            return brand
    for t in tokens:                                  # m365-login.top -> microsoft
        brand = BRAND_ALIASES.get(t)
        if brand and reg not in BRAND_DOMAINS.get(brand, ()) and host not in BRAND_DOMAINS.get(brand, ()):
            return brand
    return None


def brand_in_path(host: str, path: str) -> str | None:
    reg = registered_domain(host)
    tokens = [t for t in re.split(r"[^a-z0-9]+", path.lower()) if t]
    for brand, official in BRAND_DOMAINS.items():
        if reg in official or host in official:
            continue
        if any(_token_matches_brand(t, brand, allow_substring=False) for t in tokens):
            return brand
    return None


def is_shortener(host: str) -> bool:
    reg = registered_domain(host)
    return host in SHORTENERS or reg in SHORTENERS or host in DYNAMIC_QR_SERVICES or reg in DYNAMIC_QR_SERVICES


def has_redirect_param(query: str) -> bool:
    for key, value in parse_qsl(query, keep_blank_values=True):
        if key.lower() in REDIRECT_PARAMS and unquote(value).lower().startswith(("http://", "https://", "//")):
            return True
    return False


def _is_ip_host(host: str) -> bool:
    return bool(IP_RE.match(host)) or (host.isdigit() and len(host) >= 8) or bool(re.fullmatch(r"0x[0-9a-f]{6,8}", host))


def extract_features_v2(url: str) -> list:
    """Returns a list of floats in FEATURE_NAMES_V2 order."""
    raw = (url or "").strip()
    parts = split_url(raw)
    host, path, query = parts["host"], parts["path"], parts["query"]
    reg = registered_domain(host)
    subdomain = host[: -len(reg)].rstrip(".") if reg and host.endswith(reg) else ""
    host_tokens = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    tail = f"{path}?{query}".lower() if query else path.lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    digit_runs = re.findall(r"\d+", host + path)
    path_and_query = path + query

    return [
        float(len(raw)), float(len(host)), float(len(path)), float(len(query)),
        float(host.count(".")), float(host.count("-")),
        float(sum(c.isdigit() for c in host)),
        round(sum(c.isdigit() for c in host) / max(len(host), 1), 4),
        float(len(subdomain.split(".")) if subdomain else 0),
        float(len([s for s in path.split("/") if s])),
        float(len(query.split("&")) if query else 0),
        float(raw.count("%")),
        1.0 if _is_ip_host(host) else 0.0,
        float(parts["has_port"]), float(parts["has_at"]),
        1.0 if "xn--" in host else 0.0,
        1.0 if tld in SUSPICIOUS_TLDS else 0.0,
        float(len(tld)),
        round(_entropy(host), 4), round(_entropy(path), 4),
        float(max((len(t) for t in host_tokens), default=0)),
        float(len(host_tokens)),
        1.0 if is_shortener(host) else 0.0,
        1.0 if brand_in_host(host) else 0.0,
        1.0 if brand_in_path(host, path) else 0.0,
        float(min(sum(host.count(w) for w in SENSITIVE_WORDS), 5)),
        float(min(sum(tail.count(w) for w in SENSITIVE_WORDS), 5)),
        1.0 if has_redirect_param(query) else 0.0,
        1.0 if "//" in path else 0.0,
        float(min(max((len(r) for r in digit_runs), default=0), 20)),
        round(sum(c.isupper() for c in path_and_query) / max(len(path_and_query), 1), 4),
        1.0 if any(ord(c) > 127 for c in raw) else 0.0,
        float(len(reg)), float(len(subdomain)),
    ]