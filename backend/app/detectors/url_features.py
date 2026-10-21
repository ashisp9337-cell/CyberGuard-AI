"""
Real, deterministic lexical/structural feature extraction for URLs.
No network calls here — this is pure static analysis, shared by both the
training pipeline and the live detector.
"""
import math
import re
from urllib.parse import urlparse

FEATURE_NAMES = [
    "url_length", "domain_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_underscores", "num_at",
    "num_digits", "num_params", "num_subdomains",
    "has_https", "has_ip", "has_port", "has_punycode",
    "suspicious_tld", "entropy", "digit_ratio",
]

SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "cricket", "science", "work",
    "party", "gq", "link", "xyz", "top", "club", "tk", "ml", "ga", "cf",
}

IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def extract_url_features(url: str) -> list:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except Exception:
        parsed = urlparse("http://invalid")

    host = parsed.netloc.split("@")[-1].split(":")[0] or ""
    path = parsed.path or ""
    query = parsed.query or ""
    tld = host.rsplit(".", 1)[-1].lower() if "." in host else ""

    return [
        len(url),
        len(host),
        len(path),
        len(query),
        url.count("."),
        url.count("-"),
        url.count("_"),
        url.count("@"),
        sum(c.isdigit() for c in url),
        query.count("=") if query else 0,
        max(host.count(".") - 1, 0),
        # typed without http(s):// -> unknown, not "no HTTPS" (the scheme is only known when given)
        1 if parsed.scheme == "https" or "://" not in url else 0,
        1 if IP_RE.match(host) else 0,
        1 if parsed.port else 0,
        1 if "xn--" in host else 0,
        1 if tld in SUSPICIOUS_TLDS else 0,
        round(_entropy(url), 3),
        round(sum(c.isdigit() for c in url) / max(len(url), 1), 3),
    ]


def explain_url_features(url: str, feature_values: list) -> list[dict]:
    """Turns raw feature values into human-readable indicator dicts."""
    f = dict(zip(FEATURE_NAMES, feature_values))
    indicators = []

    def add(cond, label, desc, severity, weight):
        indicators.append({
            "label": label, "description": desc, "severity": severity,
            "weight": weight, "triggered": bool(cond),
        })

    add(f["has_ip"] == 1, "IP address used instead of domain",
        "The URL uses a raw IP address rather than a domain name, a common evasion technique.",
        "critical", 22)
    add(f["has_https"] == 0, "No HTTPS encryption",
        "The connection is not secured with HTTPS.", "high", 15)
    add(f["num_subdomains"] >= 3, "Excessive subdomains",
        f"The domain has {f['num_subdomains']} subdomain levels, often used to obscure the real host.",
        "high", 16)
    add(f["suspicious_tld"] == 1, "Suspicious top-level domain",
        "Uses a TLD frequently abused for phishing/spam campaigns.", "medium", 12)
    add(f["has_punycode"] == 1, "Punycode / homoglyph domain",
        "Domain uses punycode encoding, often used to visually impersonate a trusted brand.",
        "critical", 24)
    # Only an '@' BEFORE the host hides the real destination (paypal.com@evil.tk). An '@' in the path is normal on
    # many real sites (medium.com/@name, youtube.com/@channel) - fixed 21 Oct after real posts were flagged.
    authority = (url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]) if url else ""
    add("@" in authority, "'@' character in URL",
        "The '@' symbol before the website name hides the real destination: the browser ignores everything before it.",
        "high", 18)
    add(f["url_length"] > 90, "Unusually long URL",
        f"URL is {int(f['url_length'])} characters long, often used to obscure malicious paths/parameters.",
        "medium", 10)
    add(f["entropy"] > 4.3, "High character entropy",
        "The URL has unusually high randomness, consistent with generated/obfuscated links.",
        "medium", 10)
    add(f["num_hyphens"] >= 4, "Excessive hyphens in domain/path",
        "Multiple hyphens are commonly used in look-alike domains (e.g. paypal-secure-login.com).",
        "medium", 11)
    add(f["has_port"] == 1, "Non-standard port specified",
        "URL explicitly specifies a port, uncommon for legitimate consumer-facing sites.",
        "low", 6)
    return indicators
