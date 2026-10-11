"""
Domain-name phishing model: "does this registered domain NAME look like the names phishers register?"

ONE implementation used by training (app/ml/training/train_url_domain.py) and scanning
(app/detectors/malicious_url.py), so they can never drift apart.

Why only the domain name (not the whole URL)?
  In the public PhiUSIIL dataset every legitimate URL is a bare homepage "https://www.<domain>"
  while phishing URLs have paths, http:// etc. A model trained on whole URLs learns that format
  difference, not phishing. Comparing registered domain to registered domain removes that shortcut.
  Paths, '@' tricks, redirects and pages are judged by rules and live checks instead.

What counts as the "registered domain" uses the Public Suffix List (offline copy shipped with
tldextract, no internet needed):  netbanking.hdfcbank.com -> hdfcbank.com,
evil-login.web.app -> evil-login.web.app (web.app is a hosting platform, the attacker owns the name).
Sites on hosting platforms and raw IPs are NOT scored by the model (the data has no legitimate
examples of them, so a model would just learn "platform = phishing"); rules cover them.
"""
import math
import os
import re

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "models", "url_domain_model.joblib")
BUNDLE_KIND, BUNDLE_VERSION = "domain-name", 1

_extract = None
_extract_icann = None


def _extractors():
    global _extract, _extract_icann
    if _extract is None:
        import tldextract
        # suffix_list_urls=() -> use the copy bundled with the library; never downloads anything
        _extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
        _extract_icann = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)
    return _extract, _extract_icann


IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def site_parts(host: str) -> dict:
    """{'name','suffix','site','subdomain','platform','ip'} for a host name."""
    host = (host or "").lower().strip().rstrip(".")
    if not host or IP_RE.match(host) or ":" in host:
        return {"name": "", "suffix": "", "site": host, "subdomain": "", "platform": None, "ip": bool(host)}
    ex, ex_icann = _extractors()
    r, ri = ex(host), ex_icann(host)
    platform = r.suffix if r.suffix != ri.suffix else None      # e.g. web.app, github.io, netlify.app
    site = f"{r.domain}.{r.suffix}" if r.domain and r.suffix else host
    return {"name": r.domain, "suffix": r.suffix, "site": site, "subdomain": r.subdomain,
            "platform": platform, "ip": False}


# Brand and "security" words are only FEATURES here (counts), the rules in url_features_v2 decide
# official-vs-fake. Kept in sync on purpose: changing them requires retraining.
BRAND_WORDS = ("paypal apple icloud microsoft office outlook live hotmail google gmail amazon netflix facebook "
               "instagram whatsapp meta linkedin twitter dhl fedex ups usps chase wellsfargo bankofamerica citi "
               "hsbc barclays santander bnp coinbase binance metamask adobe dropbox docusign yahoo aol att verizon "
               "steam roblox sbi hdfc icici axis kotak paytm phonepe irctc airtel jio flipkart bput uidai aadhaar "
               "incometax epfo").split()
SENSITIVE = ("login logon signin signup verify verification secure security account update confirm support "
             "service banking bank wallet billing payment invoice recovery unlock suspend alert auth webmail").split()
FEATURES = ["len", "digits", "digit_ratio", "hyphens", "entropy", "longest_alpha", "vowel_ratio",
            "max_consonant_run", "tokens", "brand", "sensitive", "punycode", "tld_len", "suffix_parts", "tld_rate"]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def name_features(name: str, suffix: str, tld_rate: dict, prior: float) -> list[float]:
    toks = [t for t in re.split(r"[-\d]+", name) if t]
    alpha = re.findall(r"[a-z]+", name)
    letters = sum(ch.isalpha() for ch in name)
    return [
        float(len(name)), float(sum(ch.isdigit() for ch in name)),
        sum(ch.isdigit() for ch in name) / max(len(name), 1), float(name.count("-")), _entropy(name),
        float(max((len(a) for a in alpha), default=0)),
        sum(ch in "aeiou" for ch in name) / max(letters, 1),
        float(max((len(m) for m in re.findall(r"[bcdfghjklmnpqrstvwxyz]+", name)), default=0)),
        float(len(toks)), float(any(b in name for b in BRAND_WORDS)),
        float(sum(w in name for w in SENSITIVE)), float(name.startswith("xn--")),
        float(len(suffix)), float(suffix.count(".")),
        float(tld_rate.get(suffix, prior)),
    ]


def text_of(name: str, suffix: str) -> str:
    return f"{name} .{suffix}"


_cache: dict = {}


def load():
    """The trained bundle, reloaded when the file changes. None if missing or not this kind of model."""
    if not os.path.exists(MODEL_PATH):
        _cache.clear()
        return None
    mtime = os.path.getmtime(MODEL_PATH)
    if _cache.get("mtime") != mtime:
        try:
            import joblib
            b = joblib.load(MODEL_PATH)
            ok = b.get("kind") == BUNDLE_KIND and b.get("version") == BUNDLE_VERSION and b.get("features") == FEATURES
            _cache.update(mtime=mtime, bundle=b if ok else None)
        except Exception:
            _cache.update(mtime=mtime, bundle=None)
    return _cache.get("bundle")


def probabilities(bundle: dict, names, suffixes):
    """Average of the two models for many domains at once (numpy array)."""
    import numpy as np
    names, suffixes = list(names), list(suffixes)
    x = np.asarray([name_features(n, s, bundle["tld_rate"], bundle["prior"]) for n, s in zip(names, suffixes)],
                   dtype=np.float32)
    p1 = bundle["hgb"].predict_proba(x)[:, 1]
    p2 = bundle["lr"].predict_proba(bundle["vec"].transform([text_of(n, s) for n, s in zip(names, suffixes)]))[:, 1]
    return (p1 + p2) / 2


def probability(bundle: dict, name: str, suffix: str) -> float:
    return float(probabilities(bundle, [name], [suffix])[0])


def assess(host: str):
    """Model view of a host, or None when the model does not apply (no model, IP, hosting platform)."""
    b = load()
    if b is None:
        return None
    parts = site_parts(host)
    if parts["ip"] or parts["platform"] or not parts["name"]:
        return None
    p = probability(b, parts["name"], parts["suffix"])
    return {"probability": p, "site": parts["site"], "threshold": b["threshold"],
            "flagged": p >= b["threshold"], "card": b.get("card", {})}
