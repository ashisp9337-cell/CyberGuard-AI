"""
2026 link model: does a whole link (site name + path) look like the phishing links seen in 2026?

Trained by app/ml/training/train_link_2026.py on the urlscan.io collection made on this PC (real phishing links from
OpenPhish / PhishTank and real sites' pages, September-October 2026): character pieces (3-5 letters) of the link,
logistic regression. Tested on links from LATER days and other sites than it was trained on. Alert / verify levels:
the scores only 0.5% / 5% of real links reach (real urlscan pages + real 2026 sites from the Chrome UX Report); in the
URL engine only the alert level raises a score.
It only reads the link text - nothing is opened. Used by the URL engine like every URL model: it can only RAISE a
score. Without the model file it is simply not used.
"""
from __future__ import annotations

import os
import re

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "models", "link_2026.joblib")
KIND = "cyberguard-link-2026"
_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]{0,15}://", re.I)
_cache: dict = {}


def normalise(url: str) -> str:
    """Lower-case, no scheme, no leading 'www.', no '#...' part, numbers -> 0, at most 300 characters. On a free
    website host the platform's own name (vercel.app, github.io, pages.dev ...) becomes the same word 'freehost', so
    the model judges the name the uploader chose and the page, not which platform it is on."""
    from app.detectors.malicious_url import free_host
    u = _SCHEME.sub("", (url or "").strip().lower())
    u = u[4:] if u.startswith("www.") else u
    u = u.split("#", 1)[0]
    cut = min([i for i in (u.find("/"), u.find("?")) if i >= 0] or [len(u)])
    host, rest = u[:cut].split(":")[0], u[cut:]
    platform, name = free_host(host)
    if platform:
        host = f"{name}.freehost" if name else "freehost"
    return re.sub(r"\d+", "0", host + rest)[:300]


def load_model():
    if not os.path.exists(MODEL_PATH):
        _cache.clear()
        return None
    mtime = os.path.getmtime(MODEL_PATH)
    if _cache.get("mtime") != mtime:
        try:
            import joblib
            b = joblib.load(MODEL_PATH)
            b = b if isinstance(b, dict) and b.get("kind") == KIND else None
        except Exception:                      # a broken model file never breaks a scan
            b = None
        _cache.update(mtime=mtime, bundle=b)
    return _cache.get("bundle")


def assess(url: str) -> dict | None:
    b = load_model()
    if b is None or not (url or "").strip():
        return None
    p = float(b["pipeline"].predict_proba([normalise(url)])[0][1])
    level = "high" if p >= b["thr_alert"] else "medium" if p >= b["thr_verify"] else "low"
    return {"probability": p, "level": level, "thrAlert": b["thr_alert"], "thrVerify": b["thr_verify"],
            "trainedAt": b.get("trained_at")}
