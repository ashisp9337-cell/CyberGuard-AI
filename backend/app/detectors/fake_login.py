"""
Fake Login Page model (URL Security -> "Fake login page", Phishing -> "Fraudulent website" and the general URL pages):
judges the HTML of the page a link leads to - fetched read-only by safe_fetch.py during a live scan - with the clues
in login_page_features.py (the same code the model was trained with, train_fake_login.py).

No page (offline scan, site down, not HTML), a page that shows nothing without JavaScript, or no model file -> None:
the model gives no verdict, never a guess.
File: app/ml/models/fake_login.joblib
"""
from __future__ import annotations

import os

from app.detectors import login_page_features as LF

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "models", "fake_login.joblib")
KIND = "cyberguard-fake-login"
_cache: dict = {}


def load():
    """-> model bundle or None. Reloads when the file changes (drop a new file in, no restart)."""
    if not os.path.exists(MODEL_PATH):
        return None
    mtime = os.path.getmtime(MODEL_PATH)
    if _cache.get("mtime") != mtime:
        try:
            import joblib
            b = joblib.load(MODEL_PATH)
            ok = isinstance(b, dict) and b.get("kind") == KIND and b.get("features") == LF.FEATURES
            _cache.update(mtime=mtime, bundle=b if ok else None)
        except Exception:
            _cache.update(mtime=mtime, bundle=None)
    return _cache["bundle"]


MIN_TEXT = 300          # visible characters


def judgeable(values: dict) -> bool:
    """False for a page that shows (almost) nothing without JavaScript: no input field and under MIN_TEXT visible
    characters. Many real sites send only an empty app shell that a browser fills in later (LeetCode, Canva ...),
    while the model's real pages were urlscan's browser-rendered copies - so such a shell would look like a bare
    phishing kit. A page like that gives no verdict (the same rule is applied in training)."""
    import math
    return values["n_inputs"] > 0 or math.expm1(values["log_text_chars"]) >= MIN_TEXT


def asks_for_secrets(values: dict) -> bool:
    """The page asks for something worth stealing: a password, a card / OTP / ID field, or login wording."""
    return bool(values["has_password"] or values["n_sensitive_fields"] or values["has_login_words"])


def assess(html: str | None, page_url: str) -> dict | None:
    """-> {"probability", "level", "thrAlert", "thrVerify", "facts", "trainedAt"} or None (no model / no page)."""
    b = load()
    if b is None or not html or len(html) < 200:
        return None
    values = LF.extract(html, page_url)
    if not judgeable(values):
        return None
    p = float(b["model"].predict_proba([LF.vector(values)])[0][1])
    ta, tv = float(b["thr_alert"]), float(b["thr_verify"])
    level = "high" if p >= ta else "medium" if p >= tv else "low"
    # chosen at training time from the measured false alarms: a page that asks for nothing is at most "verify"
    if level == "high" and b.get("alert_needs_ask") and not asks_for_secrets(values):
        level = "medium"
    return {"probability": p, "level": level,
            "thrAlert": ta, "thrVerify": tv, "facts": values["_facts"], "trainedAt": b.get("trained_at")}


def reasons(facts: dict) -> list[str]:
    """The page's clues in plain words (for the explanation)."""
    out = []
    if facts.get("brands_imitated"):
        out.append(f"presents itself as {', '.join(facts['brands_imitated'])} on a site that is not theirs")
    if facts.get("external_form"):
        out.append("its form sends what you type to another website")
    if facts.get("exfil"):
        out.append("contains a hidden data-collection endpoint (Telegram / Discord bot, form service or a .php script)")
    if facts.get("copied_from_brand"):
        out.append(f"loads {facts['copied_from_brand']} file(s) straight from the real brand's servers (copied page)")
    if facts.get("dead_link_share", 0) >= 0.5:
        out.append(f"{facts['dead_link_share'] * 100:.0f}% of its links go nowhere (#)")
    if facts.get("obfuscation"):
        out.append("uses scrambled JavaScript")
    if facts.get("sensitive_fields"):
        out.append("asks for " + ", ".join(facts["sensitive_fields"][:3]))
    if facts.get("password_fields"):
        out.append("asks for a password")
    return out
