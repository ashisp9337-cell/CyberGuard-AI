"""
Government Official Impersonation detector.

Data source: app/ml/models/government_official_impersonation.joblib (TRAINED)
  TF-IDF + Logistic Regression, trained on 192 REAL government-agency
  impersonation phishing messages (HMRC/DVLA/Income Tax Dept tax-refund
  scams) plus synthetic examples covering themes the real data barely
  represents (arrest-warrant threats, immigration/visa fee scams, customs
  threats). See train_government_impersonation.py for exactly what's real
  vs synthetic. Auto-reloads on change.

Domain check: unlike banks or consumer brands, there is no fixed list of
"real government domains" — there are thousands of agencies worldwide. But
genuine government domains DO follow a recognizable pattern (.gov, .gov.in,
.gov.uk, .nic.in, .gc.ca, .gov.au, etc.), so this detector checks whether a
message CLAIMING to be from a government agency comes from a domain matching
that pattern, rather than needing a maintained list of specific agencies.
This is necessarily a loose heuristic: it will not catch a scam using a
government-TLD look-alike, and some real agencies may use non-standard
domains — it's one signal among several, not a verdict on its own.
"""
from __future__ import annotations

import os
import re
import uuid

import joblib

from app.detectors import phishing
from app.detectors.base import build_result

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "..", "ml", "models", "government_official_impersonation.joblib")

_model_cache: tuple[float, object] | None = None

# Claiming to represent a government body, in casual phrasing people actually use.
GOV_CLAIM_WORDS = (
    "government", "govt", "irs", "hmrc", "dvla", "income tax department", "income tax dept",
    "immigration department", "passport office", "social security", "court", "arrest warrant",
    "customs department", "election commission", "municipal corporation", "ministry of",
    "police department", "department of motor vehicles", "dmv", "benefits office",
)
GOV_TLD_PATTERN = re.compile(r"\.gov(\.[a-z]{2,3})?$|\.gc\.ca$|\.nic\.in$|\.mil$", re.I)


def _domain_of(email: str) -> str:
    return email.strip().lower().rsplit("@", 1)[-1] if "@" in email else ""


def _claims_government(text: str) -> bool:
    low = text.lower()
    return any(w in low for w in GOV_CLAIM_WORDS)


def _ind(triggered: bool, label: str, description: str, severity: str, weight: int) -> dict:
    return {"id": f"IND_{uuid.uuid4().hex[:12]}", "label": label, "description": description,
            "severity": severity, "weight": weight, "triggered": bool(triggered)}


def _get_model():
    global _model_cache
    if not os.path.exists(MODEL_PATH):
        _model_cache = None
        return None
    mtime = os.path.getmtime(MODEL_PATH)
    if _model_cache and _model_cache[0] == mtime:
        return _model_cache[1]
    try:
        model = joblib.load(MODEL_PATH)
    except Exception:
        model = None
    _model_cache = (mtime, model)
    return model


def analyze_government_impersonation(text: str, extra_field_values: dict, subtopic_title: str) -> dict:
    text = text or ""
    sender_email = (extra_field_values or {}).get("senderEmail", "").strip().lower()
    indicators: list[dict] = []

    if _claims_government(text):
        actual_domain = _domain_of(sender_email)
        if sender_email and not GOV_TLD_PATTERN.search(actual_domain):
            indicators.append(_ind(
                True, "Sender domain doesn't match a government pattern",
                f"The message claims to represent a government agency, but '{actual_domain}' doesn't match "
                "a recognized government domain pattern (.gov, .gov.in, .gov.uk, .nic.in, etc.). This is a "
                "loose signal, not proof — some agencies use other domains, and a scammer could pick a "
                "look-alike government-style domain.",
                "medium", 25,
            ))
        elif not sender_email:
            indicators.append(_ind(
                True, "No sender email given to verify",
                "The message claims to represent a government agency, but no sender email was provided "
                "to check against a government domain pattern.",
                "low", 5,
            ))

    general = phishing._rule_indicators(text, sender=sender_email or None, reply_to=None) if text.strip() else []
    indicators.extend(general)

    rule_score = sum(i["weight"] for i in indicators if i["triggered"])
    model = _get_model()
    model_used = model is not None and bool(text.strip())
    proba = None
    if model_used:
        try:
            proba = float(model.predict_proba([text])[0][1])
            blended = 0.65 * (proba * 100) + 0.35 * min(rule_score, 100)
            confidence = 60 + abs(proba - 0.5) * 60
        except Exception:
            model_used = False
            blended = min(rule_score, 100)
            confidence = 40 + min(rule_score, 50)
    else:
        blended = min(rule_score, 100)
        confidence = 40 + min(rule_score, 50)

    for ind in indicators:
        ind.setdefault("id", f"IND_{uuid.uuid4().hex[:12]}")
    triggered = [i for i in indicators if i["triggered"]]

    if not text.strip():
        explanation, blended, confidence = "No content was submitted to analyze.", 0, 0
    elif triggered:
        top = sorted(triggered, key=lambda i: -i["weight"])[:3]
        names = ", ".join(i["label"].lower() for i in top)
        model_note = f" Trained classifier: {proba*100:.0f}% probability of impersonation." if model_used else " (Trained model unavailable — rule-based only.)"
        explanation = f"{len(triggered)} indicator(s) triggered, most notably: {names}.{model_note}"
    else:
        model_note = f"the trained classifier assessed a {proba*100:.0f}% probability of impersonation" if model_used else "no trained model was available"
        explanation = f"No rule-based indicators were triggered; {model_note}."

    return build_result(
        indicators=indicators, base_score=blended, confidence=confidence,
        engine_name=f"CYBERGUARD Impersonation Engine — {'TF-IDF+LogReg (192 real + synthetic)' if model_used else 'Rule-Based (model unavailable)'}",
        threat_type=subtopic_title, explanation=explanation,
    )