"""
Financial Institution Impersonation detector.

Uses TWO data sources, loaded fresh whenever either file changes on disk
(no backend restart needed):

  1. app/ml/models/financial_impersonation.joblib  (TRAINED)
     A TF-IDF + Logistic Regression classifier trained on
     app/ml/training/data/financial_institution_impersonation.csv via
     train_financial_impersonation.py. Scores the message's LANGUAGE.

  2. app/ml/training/data/financial_institutions.json  (FETCHED / reference)
     A plain lookup table of real institution names -> their real domains.
     Not trained — this is looked up at scan time to check whether a
     claimed institution's name in the message matches the sender's actual
     email domain, and to flag domains that don't match any real
     institution at all.

If the model file is missing, falls back to rule-based-only scoring (never
crashes, same convention as every other detector in this project).
"""
from __future__ import annotations

import json
import os
import re
import uuid

import joblib

from app.detectors import phishing
from app.detectors.base import build_result

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "..", "ml", "models", "financial_impersonation.joblib")
DOMAINS_PATH = os.path.join(HERE, "..", "ml", "training", "data", "financial_institutions.json")

_model_cache: tuple[float, object] | None = None
_domains_cache: tuple[float, dict] | None = None


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


def _get_domains() -> dict:
    """Returns {institution name (lowercase): [real domains]}. Never raises."""
    global _domains_cache
    if not os.path.exists(DOMAINS_PATH):
        return {}
    mtime = os.path.getmtime(DOMAINS_PATH)
    if _domains_cache and _domains_cache[0] == mtime:
        return _domains_cache[1]
    try:
        with open(DOMAINS_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        domains = {k.lower(): v for k, v in raw.items() if not k.startswith("_")}
    except Exception:
        domains = {}
    _domains_cache = (mtime, domains)
    return domains


def _domain_of(email: str) -> str:
    return email.strip().lower().rsplit("@", 1)[-1] if "@" in email else ""


def _find_claimed_institution(text: str, domains: dict) -> str | None:
    """Which institution (if any) does the message claim to be from? Longest name wins on overlap."""
    low = text.lower()
    matches = [name for name in domains if name in low]
    return max(matches, key=len) if matches else None


def _ind(triggered: bool, label: str, description: str, severity: str, weight: int) -> dict:
    return {"id": f"IND_{uuid.uuid4().hex[:12]}", "label": label, "description": description,
            "severity": severity, "weight": weight, "triggered": bool(triggered)}


def analyze_financial_impersonation(text: str, extra_field_values: dict, subtopic_title: str) -> dict:
    text = text or ""
    sender_email = (extra_field_values or {}).get("senderEmail", "").strip().lower()
    domains = _get_domains()
    indicators: list[dict] = []

    claimed = _find_claimed_institution(text, domains)
    if claimed:
        real_domains = [d.lower() for d in domains.get(claimed, [])]
        actual_domain = _domain_of(sender_email)
        # the bank's own domain or a subdomain of it (alerts.hdfcbank.net) is genuine; look-alikes are not
        own = bool(actual_domain) and any(actual_domain == d or actual_domain.endswith("." + d) for d in real_domains)
        if sender_email and real_domains and not own:
            indicators.append(_ind(
                True, "Sender domain does not match the claimed institution",
                f"The message claims to be from {claimed.title()}, but '{actual_domain}' is not one of its "
                f"known real domains ({', '.join(real_domains[:3])}).",
                "critical", 45,
            ))
        elif not sender_email:
            indicators.append(_ind(
                True, "No sender email given to verify",
                f"The message claims to be from {claimed.title()}, but no sender email was provided to check "
                "against its real domain.",
                "low", 5,
            ))
    elif sender_email:
        indicators.append(_ind(
            True, "Sender domain not recognized as any known institution",
            f"'{_domain_of(sender_email)}' does not match any financial institution in our reference list "
            "(the list may simply be incomplete — this is not proof of anything by itself).",
            "low", 8,
        ))

    # General phishing-language rules — same engine used for email/SMS, reused
    # here because impersonation attempts share the same manipulative language.
    general = phishing._rule_indicators(text, sender=sender_email or None, reply_to=None) if text.strip() else []
    indicators.extend(general)

    rule_score = sum(i["weight"] for i in indicators if i["triggered"])
    model = _get_model()
    model_used = model is not None and bool(text.strip())
    proba = None
    if model_used:
        try:
            proba = float(model.predict_proba([text])[0][1])
            blended = 0.6 * (proba * 100) + 0.4 * min(rule_score, 100)
            confidence = 65 + abs(proba - 0.5) * 60
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

    basis = f"claimed institution: {claimed.title()}" if claimed else "no specific institution identified in the text"
    if not text.strip():
        explanation = "No content was submitted to analyze."
        blended, confidence = 0, 0
    elif triggered:
        top = sorted(triggered, key=lambda i: -i["weight"])[:3]
        names = ", ".join(i["label"].lower() for i in top)
        model_note = f" Trained classifier: {proba*100:.0f}% probability of impersonation." if model_used else " (Trained model unavailable — rule-based only.)"
        explanation = f"{len(triggered)} indicator(s) triggered ({basis}), most notably: {names}.{model_note}"
    else:
        model_note = f"the trained classifier assessed a {proba*100:.0f}% probability of impersonation" if model_used else "no trained model was available"
        explanation = f"No rule-based indicators were triggered ({basis}); {model_note}."

    return build_result(
        indicators=indicators, base_score=blended, confidence=confidence,
        engine_name=f"CYBERGUARD Impersonation Engine — {'TF-IDF+LogReg + Domain Lookup' if model_used else 'Rule-Based (model unavailable)'}",
        threat_type=subtopic_title, explanation=explanation,
    )