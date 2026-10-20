"""
Senior Management Impersonation (CEO fraud / Business Email Compromise) detector.

Data source: app/ml/models/senior_management_impersonation.joblib (TRAINED)
  TF-IDF + Logistic Regression, retrained by retrain_impersonation_real.py on the original template
  examples PLUS real genuine and real scam SMS and emails about managers, CEOs, payroll, invoices,
  wire transfers and gift cards (phishing_sms_clean_v2.tsv + phishing_email_real.tsv). Tested on a
  held-out 20% of real messages it never saw: 85% of real scams caught, 0% false alarms.
  When the model says "scam" (>= 50%), the score is at least 51 ("suspicious"). Auto-reloads on change.

No static domain reference list, same reasoning as Teacher/University: "my
company's real domain" is personal to the user, not a small public list like
banks or consumer brands. The person can optionally give it via the
"companyDomain" extra field for a check against the sender's email.
"""
from __future__ import annotations

import os
import uuid

import joblib

from app.detectors import phishing
from app.detectors.base import build_result

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "..", "ml", "models", "senior_management_impersonation.joblib")

_model_cache: tuple[float, object] | None = None


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


def _domain_of(email: str) -> str:
    return email.strip().lower().rsplit("@", 1)[-1] if "@" in email else ""


def _ind(triggered: bool, label: str, description: str, severity: str, weight: int) -> dict:
    return {"id": f"IND_{uuid.uuid4().hex[:12]}", "label": label, "description": description,
            "severity": severity, "weight": weight, "triggered": bool(triggered)}


def analyze_senior_management_impersonation(text: str, extra_field_values: dict, subtopic_title: str) -> dict:
    text = text or ""
    sender_email = (extra_field_values or {}).get("senderEmail", "").strip().lower()
    my_company_domain = (extra_field_values or {}).get("companyDomain", "").strip().lower()
    indicators: list[dict] = []

    if my_company_domain:
        actual_domain = _domain_of(sender_email)
        if sender_email and actual_domain != my_company_domain:
            indicators.append(_ind(
                True, "Sender domain does not match your company",
                f"You said your company's domain is '{my_company_domain}', but this message came from "
                f"'{actual_domain}' — a classic sign the 'executive' is really an outside attacker.",
                "critical", 40,
            ))
        elif not sender_email:
            indicators.append(_ind(
                True, "No sender email given to verify",
                f"You gave your company's domain ('{my_company_domain}') but no sender email to check it against.",
                "low", 5,
            ))

    general = phishing._rule_indicators(text, sender=sender_email or None, reply_to=None) if text.strip() else []
    indicators.extend(general)
    pattern_inds, pattern_floor = phishing.scam_patterns(text, "management") if text.strip() else ([], 0)
    indicators.extend(pattern_inds)

    rule_score = sum(i["weight"] for i in indicators if i["triggered"])
    model = _get_model()
    model_used = model is not None and bool(text.strip())
    proba = None
    if model_used:
        try:
            proba = float(model.predict_proba([text])[0][1])
            blended = 0.65 * (proba * 100) + 0.35 * min(rule_score, 100)
            if proba >= 0.5:      # the model's own verdict is "scam": at least "suspicious", up to 91 when certain
                blended = max(blended, 51 + 40 * (proba - 0.5) / 0.5)
            confidence = 60 + abs(proba - 0.5) * 60
        except Exception:
            model_used = False
            blended = min(rule_score, 100)
            confidence = 40 + min(rule_score, 50)
    else:
        blended = min(rule_score, 100)
        confidence = 40 + min(rule_score, 50)

    if pattern_floor:
        blended = max(blended, pattern_floor)
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
        engine_name=f"CYBERGUARD Impersonation Engine — {'TF-IDF+LogReg (real SMS + email trained)' if model_used else 'Rule-Based (model unavailable)'}",
        threat_type=subtopic_title, explanation=explanation,
    )