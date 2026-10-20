"""
Teacher / University Authority Impersonation detector.

Data source: app/ml/models/teacher_university_impersonation.joblib (TRAINED)
  TF-IDF + Logistic Regression, retrained by retrain_impersonation_real.py on the original template
  examples PLUS real genuine and real scam SMS and emails about exams, fees, admissions, scholarships,
  colleges and universities (phishing_sms_clean_v2.tsv + phishing_email_real.tsv). Tested on a held-out
  20% of real messages it never saw: 51% of real scams caught, 0.5% false alarms on genuine
  university messages. When the model says "scam" (>= 50%), the score is at least 51 ("suspicious").
  Auto-reloads on change.

No static domain reference list here, unlike Financial Institution or Brand:
there is no feasible fixed list of "real university domains" (there are
thousands worldwide, and this project has no way to maintain one). Instead,
the person can optionally enter THEIR OWN institution's domain
(extra field "institutionDomain") for a personal check against the sender's
email — the same idea as Known Contacts, just for one fact instead of a full
contact profile.
"""
from __future__ import annotations

import os
import uuid

import joblib

from app.detectors import phishing
from app.detectors.base import build_result

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "..", "ml", "models", "teacher_university_impersonation.joblib")

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


def analyze_teacher_university_impersonation(text: str, extra_field_values: dict, subtopic_title: str) -> dict:
    text = text or ""
    sender_email = (extra_field_values or {}).get("senderEmail", "").strip().lower()
    my_institution_domain = (extra_field_values or {}).get("institutionDomain", "").strip().lower()
    indicators: list[dict] = []

    if my_institution_domain:
        actual_domain = _domain_of(sender_email)
        if sender_email and actual_domain != my_institution_domain:
            indicators.append(_ind(
                True, "Sender domain does not match your institution",
                f"You said your institution's domain is '{my_institution_domain}', but this message came "
                f"from '{actual_domain}'.",
                "critical", 40,
            ))
        elif not sender_email:
            indicators.append(_ind(
                True, "No sender email given to verify",
                f"You gave your institution's domain ('{my_institution_domain}') but no sender email to check it against.",
                "low", 5,
            ))

    general = phishing._rule_indicators(text, sender=sender_email or None, reply_to=None) if text.strip() else []
    indicators.extend(general)
    pattern_inds, pattern_floor = phishing.scam_patterns(text, "teacher") if text.strip() else ([], 0)
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