"""
Organization / Brand Impersonation detector.

Two data sources, both auto-reloading on change (no restart needed):

  1. app/ml/models/brand_impersonation.joblib  (TRAINED)
     TF-IDF + Logistic Regression, trained on BRAND-MASKED text (see
     brand_text.py) so it learns manipulative language, not "which brand is
     named" — an earlier unmasked version flagged "watching netflix tonight"
     as phishing. Trained via train_brand_impersonation.py, which only saves
     a model that passes a hand-written trap-set check.

  2. BRAND_DOMAINS in app/detectors/url_features_v2.py  (FETCHED / reference)
     The same real brand-domain list already used by the QR/URL detectors —
     reused here rather than duplicated, so there's one source of truth.

If the model file is missing, falls back to rule-based-only scoring.
"""
from __future__ import annotations

import os
import re
import uuid

import joblib

from app.detectors import phishing
from app.detectors.base import build_result
from app.detectors.brand_text import find_brands, mask_brands
from app.detectors.url_features_v2 import BRAND_DOMAINS

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "..", "ml", "models", "brand_impersonation.joblib")

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


def _is_brand_domain(domain: str, real_domains) -> bool:
    """netflix.com and its subdomains (account.netflix.com, mailer.netflix.com) are the brand's own."""
    return bool(domain) and any(domain == d or domain.endswith("." + d) for d in real_domains)


def _ind(triggered: bool, label: str, description: str, severity: str, weight: int) -> dict:
    return {"id": f"IND_{uuid.uuid4().hex[:12]}", "label": label, "description": description,
            "severity": severity, "weight": weight, "triggered": bool(triggered)}


# The two most common brand scams: "your account/parcel is on hold" + "pay a small fee / update your card".
_HOLD_RE = re.compile(r"\b(?:on hold|held|suspended|suspend|unpaid|outstanding fee|customs|re-?delivery|"
                      r"could not be delivered|failed delivery|payment (?:failed|declined)|expired)\b", re.I)
_PAY_DEMAND_RE = re.compile(r"\b(?:pay(?: now| the)?|fee|charge|update (?:your |ur |yr )?(?:card|payment|billing)|"
                            r"card details|billing details|payment details)\b", re.I)


def analyze_brand_impersonation(text: str, extra_field_values: dict, subtopic_title: str) -> dict:
    text = text or ""
    sender_email = (extra_field_values or {}).get("senderEmail", "").strip().lower()
    indicators: list[dict] = []

    claimed_brands = find_brands(text)
    actual_domain = _domain_of(sender_email)
    if claimed_brands:
        claimed = claimed_brands[0]  # first-mentioned brand is treated as the claimed identity
        real_domains = {d.lower() for d in BRAND_DOMAINS.get(claimed, set())}
        if sender_email and real_domains and not _is_brand_domain(actual_domain, real_domains):
            indicators.append(_ind(
                True, "Sender domain does not match the claimed brand",
                f"The message claims to be from {claimed.title()}, but '{actual_domain}' is not one of its "
                f"known real domains ({', '.join(sorted(real_domains))[:80]}).",
                "critical", 45,
            ))
        elif not sender_email:
            indicators.append(_ind(
                True, "No sender email given to verify",
                f"The message claims to be from {claimed.title()}, but no sender email/handle was provided "
                "to check against its real domain.",
                "low", 5,
            ))
        if len(claimed_brands) > 1:
            indicators.append(_ind(
                True, "Multiple brands named in one message",
                f"The message names several different brands ({', '.join(b.title() for b in claimed_brands[:4])}), "
                "unusual for a genuine single-brand communication.",
                "medium", 15,
            ))
    elif sender_email:
        indicators.append(_ind(
            True, "Sender domain not matched to any known brand",
            f"'{actual_domain}' does not match any brand in our reference list (the list may simply be "
            "incomplete — this alone is not proof of anything).",
            "low", 6,
        ))

    sender_verified = bool(claimed_brands and sender_email and _is_brand_domain(
        actual_domain, {d.lower() for d in BRAND_DOMAINS.get(claimed_brands[0], set())}))
    hold_scam = bool(_HOLD_RE.search(text) and _PAY_DEMAND_RE.search(text)) and not sender_verified
    indicators.append(_ind(
        hold_scam, "Account or parcel held until you pay",
        "Says an account or delivery is on hold / unpaid and asks you to pay a fee or update card details -- "
        "the most common brand-impersonation scam. Real companies show this inside their own app or website.",
        "high", 25,
    ))

    general = phishing._rule_indicators(text, sender=sender_email or None, reply_to=None) if text.strip() else []
    indicators.extend(general)
    pattern_inds, pattern_floor = phishing.scam_patterns(text, "brand") if text.strip() else ([], 0)
    indicators.extend(pattern_inds)

    rule_score = sum(i["weight"] for i in indicators if i["triggered"])
    model = _get_model()
    model_used = model is not None and bool(text.strip())
    proba = None
    if model_used:
        try:
            proba = float(model.predict_proba([mask_brands(text)])[0][1])
            blended = 0.6 * (proba * 100) + 0.4 * min(rule_score, 100)
            confidence = 65 + abs(proba - 0.5) * 60
        except Exception:
            model_used = False
            blended = min(rule_score, 100)
            confidence = 40 + min(rule_score, 50)
    else:
        blended = min(rule_score, 100)
        confidence = 40 + min(rule_score, 50)

    # "On hold + pay / update card" from a sender we could not verify as the brand: at least Suspicious.
    if hold_scam and text.strip():
        blended = max(blended, 55)

    if pattern_floor:
        blended = max(blended, pattern_floor)
    for ind in indicators:
        ind.setdefault("id", f"IND_{uuid.uuid4().hex[:12]}")
    triggered = [i for i in indicators if i["triggered"]]

    if claimed_brands:
        basis = f"claimed brand(s): {', '.join(b.title() for b in claimed_brands)}"
    else:
        basis = "no specific brand identified in the text"

    if not text.strip():
        explanation, blended, confidence = "No content was submitted to analyze.", 0, 0
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
        engine_name=f"CYBERGUARD Impersonation Engine — {'TF-IDF+LogReg (brand-masked) + Domain Lookup' if model_used else 'Rule-Based (model unavailable)'}",
        threat_type=subtopic_title, explanation=explanation,
    )