"""
Real, deterministic rule-based detector for digital impersonation /
identity-abuse signals, applied to the actual submitted profile/message
text and metadata (account age, claimed affiliation, etc).
"""
import re
import uuid
from app.detectors.base import build_result

AUTHORITY_WORDS = ["ceo", "director", "government", "irs", "police", "official", "hr department", "legal action"]
SENSITIVE_REQUEST_WORDS = ["wire transfer", "gift card", "bank details", "send money", "confidential", "urgent payment"]
UNVERIFIED_CHANNEL_HINTS = ["whatsapp", "telegram", "personal email", "new number", "different phone"]


def analyze_identity(text: str, extra_fields: dict | None = None, subtopic_title: str = "Digital Impersonation") -> dict:
    text = (text or "").strip()
    extra_fields = extra_fields or {}
    lower = text.lower()

    indicators = []

    def add(triggered, label, desc, severity, weight):
        indicators.append({"label": label, "description": desc, "severity": severity, "weight": weight, "triggered": bool(triggered), "id": f"IND_{uuid.uuid4().hex[:12]}"})

    authority_hit = any(w in lower for w in AUTHORITY_WORDS)
    add(authority_hit, "Authority impersonation language",
        "Message invokes an authority figure or institution to pressure compliance.", "high", 20)

    sensitive_hit = any(w in lower for w in SENSITIVE_REQUEST_WORDS)
    add(sensitive_hit, "Request for sensitive action",
        "Asks for funds transfer, confidential data, or urgent payment.", "critical", 25)

    channel_hit = any(w in lower for w in UNVERIFIED_CHANNEL_HINTS)
    add(channel_hit, "Unverified contact channel",
        "References contacting through a channel not officially registered for this relationship.", "high", 18)

    account_age_days = None
    try:
        account_age_days = int(extra_fields.get("accountAgeDays")) if extra_fields.get("accountAgeDays") else None
    except (ValueError, TypeError):
        account_age_days = None
    recent_profile = account_age_days is not None and account_age_days < 30
    add(recent_profile, "Profile recently created",
        f"Claimed account is only {account_age_days} day(s) old — recently created accounts are disproportionately used for impersonation.",
        "medium", 12)

    urgency_markers = len(re.findall(r"\b(now|immediately|urgent|asap|today only)\b", lower))
    add(urgency_markers >= 2, "High-pressure urgency language",
        "Message repeatedly emphasizes urgency to short-circuit verification.", "medium", 14)

    triggered = [i for i in indicators if i["triggered"]]
    score = sum(i["weight"] for i in indicators if i["triggered"])
    confidence = 50 + min(len(triggered) * 8, 35) if text else 0

    if not text:
        explanation = "No content was submitted to analyze."
    elif triggered:
        top = sorted(triggered, key=lambda i: -i["weight"])[:3]
        names = ", ".join(i["label"].lower() for i in top)
        explanation = f"Detected {len(triggered)} indicator(s) associated with digital impersonation, most notably: {names}."
    else:
        explanation = "No rule-based impersonation indicators were detected in the submitted content."

    return build_result(
        indicators=indicators, base_score=score, confidence=confidence,
        engine_name="CYBERGUARD Impersonation Engine — Rule-Based",
        threat_type=subtopic_title, explanation=explanation,
    )
