"""
Friend / Relative / Known Contact Impersonation detector.

Idea: the user maintains their own list of trusted contacts (Settings ->
Known Contacts). When they paste a suspicious message, we check whether the
CLAIMED sender's email actually matches what that contact is known to use,
flag look-alike domains, and flag requests (money, credentials) that
contact's profile says they'd never normally make. This is genuinely
personal to the user — it is not, and cannot be, a generic trained model,
because "is this really my mother" depends on facts only the user has.

On top of that per-contact baseline, we still run the same general
rule-based phishing-language checks used elsewhere (urgency, credential
requests, suspicious links) so a message gets real scrutiny even when no
saved contact matches, or when no contacts have been configured yet.

No ML model here by design — see the docstring above. `db`/`user_id` are
optional so this module (and analyze_url-style detectors that don't need a
database) can still be unit-tested without a database session.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from difflib import SequenceMatcher

from app.detectors import phishing
from app.detectors.base import build_result

PAYMENT_WORDS = (
    "gift card", "gift cards", "wire transfer", "wire the money", "send money", "upi", "bank transfer",
    "account number", "routing number", "western union", "moneygram", "urgent payment", "reimburse",
    "pay this invoice", "purchase order", "cryptocurrency", "bitcoin", "itunes card", "google play card",
)
CREDENTIAL_WORDS = (
    "password", "otp", "one-time code", "verification code", "pin number", "login details",
    "verify your credentials", "confirm your identity", "security question", "reset your password",
)


def _string_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _domain_of(email: str) -> str:
    return email.strip().lower().rsplit("@", 1)[-1] if "@" in email else ""


def _contains_any(text: str, words: tuple[str, ...]) -> list[str]:
    low = text.lower()
    return [w for w in words if w in low]


def _find_contact(db, user_id: str, claimed_name: str):
    """Exact (case-insensitive) match first, then a fuzzy fallback for minor typos."""
    from app.db.models import KnownContact  # local import: keeps this module DB-optional

    if not claimed_name.strip():
        return None
    contacts = db.query(KnownContact).filter(KnownContact.user_id == user_id).all()
    name_lower = claimed_name.strip().lower()
    for c in contacts:
        if c.display_name.strip().lower() == name_lower:
            return c
    best, best_score = None, 0.0
    for c in contacts:
        score = _string_similarity(c.display_name, claimed_name)
        if score > best_score:
            best, best_score = c, score
    return best if best_score >= 0.72 else None


def _ind(triggered: bool, label: str, description: str, severity: str, weight: int) -> dict:
    return {"id": f"IND_{uuid.uuid4().hex[:12]}", "label": label, "description": description,
            "severity": severity, "weight": weight, "triggered": bool(triggered)}


def analyze_known_contact_message(
    text: str,
    extra_field_values: dict,
    subtopic_title: str,
    *,
    db=None,
    user_id: str | None = None,
) -> dict:
    text = text or ""
    claimed_name = (extra_field_values or {}).get("claimedSenderName", "").strip()
    sender_email = (extra_field_values or {}).get("senderEmail", "").strip().lower()
    timestamp_raw = (extra_field_values or {}).get("messageTime", "").strip()

    indicators: list[dict] = []
    has_contacts_configured = False
    contact = None

    if db is not None and user_id is not None:
        from app.db.models import KnownContact
        has_contacts_configured = db.query(KnownContact).filter(KnownContact.user_id == user_id).first() is not None
        if claimed_name:
            contact = _find_contact(db, user_id, claimed_name)

    if claimed_name and contact is None:
        indicators.append(_ind(
            True, "Sender not in your saved contacts",
            (f"'{claimed_name}' does not match anyone in your saved contacts list."
             if has_contacts_configured else
             "You haven't saved any trusted contacts yet, so this claim can't be verified against a baseline. "
             "Add contacts in Settings -> Known Contacts for personalized checks."),
            "medium" if has_contacts_configured else "low",
            18 if has_contacts_configured else 4,
        ))
    elif contact is not None:
        official_domain = (contact.authorized_domain or _domain_of(contact.authorized_email)).strip().lower()
        actual_domain = _domain_of(sender_email)
        if sender_email and official_domain and actual_domain != official_domain:
            similarity = _string_similarity(actual_domain, official_domain)
            if similarity >= 0.6:
                indicators.append(_ind(
                    True, "Look-alike domain spoofing",
                    f"'{actual_domain}' closely mimics {contact.display_name}'s real domain "
                    f"'{official_domain}' ({similarity:.0%} similar) — a classic spoofing technique.",
                    "critical", 45,
                ))
            else:
                indicators.append(_ind(
                    True, "Unauthorized sending domain",
                    f"'{actual_domain}' does not match {contact.display_name}'s known domain '{official_domain}' at all.",
                    "high", 35,
                ))
        elif not sender_email:
            indicators.append(_ind(
                True, "No sender email provided to verify",
                f"You named '{contact.display_name}' but didn't paste their email/handle, so the domain can't be checked.",
                "low", 5,
            ))

        if timestamp_raw:
            try:
                hour = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00")).hour
            except ValueError:
                hour = None
            if hour is not None and not (contact.typical_hours_start <= hour <= contact.typical_hours_end):
                indicators.append(_ind(
                    True, "Message sent outside this contact's usual hours",
                    f"Received at {hour:02d}:00, outside {contact.display_name}'s typical "
                    f"{contact.typical_hours_start:02d}:00-{contact.typical_hours_end:02d}:00 window.",
                    "low", 8,
                ))

        payment_hits = _contains_any(text, PAYMENT_WORDS)
        if payment_hits and not contact.high_risk_requests_allowed:
            indicators.append(_ind(
                True, "Uncharacteristic payment request",
                f"{contact.display_name}'s profile doesn't allow payment requests, but this message mentions: "
                + ", ".join(payment_hits[:3]) + ".",
                "critical", 40,
            ))
        cred_hits = _contains_any(text, CREDENTIAL_WORDS)
        if cred_hits and not contact.high_risk_requests_allowed:
            indicators.append(_ind(
                True, "Uncharacteristic credential request",
                f"{contact.display_name}'s profile doesn't allow credential requests, but this message mentions: "
                + ", ".join(cred_hits[:3]) + ".",
                "critical", 40,
            ))

    # General phishing-language checks always run, regardless of whether a
    # saved contact matched — a compromised real account can still send a
    # scripted phishing message, and a first-time user has no baseline yet.
    if text.strip():
        general = phishing._rule_indicators(text, sender=sender_email or None, reply_to=None)
        indicators.extend({**i, "id": f"IND_{uuid.uuid4().hex[:12]}"} for i in general)

    score = min(100, sum(i["weight"] for i in indicators if i["triggered"]))
    triggered = [i for i in indicators if i["triggered"]]
    confidence = 55 + min(score, 40) if (contact is not None or claimed_name) else 40

    if contact is not None:
        basis = f"checked against your saved contact '{contact.display_name}'"
    elif claimed_name:
        basis = f"'{claimed_name}' is not a contact you've saved, so only general language checks were applied"
    else:
        basis = "no claimed sender name was given, so only general language checks were applied"

    explanation = (
        f"{len(triggered)} indicator(s) triggered ({basis})." if triggered
        else f"No indicators were triggered ({basis})."
    )

    return build_result(
        indicators=indicators, base_score=score, confidence=confidence,
        engine_name="CYBERGUARD Impersonation Engine — Known Contact Baseline",
        threat_type=subtopic_title, explanation=explanation,
    )