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

On top of both, the SCAM-SCRIPT check recognises the "Hi Mum, new number" script that criminals use
(UK "Hi Mum", India "Hi Papa / beta, new number", hacked-friend OTP requests), stage by stage:
    1. relationship greeting without a name ("Hi Mum", "Hey beta", "it's me")
    2. a story to explain the unknown number (new / temporary number, broken or lost phone, friend's phone)
    3. moving the chat (WhatsApp me, don't call, I'm in class)
    4. the ask: money / UPI / bill / bank details, or the OTP / code that was "sent by mistake"
    5. pressure (urgent, ASAP, I'll pay you back)
A new number + an ask is the scam; a greeting or a new number alone is common in real life, so it only asks
you to verify. The script check was tested on real reported scam messages and 1,400+ real personal SMS
(see tests/test_known_contact_script.py). The general SMS phishing model (trained on 20,000+ real scam SMS)
also reads the message.

`db`/`user_id` are optional so this module can be unit-tested without a database session.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from difflib import SequenceMatcher

from app.detectors import phishing
from app.detectors.base import build_result

# ---- the scam script, stage by stage --------------------------------------------------------------------------
GREETING_RE = re.compile(
    r"^\W*(hi|hey|hello|hii+|helo|dear)\W+(mum|mom|mam|mummy|mama|ma|dad|daddy|papa|pa|mother|father|son|beta|bro|"
    r"brother|sis|sister|aunty|auntie|aunt|uncle|grandma|granny|nan|nana|grandpa)\b|^\W*(hey,? |hi,? )?it'?s me\b|"
    r"\b(this is|it'?s) (your )?(son|daughter|beta|papa|mummy|mum|mom|dad|bro|brother|sis|sister)\b", re.I)
NEW_NUMBER_RE = re.compile(
    r"\b(my (new|other|temporary|temp) (phone |mobile )?(number|no\.?)|new (phone |mobile )?number|temporary number|"
    r"changed my number|changed (from )?provider|delete (my|the) old (number|one)|save (this|my new|my) number|"
    r"(lost|broke|broken|dropped|drop|smashed|damaged|cracked) my (phone|mobile|wallet|purse)|"
    r"(phone|mobile) (is |got |fell )?(broken|dead|damaged|stolen|in (the )?(water|toilet|sink))|"
    r"(texting|messaging|message|writing) (you )?(from|off|on) (a |my )?friends?'?s? (old )?phone|"
    r"using a friends?'?s? (old )?phone|borrowing a friends?'?s? phone)\b", re.I)
MOVE_RE = re.compile(
    r"\b(whats ?app (me|when|as soon)|send (me )?a (message|whatsapp)|text me (on|at|back)|message me (on|at)|"
    r"contact my new|save (it|this)|don'?t call|can'?t (talk|call|speak)|cannot (talk|call)|in (a |the )?(class|meeting|"
    r"exam|lecture)|phones? (is |are )?about to die|no balance)\b", re.I)
MONEY_RE = re.compile(
    r"\b(send (me )?(some )?(money|cash|rs|inr|\d)|transfer|pay (for|the|this|my|me|it)|payment|bill|upi|g ?pay|"
    r"phone ?pe|paytm|bank (details|account)|account (details|number)|lend me|need (some )?(money|cash|rs|\d)|"
    r"(rs\.?|inr|₹|£|\$) ?\d|\d+ ?(rupees|rs|k)\b|pay you back|return (it|the money)|fees?)\b", re.I)
CODE_RE = re.compile(
    r"\b((share|send|forward|tell|text) (me )?(the |that |your )?(otp|code|pin|verification code)|"
    r"(otp|code) (that )?(was )?(sent|came|come) (to you|to your)|sent you an? (otp|code)|"
    r"(otp|code) by mistake|(\d|six|four)[- ]digit (code|otp|number)[^.\n]{0,60}\b(forward|send|share|tell)|"
    r"(forward|send|share) (it|that|the (code|otp|message)) (to me|back)|code (on|to) your (phone|number))\b", re.I)
PRESSURE_RE = re.compile(r"\b(urgent|urgently|asap|right now|immediately|today itself|quick(ly)?|emergency|"
                         r"in trouble|don'?t tell|i promise|pay you back|will return)\b", re.I)

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

    # The "Hi Mum, new number" scam script.
    script_score, script_inds = scam_script(text)
    indicators.extend(script_inds)

    # General phishing-language checks always run, regardless of whether a
    # saved contact matched — a compromised real account can still send a
    # scripted phishing message, and a first-time user has no baseline yet.
    if text.strip():
        general = phishing._rule_indicators(text, sender=sender_email or None, reply_to=None)
        indicators.extend({**i, "id": f"IND_{uuid.uuid4().hex[:12]}"} for i in general)

    rule_score = min(100, sum(i["weight"] for i in indicators if i["triggered"] and not i.get("script")))
    sms_p = _sms_model_probability(text)
    if sms_p is not None and sms_p >= 0.5:
        indicators.append(_ind(True, "SMS scam model: written like a scam message",
                               f"The SMS phishing model (trained on 20,000+ real scam SMS) rates this message "
                               f"{sms_p:.0%} likely a scam.", "high" if sms_p >= 0.8 else "medium", 0))
    model_score = round(70 * sms_p) if sms_p is not None else 0
    pattern_inds, pattern_floor = phishing.scam_patterns(text, "contact") if text.strip() else ([], 0)
    indicators.extend({**i, "id": f"IND_{uuid.uuid4().hex[:12]}"} for i in pattern_inds)
    score = max(rule_score, script_score, model_score, pattern_floor)
    triggered = [i for i in indicators if i["triggered"]]
    confidence = 55 + min(score, 40) if (contact is not None or claimed_name or script_score) else 40

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
    if script_score >= 71:
        explanation = ("This follows the known 'Hi Mum, new number' scam script: " + _script_summary(script_inds)
                       + ". Do not send money or codes - call the person on their OLD number, or ask a question only "
                       "they can answer. " + explanation)
    elif script_score >= 51:
        explanation = ("Part of the 'Hi Mum, new number' scam script is present: " + _script_summary(script_inds)
                       + ". Real people do change numbers - confirm by calling their old number before replying. "
                       + explanation)

    return build_result(
        indicators=indicators, base_score=score, confidence=confidence,
        engine_name="CYBERGUARD Impersonation Engine — Known Contact Baseline + Scam-Script Check + SMS Scam Model",
        threat_type=subtopic_title, explanation=explanation,
    )

def _sms_model_probability(text: str):
    if not text.strip():
        return None
    model = phishing._get_model("sms-analysis")
    if model is None:
        return None
    try:
        return float(model.predict_proba([text])[0][1])
    except Exception:
        return None


SCRIPT_STAGES = (  # key, regex, points, label, description
    ("greeting", GREETING_RE, 15, "Opens like a family member or friend, without a name",
     "Starts with '{m}' - the scam is sent to many people, so it uses a role ('Hi Mum') instead of a name."),
    ("new_number", NEW_NUMBER_RE, 30, "Story to explain an unknown number",
     "'{m}' - a lost/broken phone or 'new number' explains why the message comes from a number you don't know."),
    ("move", MOVE_RE, 10, "Moves the chat / avoids a call",
     "'{m}' - scammers move to WhatsApp and avoid calls, because a call would reveal the voice."),
    ("money", MONEY_RE, 30, "Asks for money or bank details", "'{m}' - the goal of the scam: money, UPI or bank details."),
    ("code", CODE_RE, 45, "Asks for an OTP / verification code",
     "'{m}' - an OTP 'sent by mistake' is used to take over your WhatsApp or bank account. Never share it."),
    ("pressure", PRESSURE_RE, 8, "Pressure or promise", "'{m}' - urgency stops you from checking."),
)


def scam_script(text: str) -> tuple[int, list[dict]]:
    """-> (score 0-100, indicators). A new number + an ask is the scam; parts alone only ask to verify."""
    hits = {}
    for key, rx, *_ in SCRIPT_STAGES:
        m = rx.search(text or "")
        if m:
            hits[key] = m.group(0).strip()
    inds = []
    for key, _rx, pts, label, desc in SCRIPT_STAGES:
        if key in hits:
            inds.append({**_ind(True, label, desc.format(m=hits[key][:60]),
                                "critical" if key == "code" else "high" if key in ("money", "new_number") else "medium",
                                0), "script": key})
    ask = "money" in hits or "code" in hits
    score = sum(p for k, _r, p, *_ in SCRIPT_STAGES if k in hits)
    if "new_number" in hits and ask:
        score = max(score, 80 + 5 * ("greeting" in hits) + 5 * ("move" in hits or "pressure" in hits))
    elif ("greeting" in hits or "new_number" in hits) and ask:
        score = max(score, 55)                         # e.g. a real child asking for money: verify, don't alarm
    elif "new_number" in hits and ("greeting" in hits or "move" in hits):
        score = max(score, 55)                         # the opening message of the scam - verify before replying
    else:
        score = min(score, 45)                         # one part alone happens in real life
    if "code" in hits:
        score = max(score, 75)                         # asking for an OTP / code is never normal
    return min(score, 100), inds


def _script_summary(inds: list[dict]) -> str:
    return ", ".join(i["label"].lower() for i in inds)
