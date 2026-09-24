"""
Real phishing/scam text detector: combines a trained TF-IDF + Logistic
Regression model with deterministic rule-based indicators extracted from
the ACTUAL submitted text (not random). If the trained model file is
missing, the detector still runs on rules alone and reports the model as
unavailable rather than fabricating a confidence score.

Each phishing subtopic (email / SMS / social media) can have its own
independently-trained model file — see MODEL_FILES below. Subtopics not
listed fall back to the shared DEFAULT_MODEL_FILE.
"""
import os
import re
import uuid
import joblib

from app.core.config import get_settings
from app.detectors.base import build_result

settings = get_settings()

# subtopic_id -> model filename (relative to settings.MODELS_DIR).
# Train each with: python -m app.ml.training.train_phishing --data <file> --out <filename> --pos-label <label>
MODEL_FILES = {
    "email-analysis": "phishing_email.joblib",
    "sms-analysis": "phishing_sms.joblib",
    "social-media-analysis": "phishing_social.joblib",
}
DEFAULT_MODEL_FILE = "phishing_pipeline.joblib"

_model_cache: dict[str, tuple[float, object]] = {}  # filename -> (mtime, model)


def _get_model(subtopic_id: str | None):
    """
    Loads the model for a subtopic, auto-reloading it if the .joblib file
    on disk has changed since it was last cached (so a freshly retrained
    model is picked up without needing to restart the backend). If the
    file is missing, unreadable, or fails to load, returns None — the
    caller falls back to rule-based-only scoring rather than crashing.
    """
    filename = MODEL_FILES.get(subtopic_id or "", DEFAULT_MODEL_FILE)
    path = os.path.join(settings.MODELS_DIR, filename)

    if not os.path.exists(path):
        _model_cache.pop(filename, None)
        return None

    mtime = os.path.getmtime(path)
    cached = _model_cache.get(filename)
    if cached and cached[0] == mtime:
        return cached[1]

    try:
        model = joblib.load(path)
    except Exception:
        model = None
    _model_cache[filename] = (mtime, model)
    return model


URGENCY_WORDS = [
    "urgent", "immediately", "act now", "verify your account", "suspended",
    "expire", "act fast", "limited time", "final notice", "click here now",
    "action required", "your account will be locked", "unusual activity",
    "confirm your identity", "response required", "within 24 hours",
    "avoid suspension", "restricted access", "security alert",
]
CREDENTIAL_WORDS = [
    "password", "otp", "one-time code", "one-time password", "pin", "cvv",
    "login credentials", "ssn", "social security", "security question",
    "date of birth", "account number", "routing number", "card number",
]
MONEY_WORDS = [
    "wire transfer", "gift card", "bitcoin", "crypto", "claim your prize",
    "you have won", "lottery", "refund", "tax rebate", "unclaimed funds",
    "inheritance", "cashapp", "venmo", "western union", "processing fee",
]
KNOWN_BRANDS = [
    "paypal", "microsoft", "amazon", "apple", "bank", "google", "netflix",
    "facebook", "instagram", "linkedin", "irs", "fedex", "ups", "dhl",
    "chase", "wells fargo", "hdfc", "sbi", "icici",
]
LINK_RE = re.compile(r"https?://\S+|www\.\S+")
GENERIC_GREETING_RE = re.compile(r"^\s*(dear (customer|user|member|sir/madam)|hello,)", re.I)
MISSPELLINGS = ["verifiy", "recieve", "acount", "securty", "confimation", "immediatly", "informations", "kindly", "beneficery"]


def _rule_indicators(text: str, sender: str | None, reply_to: str | None = None) -> list[dict]:
    lower = text.lower()
    indicators = []

    def add(triggered, label, desc, severity, weight):
        indicators.append({"label": label, "description": desc, "severity": severity, "weight": weight, "triggered": bool(triggered)})

    urgency_hit = any(w in lower for w in URGENCY_WORDS)
    add(urgency_hit, "Urgency language detected",
        "Message pressures the recipient to act immediately ('act now', 'account will be suspended').",
        "high", 18)

    cred_hit = any(w in lower for w in CREDENTIAL_WORDS)
    add(cred_hit, "Credential request",
        "Content asks the recipient for a password, OTP, PIN, or similar sensitive credential.",
        "critical", 25)

    links = LINK_RE.findall(text)
    add(len(links) > 0, "Suspicious embedded link",
        f"Message contains {len(links)} embedded link(s); verify destination before clicking.",
        "high", 20 if links else 0)

    money_hit = any(w in lower for w in MONEY_WORDS)
    add(money_hit, "Financial lure / prize claim",
        "References unexpected money, gift cards, cryptocurrency, or prize claims — a classic scam lure.",
        "critical", 22)

    generic_greeting = bool(GENERIC_GREETING_RE.search(text))
    add(generic_greeting, "Generic greeting",
        "Message lacks personalization typical of legitimate correspondence.", "low", 5)

    sender_lower = (sender or "").lower()
    domain_mismatch = bool(sender) and any(
        brand in text.lower() and brand not in sender_lower for brand in KNOWN_BRANDS
    )
    add(domain_mismatch, "Sender domain mismatch",
        "The claimed brand in the message body does not match the sender's domain.",
        "high", 20)

    misspelling_markers = sum(lower.count(m) for m in MISSPELLINGS)
    add(misspelling_markers > 0, "Spelling anomalies",
        "Contains spelling inconsistencies typical of templated scam content.", "low", 6)

    # Reply-To pointing somewhere different from the From address is a
    # classic BEC/phishing tell — legitimate mail rarely does this.
    reply_to_mismatch = False
    if reply_to and sender:
        reply_domain = reply_to.split("@")[-1].lower()
        sender_domain = sender.split("@")[-1].lower()
        reply_to_mismatch = bool(reply_domain) and bool(sender_domain) and reply_domain != sender_domain
    add(reply_to_mismatch, "Reply-To domain mismatch",
        f"Replies are routed to a different domain ({reply_to}) than the sender ({sender}) — common in spoofed mail.",
        "critical", 22)

    return indicators


def _link_destination_indicator(text: str, subtopic_id: str | None) -> dict | None:
    """
    Real integration: run the actual malicious-URL detector against links
    found in the email body, and fold the worst result into this scan.
    Checks at most 3 links to keep scan time bounded.
    """
    links = LINK_RE.findall(text)[:3]
    if not links:
        return None
    from app.detectors import malicious_url  # local import avoids a module-load cycle
    worst_score, worst_url = 0, None
    for link in links:
        try:
            result = malicious_url.analyze_url(link, "Embedded link check", subtopic_id=subtopic_id)
            if result["riskScore"] > worst_score:
                worst_score, worst_url = result["riskScore"], link
        except Exception:
            continue
    if worst_url is None:
        return None
    return {
        "label": "Malicious link destination", "severity": "critical" if worst_score >= 70 else "high",
        "description": f"An embedded link ({worst_url}) scored {worst_score}/100 for malicious characteristics when analyzed directly.",
        "weight": min(30, round(worst_score * 0.35)), "triggered": worst_score >= 40,
    }


def analyze_text(text: str, sender: str | None = None, subtopic_title: str = "Phishing Detection",
                  subtopic_id: str | None = None, reply_to: str | None = None) -> dict:
    text = (text or "").strip()
    rule_indicators = _rule_indicators(text, sender, reply_to)

    link_indicator = _link_destination_indicator(text, subtopic_id) if text else None
    if link_indicator:
        rule_indicators.append(link_indicator)

    rule_score = sum(i["weight"] for i in rule_indicators if i["triggered"])

    model = _get_model(subtopic_id)
    model_used = model is not None and bool(text)
    proba = None
    if model_used:
        try:
            proba = float(model.predict_proba([text])[0][1])  # P(phishing/spam)
            model_score = proba * 100
            # Blend: model carries more weight when the text is long enough
            # to be meaningfully vectorized; rules always contribute explainability.
            blended = 0.6 * model_score + 0.4 * min(rule_score, 100)
            confidence = 65 + abs(proba - 0.5) * 60  # more confident away from 0.5
        except Exception:
            # A corrupt, incompatible, or otherwise broken model file must
            # never crash a scan — fall back to rule-based-only scoring,
            # same as if no model were configured at all.
            model_used = False
            blended = min(rule_score, 100)
            confidence = 40 + min(rule_score, 50)
    else:
        blended = min(rule_score, 100)
        confidence = 40 + min(rule_score, 50)  # lower confidence without ML backing

    triggered = [i for i in rule_indicators if i["triggered"]]
    if not text:
        explanation = "No content was submitted to analyze."
        blended = 0
        confidence = 0
    elif not triggered and not model_used:
        explanation = "No rule-based phishing indicators were detected in the submitted text, and no trained model was available to provide a second opinion."
    elif not triggered:
        explanation = f"The trained classifier assessed this content as {'likely phishing/scam' if model.predict([text])[0] == 1 else 'likely legitimate'} (model confidence {confidence:.0f}%). No rule-based indicators were additionally triggered."
    else:
        top = sorted(triggered, key=lambda i: -i["weight"])[:3]
        names = ", ".join(i["label"].lower() for i in top)
        model_note = f" A trained classifier corroborated this with a phishing probability of {proba*100:.0f}%." if model_used else " (Trained model unavailable — indicators are rule-based only.)"
        explanation = f"Detected {len(triggered)} indicator(s), most notably: {names}.{model_note}"

    for ind in rule_indicators:
        ind["id"] = f"IND_{uuid.uuid4().hex[:12]}"

    return build_result(
        indicators=rule_indicators,
        base_score=blended,
        confidence=confidence,
        engine_name=f"CYBERGUARD Phishing Engine — {'TF-IDF+LogReg' if model_used else 'Rule-Based (model unavailable)'}",
        threat_type=subtopic_title,
        explanation=explanation,
    )