"""
Step 4b - Account-takeover signals from email (feeds the Credential Theft &
Account Takeover module).

Two kinds of evidence arrive by email:

1. GENUINE security notifications ("new sign-in", "password changed",
   "2-step verification turned off", "forwarding address added", ...).
   If the email is authenticated (DMARC/DKIM pass from the provider's real
   domain), the event really happened on the user's account. If the user did
   not do it, the account is being taken over. These are NOT phishing.

2. FAKE security notifications. The same wording, but unauthenticated or
   from a look-alike domain. Those are phishing and are scored by the other
   detectors; here they are only labelled so they are not mistaken for (1).

Signals are mapped onto the same field names account_takeover.analyze_event()
already understands (newDevice, passwordResetRecent, mfaChanged, ...), so the
existing engine scores them, with the email-specific extras added on top.
"""
import re
import uuid

from app.detectors.base import build_result
from app.email_pipeline import org_directory as orgs
from app.email_pipeline.schemas import EmailEvent

SECURITY_SENDERS = {
    "google.com", "accounts.google.com", "microsoft.com", "accountprotection.microsoft.com", "live.com",
    "apple.com", "id.apple.com", "facebookmail.com", "instagram.com", "mail.instagram.com", "linkedin.com",
    "github.com", "amazon.com", "amazon.in", "paypal.com", "x.com", "twitter.com", "dropbox.com",
    "slack.com", "zoom.us", "hdfcbank.net", "hdfcbank.com", "icicibank.com", "sbi.co.in", "axisbank.com",
    "paytm.com", "phonepe.com", "netflix.com", "flipkart.com",
}

PATTERNS = {
    "new_signin": re.compile(r"new sign[- ]?in|new login|signed in (?:on|from) a new|login from a new device|"
                             r"new device (?:signed|logged)|unrecognized (?:device|sign|login)|was this you", re.I),
    "password_changed": re.compile(r"password (?:was |has been )?(?:changed|reset|updated)|"
                                   r"your password changed|reset your password", re.I),
    "mfa_changed": re.compile(r"2-step verification (?:was |has been )?(?:turned off|disabled)|two[- ]factor .*disabled|"
                              r"(?:mfa|authenticator|security key|backup codes?) (?:was |were )?(?:removed|changed|added)|"
                              r"phone number (?:was |has been )?(?:changed|removed)", re.I),
    "recovery_changed": re.compile(r"recovery (?:email|phone)(?: address)? (?:was |has been )?(?:changed|added|removed)", re.I),
    "forwarding_rule": re.compile(r"forwarding address|(?:mail|email) forwarding (?:was |has been )?(?:enabled|added)|"
                                  r"new (?:inbox|mail) rule|filter (?:was )?created", re.I),
    "failed_attempts": re.compile(r"(?:multiple|several|\d+) (?:failed|unsuccessful) (?:sign[- ]?in|login) attempts?|"
                                  r"someone (?:tried|attempted) to (?:sign|log) in|blocked a sign[- ]?in attempt", re.I),
    "unusual_location": re.compile(r"unusual (?:sign[- ]?in|location|activity)|from (?:a )?new location|"
                                   r"sign[- ]?in from [A-Z][a-z]+", re.I),
    "otp_requested": re.compile(r"(?:one[- ]time password|otp|verification code)\b.*(?:requested|for (?:login|sign))", re.I),
}
VPN_TOR = re.compile(r"\btor\b|anonymi[sz]ing|vpn|proxy", re.I)
TIME_RE = re.compile(r"\b(0?[0-4]):[0-5]\d\s*(?:am)?\b", re.I)


def _ind(triggered, label, description, severity, weight, mitre=None):
    return {"id": f"IND_{uuid.uuid4().hex[:12]}", "label": label, "description": description,
            "severity": severity, "weight": weight, "triggered": bool(triggered),
            "source": "account-takeover", "mitre": mitre}


def _is_genuine_provider(ev: EmailEvent) -> bool:
    reg = orgs.registered(ev.from_domain)
    from_known = ev.from_domain in SECURITY_SENDERS or reg in SECURITY_SENDERS
    a = ev.auth or {}
    authenticated = a.get("dmarc") == "pass" or a.get("dkim_aligned")
    return bool(from_known and authenticated)


def detect(ev: EmailEvent) -> dict:
    text = f"{ev.subject}\n{ev.body_text[:3000]}"
    hits = {k: bool(rx.search(text)) for k, rx in PATTERNS.items()}
    is_security_mail = any(hits.values())
    genuine = is_security_mail and _is_genuine_provider(ev)

    result_base = {"is_security_notification": is_security_mail, "genuine_provider": genuine, "signals": hits}
    if not is_security_mail:
        r = build_result(indicators=[], base_score=0, confidence=0,
                         engine_name="CYBERGUARD ATO Email Signals", threat_type="Account Takeover",
                         explanation="Not an account-security notification.")
        return r | result_base

    if not genuine:
        # Looks like a security alert but can't be proven to come from the provider:
        # that is a phishing lure. Other detectors score it; we just label it.
        r = build_result(indicators=[_ind(True, "Unverified security alert",
                                          "Looks like an account-security notification but is not authenticated as "
                                          "coming from the real provider — a common phishing lure.",
                                          "high", 15, "T1566")],
                         base_score=15, confidence=60, engine_name="CYBERGUARD ATO Email Signals",
                         threat_type="Fake Security Alert",
                         explanation="Security-alert wording from an unverified sender: treat as phishing, not as a real account event.")
        return r | result_base

    # Genuine notification -> real event on the user's account.
    fields = {
        "newDevice": hits["new_signin"],
        "passwordResetRecent": hits["password_changed"],
        "mfaChanged": hits["mfa_changed"],
        "failedAttempts": 6 if hits["failed_attempts"] else 0,
        "anonymizingNetwork": bool(VPN_TOR.search(text)),
        "unusualHour": bool(TIME_RE.search(text)),
        "impossibleTravel": False,
    }
    from app.detectors import account_takeover
    base = account_takeover.analyze_event(fields, "Account Takeover (from security notification)")

    extra = [
        _ind(hits["forwarding_rule"], "Mail forwarding / inbox rule created",
             "A forwarding address or inbox rule was added. Attackers use this to silently copy all your mail.",
             "critical", 30, "T1114.003"),
        _ind(hits["recovery_changed"], "Recovery email/phone changed",
             "Recovery details changed — lets an attacker lock you out permanently.", "critical", 25, "T1098"),
        _ind(hits["unusual_location"], "Sign-in from unusual location",
             "The provider itself flagged the location as unusual.", "high", 15, "T1078"),
    ]
    indicators = [dict(i, source="account-takeover") for i in base["indicators"]] + extra
    score = min(100, base["riskScore"] + sum(i["weight"] for i in extra if i["triggered"]))
    # A combination that SOCs treat as account compromise in progress:
    if (hits["password_changed"] or hits["mfa_changed"] or hits["recovery_changed"]) and (hits["new_signin"] or hits["unusual_location"]):
        score = max(score, 80)
    if hits["forwarding_rule"]:
        score = max(score, 75)

    triggered = [i["label"].lower() for i in indicators if i["triggered"]]
    explanation = (f"Genuine security notification from {ev.from_domain} reports: {', '.join(triggered[:4]) or 'account activity'}. "
                   "If you did not do this, the account may be compromised — change the password and review sessions now.")
    r = build_result(indicators=indicators, base_score=score, confidence=85,
                     engine_name="CYBERGUARD ATO Email Signals + Account Takeover Engine",
                     threat_type="Possible Account Takeover", explanation=explanation,
                     extra_recommendations=[
                         "Confirm with the account owner whether they performed this action.",
                         "If not: reset the password, sign out all sessions, re-enable MFA, remove unknown forwarding rules.",
                     ])
    return r | result_base
