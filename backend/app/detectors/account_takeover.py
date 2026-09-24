"""
Real, deterministic rule engine for credential theft / account takeover
signals. Operates on structured event fields supplied by the caller
(login location, device, failed attempts, etc). No randomness.
"""
import uuid
from app.detectors.base import build_result


def analyze_event(fields: dict, subtopic_title: str = "Credential Theft & Account Takeover") -> dict:
    def gi(key, default=0):
        try:
            return int(fields.get(key, default) or default)
        except (ValueError, TypeError):
            return default

    def gb(key):
        v = fields.get(key)
        return str(v).strip().lower() in ("1", "true", "yes", "y")

    def gs(key, default=""):
        return str(fields.get(key, default) or default).strip()

    failed_attempts = gi("failedAttempts", 0)
    impossible_travel = gb("impossibleTravel")
    new_device = gb("newDevice")
    anonymizing_network = gb("anonymizingNetwork")
    password_reset_recent = gb("passwordResetRecent")
    mfa_changed = gb("mfaChanged")
    privilege_escalation = gb("privilegeEscalation")
    unusual_hour = gb("unusualHour")

    indicators = []

    def add(triggered, label, desc, severity, weight):
        indicators.append({"label": label, "description": desc, "severity": severity, "weight": weight, "triggered": bool(triggered), "id": f"IND_{uuid.uuid4().hex[:12]}"})

    add(failed_attempts >= 5, "Multiple failed login attempts",
        f"{failed_attempts} failed authentication attempt(s) recorded in this session window.",
        "high", 18)
    add(impossible_travel, "Impossible travel detected",
        "Login locations are geographically implausible within the elapsed time.", "critical", 24)
    add(new_device, "Unrecognized device fingerprint",
        "This device signature does not match any previously trusted device.", "high", 18)
    add(anonymizing_network, "Login from anonymizing network",
        "Connection originates from a known VPN/proxy/Tor exit node.", "medium", 10)
    add(password_reset_recent, "Recent password reset activity",
        "A password reset occurred shortly before or after this event.", "medium", 12)
    add(mfa_changed, "MFA configuration changed",
        "Multi-factor authentication settings were modified around this event — common in takeover attempts.",
        "critical", 20)
    add(privilege_escalation, "Sudden privilege escalation",
        "Account permissions changed shortly after a suspicious login.", "critical", 20)
    add(unusual_hour, "Unusual login hour",
        "Login occurred well outside this account's established activity pattern.", "low", 8)
    add(failed_attempts >= 15, "Password spray / brute-force pattern",
        "Failed attempt volume is consistent with an automated brute-force or spray attack.", "critical", 22)

    score = sum(i["weight"] for i in indicators if i["triggered"])
    triggered = [i for i in indicators if i["triggered"]]
    confidence = 55 + min(len(triggered) * 6, 35)

    if not any([failed_attempts, impossible_travel, new_device, anonymizing_network,
                password_reset_recent, mfa_changed, privilege_escalation, unusual_hour]):
        explanation = "No account-security event fields were supplied, or none indicated risk. Provide login/session signals for a meaningful assessment."
        confidence = 20
    elif triggered:
        top = sorted(triggered, key=lambda i: -i["weight"])[:3]
        names = ", ".join(i["label"].lower() for i in top)
        explanation = f"Event-based risk engine flagged {len(triggered)} signal(s), most notably: {names}."
    else:
        explanation = "Supplied login/session signals fall within expected baseline behavior for this account."

    return build_result(
        indicators=indicators, base_score=score, confidence=confidence,
        engine_name="CYBERGUARD Account Takeover Risk Engine — Rule-Based",
        threat_type=subtopic_title, explanation=explanation,
    )
