"""
One-time codes (OTP) sent by email, for signup and login.

    signup:  name + email  -> code by email -> code correct -> short "signup token" -> create password
    login:   email + password correct -> code by email -> code correct -> logged in

Security choices
  * 6 random digits from `secrets` (not `random`).
  * Only an HMAC of the code is stored (keyed with JWT_SECRET + the challenge id),
    so a database leak does not reveal live codes.
  * The browser only ever holds the challenge id (a long random string), never a user id.
  * A code expires after OTP_TTL_MINUTES, dies after OTP_MAX_ATTEMPTS wrong guesses,
    and "Resend" waits OTP_RESEND_SECONDS, at most OTP_MAX_RESENDS times.
  * Codes are compared in constant time.

Delivery: by email through the SMTP settings in .env. In development, when the email
cannot be sent, the code is printed in the backend window and returned as `devOtp`
so the flow can still be tested. In production a failed send is an error instead.
"""
import hashlib
import hmac
import html
import logging
import secrets
from datetime import datetime, timedelta, timezone

from app.core.config import get_settings
from app.db.models import EmailOTP
from app.services import notifier

logger = logging.getLogger("cyberguard.otp")


class OTPError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _hash(challenge_id: str, code: str) -> str:
    key = get_settings().JWT_SECRET.encode()
    return hmac.new(key, f"{challenge_id}:{code}".encode(), hashlib.sha256).hexdigest()


def _new_code() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def mask_email(email: str) -> str:
    name, _, domain = email.partition("@")
    shown = name[:2] if len(name) > 2 else name[:1]
    return f"{shown}{'*' * max(len(name) - len(shown), 1)}@{domain}"


def _deliver(otp: EmailOTP, code: str) -> dict:
    """Email the code. Returns the fields to add to the API response."""
    s = get_settings()
    action = "create your CYBERGUARD account" if otp.purpose == "signup" else "sign in to CYBERGUARD"
    subject = f"{code} is your CYBERGUARD verification code"
    text = (f"Your CYBERGUARD verification code is: {code}\n\n"
            f"Use it to {action}. It expires in {s.OTP_TTL_MINUTES} minutes.\n\n"
            "If you did not try to do this, ignore this email and do not share the code with anyone. "
            "CYBERGUARD staff will never ask you for it.")
    body = (
        '<div style="font-family:Arial,sans-serif;max-width:480px;color:#111">'
        '<h2 style="margin:0 0 12px;color:#0891b2">CYBERGUARD</h2>'
        f'<p style="margin:0 0 10px">Use this code to {html.escape(action)}:</p>'
        f'<p style="font-size:32px;letter-spacing:8px;font-weight:bold;margin:8px 0 14px">{code}</p>'
        f'<p style="margin:0 0 10px;color:#444">It expires in {s.OTP_TTL_MINUTES} minutes.</p>'
        '<p style="margin:16px 0 0;color:#666;font-size:12px">If you did not try to do this, ignore this email. '
        'Never share this code with anyone &mdash; CYBERGUARD staff will never ask for it.</p></div>'
    )
    result = notifier.send_mail([otp.email], subject, text, body, channel="otp-email")
    extra = {"sentTo": mask_email(otp.email), "delivered": result["status"] == "sent"}
    if result["status"] != "sent":
        if s.is_production:
            raise OTPError("OTP_DELIVERY_FAILED",
                           "We could not send the verification email. Please try again in a moment.", 503)
        # Development only: lets you test the flow while email is not working yet.
        logger.warning("[DEV] OTP for %s (%s): %s  -- email not sent: %s %s",
                       otp.email, otp.purpose, code, result["status"], result.get("error", ""))
        print(f"[DEV] OTP for {otp.email} ({otp.purpose}): {code}")
        extra.update(devOtp=code, deliveryNote=f"Email not sent ({result['status']}). Development mode shows the code here.")
    return extra


def _public(otp: EmailOTP) -> dict:
    s = get_settings()
    return {"challengeId": otp.id, "expiresInSeconds": s.OTP_TTL_MINUTES * 60,
            "resendInSeconds": s.OTP_RESEND_SECONDS}


def start(db, *, purpose: str, email: str, user_id: str | None = None, name: str | None = None,
          remember_me: bool = True) -> dict:
    """Create a challenge, email the code, return what the browser needs."""
    s = get_settings()
    # Only one live challenge per email + purpose: older ones stop working.
    for old in db.query(EmailOTP).filter(EmailOTP.email == email, EmailOTP.purpose == purpose,
                                         EmailOTP.consumed.is_(False)).all():
        old.consumed = True
    code = _new_code()
    otp = EmailOTP(id="OTP_" + secrets.token_urlsafe(24), purpose=purpose, email=email, user_id=user_id,
                   name=name, remember_me=remember_me, attempts=0, resends=0, verified=False, consumed=False,
                   expires_at=_now() + timedelta(minutes=s.OTP_TTL_MINUTES), sent_at=_now())
    otp.code_hash = _hash(otp.id, code)
    db.add(otp)
    db.flush()
    try:
        extra = _deliver(otp, code)
    except OTPError:
        db.rollback()
        raise
    db.commit()
    return {**_public(otp), **extra}


def _live(db, challenge_id: str, purpose: str) -> EmailOTP:
    otp = db.get(EmailOTP, challenge_id or "")
    if otp is None or otp.purpose != purpose or otp.consumed:
        raise OTPError("OTP_INVALID", "This verification request is no longer valid. Please start again.", 400)
    if _aware(otp.expires_at) < _now():
        otp.consumed = True
        db.commit()
        raise OTPError("OTP_EXPIRED", "The code has expired. Request a new one.", 400)
    return otp


def resend(db, challenge_id: str, purpose: str) -> dict:
    s = get_settings()
    otp = _live(db, challenge_id, purpose)
    wait = s.OTP_RESEND_SECONDS - (_now() - _aware(otp.sent_at)).total_seconds()
    if wait > 0:
        raise OTPError("OTP_RESEND_TOO_SOON", f"Please wait {int(wait) + 1} seconds before asking for a new code.", 429)
    if otp.resends >= s.OTP_MAX_RESENDS:
        raise OTPError("OTP_RESEND_LIMIT", "Too many codes requested. Please start again later.", 429)
    code = _new_code()
    otp.code_hash = _hash(otp.id, code)
    otp.resends += 1
    otp.attempts = 0
    otp.sent_at = _now()
    otp.expires_at = _now() + timedelta(minutes=s.OTP_TTL_MINUTES)
    extra = _deliver(otp, code)
    db.commit()
    return {**_public(otp), **extra}


def check(db, challenge_id: str, purpose: str, code: str) -> EmailOTP:
    """Return the challenge if the code is right; otherwise raise. Counts wrong attempts."""
    s = get_settings()
    otp = _live(db, challenge_id, purpose)
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if otp.attempts >= s.OTP_MAX_ATTEMPTS:
        otp.consumed = True
        db.commit()
        raise OTPError("OTP_TOO_MANY_ATTEMPTS", "Too many wrong codes. Please start again.", 429)
    if len(code) != 6 or not hmac.compare_digest(otp.code_hash, _hash(otp.id, code)):
        otp.attempts += 1
        left = s.OTP_MAX_ATTEMPTS - otp.attempts
        if left <= 0:
            otp.consumed = True
        db.commit()
        if left <= 0:
            raise OTPError("OTP_TOO_MANY_ATTEMPTS", "Too many wrong codes. Please start again.", 429)
        raise OTPError("OTP_WRONG", f"That code is not correct. {left} attempt{'s' if left != 1 else ''} left.", 400)
    otp.verified = True
    return otp
