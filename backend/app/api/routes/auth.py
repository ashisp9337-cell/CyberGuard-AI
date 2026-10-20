from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, Request
import jwt
from jwt import PyJWTError as JWTError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.dependencies import get_current_user, get_current_user_optional, is_admin
from app.core.security import (
    hash_password, verify_password, password_is_strong, create_access_token,
    generate_reset_token, hash_token, verify_google_credential, GoogleVerificationError,
    verify_turnstile,
)
from app.db.database import get_db
from app.core.rate_limit import limiter
from app.db.models import User, PasswordResetToken, UserSettings
from app.schemas.auth import (
    SignUpRequest, SignInRequest, GoogleAuthRequest, ForgotPasswordRequest,
    ResetPasswordRequest, AuthResultOut, SignupStartRequest, OTPVerifyRequest,
    SignupCompleteRequest, OTPResendRequest,
)
from app.services import otp as otp_service
from app.automation import login_monitor
from app.services import audit

router = APIRouter(prefix="/api/auth", tags=["auth"])
settings = get_settings()


def _err(code: str, message: str, status_code: int = 400):
    return HTTPException(status_code=status_code, detail={"error": {"code": code, "message": message}})


def _set_session_cookie(response: Response, user: User, remember_me: bool = True):
    token = create_access_token(user.id, user.session_version or 0)
    max_age = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60 if remember_me else None
    response.set_cookie(
        key=settings.COOKIE_NAME, value=token, httponly=True,
        secure=settings.COOKIE_SECURE, samesite="lax", max_age=max_age, path="/",
    )


def _to_public(user: User) -> dict:
    return {
        "id": user.id, "name": user.name, "email": user.email,
        "avatarUrl": user.profile_image, "provider": user.provider,
        "createdAt": user.created_at.isoformat() if user.created_at else "",
    }


def _otp_http(e: "otp_service.OTPError"):
    return _err(e.code, e.message, e.status)


async def _captcha_ok(token: str | None, request: Request):
    """When Turnstile is configured the token is REQUIRED -- leaving it out must not skip the check."""
    if not settings.TURNSTILE_SECRET_KEY and not settings.is_production:
        return                                   # CAPTCHA not set up (local development)
    if not token or not await verify_turnstile(token, request.client.host if request.client else None):
        raise _err("CAPTCHA_FAILED", "CAPTCHA verification failed.")


SIGNUP_TOKEN_MINUTES = 15


def _signup_token(email: str, name: str, challenge_id: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=SIGNUP_TOKEN_MINUTES)
    return jwt.encode({"typ": "signup", "email": email, "name": name, "otp": challenge_id, "exp": exp},
                      settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


# ---------------------------------------------------------------------------
# SIGNUP:  1) name + email  ->  2) code from email  ->  3) create password
# ---------------------------------------------------------------------------
@router.post("/signup/start")
@limiter.limit("5/minute")
async def signup_start(body: SignupStartRequest, request: Request, db: Session = Depends(get_db)):
    await _captcha_ok(body.turnstileToken, request)
    email = body.email.strip().lower()
    if db.query(User).filter(User.email == email).first():
        raise _err("EMAIL_EXISTS", "An account with this email already exists. Sign in instead.", 409)
    try:
        return otp_service.start(db, purpose="signup", email=email, name=body.name)
    except otp_service.OTPError as e:
        raise _otp_http(e)


@router.post("/signup/verify")
@limiter.limit("10/minute")
def signup_verify(body: OTPVerifyRequest, request: Request, db: Session = Depends(get_db)):
    try:
        otp = otp_service.check(db, body.challengeId, "signup", body.code)
    except otp_service.OTPError as e:
        raise _otp_http(e)
    db.commit()
    return {"signupToken": _signup_token(otp.email, otp.name or otp.email, otp.id),
            "email": otp.email, "name": otp.name, "expiresInSeconds": SIGNUP_TOKEN_MINUTES * 60}


@router.post("/signup/complete", status_code=201)
@limiter.limit("10/minute")
def signup_complete(body: SignupCompleteRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    try:
        data = jwt.decode(body.signupToken, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        raise _err("SIGNUP_EXPIRED", "Your verification has expired. Please start the sign-up again.", 400)
    from app.db.models import EmailOTP
    otp = db.get(EmailOTP, data.get("otp", "")) if data.get("typ") == "signup" else None
    if otp is None or not otp.verified or otp.consumed or otp.email != data.get("email"):
        raise _err("SIGNUP_EXPIRED", "Your verification has expired. Please start the sign-up again.", 400)

    weak_reason = password_is_strong(body.password)
    if weak_reason:
        raise _err("WEAK_PASSWORD", weak_reason, 422)
    email = otp.email
    if db.query(User).filter(User.email == email).first():
        raise _err("EMAIL_EXISTS", "An account with this email already exists. Sign in instead.", 409)

    user = User(name=otp.name or data.get("name") or email, email=email, password_hash=hash_password(body.password),
                provider="password", is_verified=True, last_login=datetime.now(timezone.utc))
    db.add(user)
    db.flush()
    db.add(UserSettings(user_id=user.id))
    otp.consumed = True
    audit.log(db, action="auth.signup", user=user, request=request)
    db.commit()
    db.refresh(user)
    _set_session_cookie(response, user)
    return AuthResultOut(user=_to_public(user))


@router.post("/register", status_code=410)
def register_removed(body: SignUpRequest):
    """Old one-step sign-up. Replaced by /signup/start -> /signup/verify -> /signup/complete."""
    raise _err("USE_OTP_SIGNUP", "Sign-up now verifies your email first. Use the sign-up page.", 410)


# ---------------------------------------------------------------------------
# LOGIN:  1) email + password  ->  2) code from email  ->  logged in
# ---------------------------------------------------------------------------
@router.post("/login")
@limiter.limit("10/minute")
async def login(body: SignInRequest, request: Request, db: Session = Depends(get_db)):
    await _captcha_ok(body.turnstileToken, request)
    email = body.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.password_hash or not verify_password(body.password, user.password_hash):
        audit.log(db, action="auth.login_failed", user=user, actor=email, request=request, success=False,
                  detail={"reason": "wrong password" if user else "no such account"})
        login_monitor.record_attempt(db, email=email, user_id=user.id if user else None, request=request,
                                     success=False, stage="password")
        raise _err("INVALID_CREDENTIALS", "Invalid email or password.", 401)
    # Password is right -- but no session yet. A code goes to the account's email first.
    try:
        challenge = otp_service.start(db, purpose="login", email=user.email, user_id=user.id,
                                      remember_me=bool(body.rememberMe) if body.rememberMe is not None else True)
    except otp_service.OTPError as e:
        raise _otp_http(e)
    return {"otpRequired": True, **challenge}


@router.post("/login/verify")
@limiter.limit("10/minute")
def login_verify(body: OTPVerifyRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    try:
        otp = otp_service.check(db, body.challengeId, "login", body.code)
    except otp_service.OTPError as e:
        if e.code in ("OTP_WRONG", "OTP_TOO_MANY_ATTEMPTS"):          # the password was right, the code was not
            row = _challenge_owner(db, body.challengeId)
            if row is not None:
                audit.log(db, action="auth.otp_failed", user=db.get(User, row.user_id) if row.user_id else None,
                          actor=row.email, request=request, success=False)
                login_monitor.record_attempt(db, email=row.email, user_id=row.user_id, request=request,
                                             success=False, stage="otp")
        raise _otp_http(e)
    user = db.get(User, otp.user_id) if otp.user_id else None
    if user is None:
        raise _err("OTP_INVALID", "This verification request is no longer valid. Please sign in again.", 400)
    otp.consumed = True
    user.is_verified = True          # they just proved they own the email
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    _set_session_cookie(response, user, remember_me=otp.remember_me)
    audit.log(db, action="auth.login", user=user, request=request, commit=True)
    login_monitor.record_attempt(db, email=user.email, user_id=user.id, request=request, success=True, stage="otp")
    return AuthResultOut(user=_to_public(user))


def _challenge_owner(db, challenge_id: str):
    from app.db.models import EmailOTP
    try:
        return db.get(EmailOTP, challenge_id)
    except Exception:
        return None


@router.post("/otp/resend")
@limiter.limit("5/minute")
def otp_resend(body: OTPResendRequest, request: Request, db: Session = Depends(get_db)):
    if body.purpose not in ("signup", "login"):
        raise _err("OTP_INVALID", "Unknown verification type.", 400)
    try:
        return otp_service.resend(db, body.challengeId, body.purpose)
    except otp_service.OTPError as e:
        raise _otp_http(e)


@router.post("/google")
@limiter.limit("10/minute")
async def google_auth(body: GoogleAuthRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    try:
        idinfo = verify_google_credential(body.credential)
    except GoogleVerificationError as e:
        raise _err("GOOGLE_VERIFICATION_FAILED", str(e), 401)

    email = idinfo["email"].strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            name=idinfo.get("name", email), email=email, google_id=idinfo.get("sub"),
            profile_image=idinfo.get("picture"), provider="google", is_verified=True,
            last_login=datetime.now(timezone.utc),
        )
        db.add(user)
        db.flush()
        db.add(UserSettings(user_id=user.id))
    else:
        user.google_id = idinfo.get("sub")
        user.last_login = datetime.now(timezone.utc)
        if not user.profile_image:
            user.profile_image = idinfo.get("picture")
    db.flush()
    audit.log(db, action="auth.google_login", user=user, request=request)
    db.commit()
    db.refresh(user)

    _set_session_cookie(response, user)
    return AuthResultOut(user=_to_public(user))


@router.get("/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return {**_to_public(user), "isAdmin": is_admin(user, db)}


@router.post("/logout")
def logout(response: Response, user: User | None = Depends(get_current_user_optional), db: Session = Depends(get_db)):
    """Ends the session on this device AND every other device (old tokens stop working)."""
    if user is not None:
        user.session_version = int(user.session_version or 0) + 1
        db.commit()
    response.delete_cookie(settings.COOKIE_NAME, path="/", httponly=True, secure=settings.COOKIE_SECURE, samesite="lax")
    return {"success": True}


RESET_MESSAGE = "If that email exists, a reset link has been sent."


def _send_reset_email(email: str, raw_token: str) -> bool:
    from app.services import notifier
    link = f"{settings.APP_BASE_URL.rstrip('/')}/reset-password?token={raw_token}"
    text = ("Someone asked to reset your CYBERGUARD password.\n\n"
            f"Open this link within 1 hour to choose a new password:\n{link}\n\n"
            "If this wasn't you, ignore this email -- your password stays the same.")
    import html as _html
    body = ('<div style="font-family:Arial,sans-serif;max-width:480px;color:#111">'
            '<h2 style="margin:0 0 12px;color:#0891b2">CYBERGUARD</h2>'
            '<p>Someone asked to reset your password. The link works for 1 hour:</p>'
            f'<p><a href="{_html.escape(link)}" style="background:#0891b2;color:#fff;padding:9px 14px;'
            'border-radius:6px;text-decoration:none">Reset password</a></p>'
            '<p style="color:#666;font-size:12px">If this wasn\'t you, ignore this email.</p></div>')
    result = notifier.send_mail([email], "Reset your CYBERGUARD password", text, body, channel="reset-email")
    return result.get("status") == "sent"


@router.post("/forgot-password")
@limiter.limit("3/minute")
def forgot_password(body: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """The reset link is ONLY ever emailed. It is never returned in the response -- otherwise anyone
    who knows an email address could take over that account."""
    email = body.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return {"message": RESET_MESSAGE}          # identical answer whether or not the account exists
    raw_token, token_hash = generate_reset_token()
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    db.add(PasswordResetToken(user_id=user.id, token_hash=token_hash, expires_at=expires))
    db.commit()
    sent = _send_reset_email(user.email, raw_token)
    if not sent and not settings.is_production:
        # Development, email not working: only the person running the server can see this line.
        import logging
        logging.getLogger("cyberguard").warning("[DEV] Password reset link for %s: %s/reset-password?token=%s",
                                                email, settings.APP_BASE_URL.rstrip("/"), raw_token)
    if settings.dev_codes_allowed:                  # automated tests only (EXPOSE_DEV_CODES)
        return {"message": RESET_MESSAGE, "devResetToken": raw_token}
    return {"message": RESET_MESSAGE}


@router.post("/reset-password")
@limiter.limit("5/minute")
def reset_password(body: ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    weak_reason = password_is_strong(body.newPassword)
    if weak_reason:
        raise _err("WEAK_PASSWORD", weak_reason, 422)

    token_hash = hash_token(body.token)
    record = db.query(PasswordResetToken).filter(PasswordResetToken.token_hash == token_hash).first()
    now = datetime.now(timezone.utc)
    if not record or record.used or record.expires_at.replace(tzinfo=timezone.utc) < now:
        raise _err("INVALID_RESET_TOKEN", "This reset link is invalid or has expired.", 400)

    user = db.query(User).filter(User.id == record.user_id).first()
    if not user:
        raise _err("INVALID_RESET_TOKEN", "This reset link is invalid or has expired.", 400)

    user.password_hash = hash_password(body.newPassword)
    record.used = True
    # every other unused reset link for this account dies too, and every signed-in session ends
    for other in db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id,
                                                     PasswordResetToken.used.is_(False)).all():
        other.used = True
    user.session_version = int(user.session_version or 0) + 1
    audit.log(db, action="auth.password_reset", user=user, request=request)
    db.commit()
    return {"success": True}
