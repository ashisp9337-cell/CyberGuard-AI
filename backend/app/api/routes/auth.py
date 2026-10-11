from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, Request, status
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.dependencies import get_current_user
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

router = APIRouter(prefix="/api/auth", tags=["auth"])
settings = get_settings()


def _err(code: str, message: str, status_code: int = 400):
    return HTTPException(status_code=status_code, detail={"error": {"code": code, "message": message}})


def _set_session_cookie(response: Response, user_id: str, remember_me: bool = True):
    token = create_access_token(user_id)
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
    if token and not await verify_turnstile(token, request.client.host if request.client else None):
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
    db.commit()
    db.refresh(user)
    _set_session_cookie(response, user.id)
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
        raise _otp_http(e)
    user = db.get(User, otp.user_id) if otp.user_id else None
    if user is None:
        raise _err("OTP_INVALID", "This verification request is no longer valid. Please sign in again.", 400)
    otp.consumed = True
    user.is_verified = True          # they just proved they own the email
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    _set_session_cookie(response, user.id, remember_me=otp.remember_me)
    return AuthResultOut(user=_to_public(user))


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
async def google_auth(body: GoogleAuthRequest, response: Response, db: Session = Depends(get_db)):
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
    db.commit()
    db.refresh(user)

    _set_session_cookie(response, user.id)
    return AuthResultOut(user=_to_public(user))


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return _to_public(user)


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(settings.COOKIE_NAME, path="/")
    return {"success": True}


@router.post("/forgot-password")
def forgot_password(body: ForgotPasswordRequest, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    # Always behave identically whether or not the account exists.
    if user:
        raw_token, token_hash = generate_reset_token()
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        db.add(PasswordResetToken(user_id=user.id, token_hash=token_hash, expires_at=expires))
        db.commit()
        if not settings.is_production:
            # Development-only convenience: log instead of emailing.
            print(f"[DEV] Password reset token for {email}: {raw_token}")
            return {"message": "If that email exists, a reset link has been sent.", "devResetToken": raw_token}
        # Production: integrate a real email provider here (SES/SendGrid/Postmark)
        # and never return the token in the response.
    return {"message": "If that email exists, a reset link has been sent."}


@router.post("/reset-password")
def reset_password(body: ResetPasswordRequest, db: Session = Depends(get_db)):
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
    db.commit()
    return {"success": True}
