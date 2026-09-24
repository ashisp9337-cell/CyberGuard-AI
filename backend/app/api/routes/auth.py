from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, Request, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.dependencies import get_current_user
from app.core.security import (
    hash_password, verify_password, password_is_strong, create_access_token,
    generate_reset_token, hash_token, verify_google_credential, GoogleVerificationError,
    verify_turnstile,
)
from app.db.database import get_db
from app.db.models import User, PasswordResetToken, UserSettings
from app.schemas.auth import (
    SignUpRequest, SignInRequest, GoogleAuthRequest, ForgotPasswordRequest,
    ResetPasswordRequest, AuthResultOut,
)

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


@router.post("/register", status_code=201)
async def register(body: SignUpRequest, response: Response, request: Request, db: Session = Depends(get_db)):
    if body.turnstileToken and not await verify_turnstile(body.turnstileToken, request.client.host if request.client else None):
        raise _err("CAPTCHA_FAILED", "CAPTCHA verification failed.")

    weak_reason = password_is_strong(body.password)
    if weak_reason:
        raise _err("WEAK_PASSWORD", weak_reason, 422)

    email = body.email.strip().lower()
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise _err("EMAIL_EXISTS", "An account with this email already exists.", 409)

    user = User(name=body.name, email=email, password_hash=hash_password(body.password),
                provider="password", last_login=datetime.now(timezone.utc))
    db.add(user)
    db.flush()
    db.add(UserSettings(user_id=user.id))
    db.commit()
    db.refresh(user)

    _set_session_cookie(response, user.id)
    return AuthResultOut(user=_to_public(user))


@router.post("/login")
async def login(body: SignInRequest, response: Response, request: Request, db: Session = Depends(get_db)):
    if body.turnstileToken and not await verify_turnstile(body.turnstileToken, request.client.host if request.client else None):
        raise _err("CAPTCHA_FAILED", "CAPTCHA verification failed.")

    email = body.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.password_hash or not verify_password(body.password, user.password_hash):
        raise _err("INVALID_CREDENTIALS", "Invalid email or password.", 401)

    user.last_login = datetime.now(timezone.utc)
    db.commit()

    _set_session_cookie(response, user.id, remember_me=bool(body.rememberMe) if body.rememberMe is not None else True)
    return AuthResultOut(user=_to_public(user))


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
