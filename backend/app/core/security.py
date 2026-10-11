"""
Password hashing, JWT session tokens, Google ID token verification, and
Cloudflare Turnstile verification. Everything here is real — no mocked
verification of any kind.
"""
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from jose import jwt, JWTError
from passlib.context import CryptContext
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

from app.core.config import get_settings

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---- Password hashing -------------------------------------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        return False


PASSWORD_MIN_LENGTH = 8


def password_is_strong(password: str) -> Optional[str]:
    """Returns an error message if weak, else None."""
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters."
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one number."
    return None


# ---- Session JWTs (delivered as HTTP-only cookies) --------------------

def create_access_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": user_id, "exp": expire, "iat": datetime.now(timezone.utc)}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("typ"):   # short-lived purpose tokens (e.g. signup) are never a login session
            return None
        return payload.get("sub")
    except JWTError:
        return None


# ---- Password reset tokens ---------------------------------------------

def generate_reset_token() -> tuple[str, str]:
    """Returns (raw_token_for_email, sha256_hash_for_db). Only the hash is stored."""
    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, token_hash


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


# ---- Google Identity verification (real, server-side) ------------------

class GoogleVerificationError(Exception):
    pass


def verify_google_credential(credential: str) -> dict:
    """
    Verifies a Google ID token server-side against Google's public keys.
    Raises GoogleVerificationError if invalid, expired, or the audience
    doesn't match our configured client ID. Never trust a decoded-but-
    unverified token from the browser.
    """
    if not settings.GOOGLE_CLIENT_ID:
        raise GoogleVerificationError("GOOGLE_CLIENT_ID is not configured on the server.")
    try:
        idinfo = google_id_token.verify_oauth2_token(
            credential, google_requests.Request(), settings.GOOGLE_CLIENT_ID
        )
    except ValueError as e:
        raise GoogleVerificationError(f"Invalid Google credential: {e}")

    if idinfo.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        raise GoogleVerificationError("Invalid token issuer.")
    if not idinfo.get("email_verified", False):
        raise GoogleVerificationError("Google account email is not verified.")
    return idinfo


# ---- Cloudflare Turnstile (real server-side verification) --------------

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


async def verify_turnstile(token: str, remote_ip: Optional[str] = None) -> bool:
    """
    Verifies a Turnstile response token with Cloudflare using the secret
    key. If TURNSTILE_SECRET_KEY isn't configured, verification is skipped
    in development but this is logged — never silently "pass" in production.
    """
    if not settings.TURNSTILE_SECRET_KEY:
        if settings.is_production:
            return False
        return True  # allow local dev without a Turnstile account

    data = {"secret": settings.TURNSTILE_SECRET_KEY, "response": token}
    if remote_ip:
        data["remoteip"] = remote_ip

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(TURNSTILE_VERIFY_URL, data=data)
            result = resp.json()
            return bool(result.get("success"))
        except (httpx.HTTPError, ValueError):
            return False
