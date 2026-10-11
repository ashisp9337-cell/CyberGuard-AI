from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator


class SignUpRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    turnstileToken: Optional[str] = None

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, v):
        if not v.strip():
            raise ValueError("Name is required.")
        return v.strip()


class SignInRequest(BaseModel):
    email: EmailStr
    password: str
    rememberMe: Optional[bool] = False
    turnstileToken: Optional[str] = None


class GoogleAuthRequest(BaseModel):
    credential: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    newPassword: str


class AuthUserOut(BaseModel):
    id: str
    name: str
    email: str
    avatarUrl: Optional[str] = None
    provider: str
    createdAt: str


class AuthResultOut(BaseModel):
    user: AuthUserOut


# ---- OTP signup / login ---------------------------------------------------
class SignupStartRequest(BaseModel):
    name: str
    email: EmailStr
    turnstileToken: Optional[str] = None

    @field_validator("name")
    @classmethod
    def name_ok(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Name is required.")
        if len(v) > 80:
            raise ValueError("Name is too long.")
        return v


class OTPVerifyRequest(BaseModel):
    challengeId: str
    code: str


class SignupCompleteRequest(BaseModel):
    signupToken: str
    password: str


class OTPResendRequest(BaseModel):
    challengeId: str
    purpose: str  # "signup" | "login"
