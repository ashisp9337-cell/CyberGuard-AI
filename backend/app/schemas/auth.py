from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator


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
    password: str = Field(..., max_length=256)
    rememberMe: Optional[bool] = False
    turnstileToken: Optional[str] = None


class GoogleAuthRequest(BaseModel):
    credential: str = Field(..., max_length=8192)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., max_length=256)
    newPassword: str = Field(..., max_length=256)


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
    challengeId: str = Field(..., max_length=128)
    code: str = Field(..., max_length=12)


class SignupCompleteRequest(BaseModel):
    signupToken: str = Field(..., max_length=4096)
    password: str = Field(..., max_length=256)


class OTPResendRequest(BaseModel):
    challengeId: str = Field(..., max_length=128)
    purpose: str  # "signup" | "login"
