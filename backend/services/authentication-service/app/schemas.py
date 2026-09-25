"""Request/response schemas for the Authentication Service (single source file)."""

import re
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)

from app.core.config import settings

__all__ = [
    "MessageResponse",
    "RegisterRequest",
    "OTPVerifyRequest",
    "RegistrationVerifiedResponse",
    "LoginRequest",
    "LoginResponse",
    "RefreshResponse",
]

PERSONAL_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
}

AccountType = Literal["individual", "organization"]


def email_domain(email: str) -> str:
    return str(email).rsplit("@", 1)[1].lower()


def validate_password_strength(value: str) -> str:
    errors = []

    if not value:
        raise ValueError("Password is required")

    if len(value) < 8:
        errors.append("at least 8 characters")
    elif len(value) > 72:
        errors.append("at most 72 characters")

    if not value[0].isalnum() and value[0] != "_":
        errors.append("must not start with a special character except underscore (_)")

    if not re.search(r"[a-z]", value):
        errors.append("at least one lowercase letter")

    if not re.search(r"[A-Z]", value):
        errors.append("at least one uppercase letter")

    if not re.search(r"\d", value):
        errors.append("at least one digit")

    if not re.search(r"[^A-Za-z0-9]", value):
        errors.append("at least one special character")

    if errors:
        raise ValueError("Password is missing some criteria : " + ", ".join(errors))

    return value


class MessageResponse(BaseModel):
    message: str
    remaining_attempts: int | None = None
    resend_count: int | None = None
    expires_in: int | None = None


class RegisterRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=150)
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    confirm_password: str = Field(min_length=8, max_length=72)
    account_type: AccountType

    organization_name: str | None = Field(default=None, min_length=2, max_length=150)
    organization_type: str | None = "enterprise"
    industry: str | None = None

    @field_validator("email", mode="after")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return value.strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return validate_password_strength(value)

    @model_validator(mode="after")
    def validate_registration(self):
        if self.password != self.confirm_password:
            raise ValueError("Password and confirm password must match")

        if self.account_type == "individual" and email_domain(self.email) not in PERSONAL_EMAIL_DOMAINS:
            raise ValueError("Individual accounts must use a supported personal email address")

        if self.account_type == "organization":
            if email_domain(self.email) in PERSONAL_EMAIL_DOMAINS:
                raise ValueError("Organization accounts must use an official business email address")
            if not self.organization_name:
                raise ValueError("Organization name is required")

        return self


class OTPVerifyRequest(BaseModel):
    otp: str = Field(
        min_length=settings.otp_length,
        max_length=settings.otp_length,
        pattern=r"^\d+$",
    )


class RegistrationVerifiedResponse(BaseModel):
    message: str
    user_id: int
    email: EmailStr
    account_type: str
    organization: dict | None = None

    model_config = ConfigDict(extra="allow")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    """Safe login payload.

    Deliberately contains NO raw JWTs — access/refresh tokens travel only in
    HttpOnly cookies. ``session_id`` and expiries are safe metadata.
    """

    message: str
    user_id: int
    email: EmailStr
    account_type: str
    session_id: str
    access_token_expires_in: int
    refresh_token_expires_in: int


class RefreshResponse(BaseModel):
    """Safe refresh payload.

    Deliberately contains NO raw JWTs — the rotated access/refresh tokens
    travel only in HttpOnly cookies. ``session_id`` is the new session id.
    """

    message: str
    user_id: int
    session_id: str
    access_token_expires_in: int
    refresh_token_expires_in: int