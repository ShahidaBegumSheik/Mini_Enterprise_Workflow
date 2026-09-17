import re
from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)

PERSONAL_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
}


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


class RegisterRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=150)
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    confirm_password: str = Field(min_length=8, max_length=72)
    account_type: str = Field(pattern="^(individual|organization)$")

    organization_name: str | None = Field(default=None, min_length=2, max_length=150)
    organization_type: str | None = "enterprise"
    industry: str | None = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return validate_password_strength(value)

    @model_validator(mode="after")
    def validate_registration(self):
        if self.password != self.confirm_password:
            raise ValueError("Password and confirm password must match")
        domain = str(self.email).rsplit("@", 1)[1].lower()

        if self.account_type == "individual" and domain not in PERSONAL_EMAIL_DOMAINS:
            raise ValueError("Individual accounts must use a supported personal email address")

        if self.account_type == "organization" and domain in PERSONAL_EMAIL_DOMAINS:
            raise ValueError("Organization accounts must use an official business email address")

        if self.account_type == "organization" and not self.organization_name:
            raise ValueError("Organization name is required")

        return self


class OTPVerifyRequest(BaseModel):
    otp: str = Field(min_length=4, max_length=6, pattern=r"^\d{4,6}$")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=8, max_length=72)
    confirm_password: str = Field(min_length=8, max_length=72)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        return validate_password_strength(value)

    @model_validator(mode="after")
    def validate_passwords(self):
        if self.new_password != self.confirm_password:
            raise ValueError("Password and confirm password must match")
        return self


class AuthUserInfo(BaseModel):
    user_id: int
    email: EmailStr
    account_type: str
    organization_id: int | None = None
    is_active: bool = True
    is_verified: bool = True
    created_at: datetime | None = None

    model_config = ConfigDict(extra="allow")


class RegistrationVerifiedResponse(BaseModel):
    message: str
    user_id: int
    email: EmailStr
    account_type: str
    organization: dict | None = None


class LoginResponse(BaseModel):
    message: str
    user: AuthUserInfo


class TokenContextResponse(BaseModel):
    user_id: int
    email: EmailStr
    account_type: str
    organization_id: int | None = None
    token_version: int
    is_active: bool
    is_verified: bool