from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)


PASSWORD_MIN_LENGTH = 8


def validate_password_policy(password: str) -> str:
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(
            f"Password must be at least {PASSWORD_MIN_LENGTH} characters long"
        )
    if not any(ch.isupper() for ch in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(ch.islower() for ch in password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not any(ch.isdigit() for ch in password):
        raise ValueError("Password must contain at least one digit")
    if not any(ch in "!@#$%^&*()-_=+[]{};:,.<>?/~" for ch in password):
        raise ValueError(
            "Password must contain at least one special character"
        )
    return password


class BaseAccount(BaseModel):
    full_name: str = Field(..., min_length=1, max_length=150)
    email: EmailStr
    password: str = Field(..., min_length=PASSWORD_MIN_LENGTH)
    confirm_password: str = Field(..., min_length=PASSWORD_MIN_LENGTH)
    account_type: Literal["individual", "organization"]

    @field_validator("full_name")
    @classmethod
    def strip_full_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("full_name is required")
        return value

    @field_validator("password")
    @classmethod
    def password_policy(cls, value: str) -> str:
        return validate_password_policy(value)

    @model_validator(mode="after")
    def passwords_match(self) -> "BaseAccount":
        if self.password != self.confirm_password:
            raise ValueError("password and confirm_password must match")
        return self


class IndividualRegisterRequest(BaseAccount):
    account_type: Literal["individual"]

    @field_validator("email")
    @classmethod
    def personal_email_only(cls, value: EmailStr) -> EmailStr:
        from app.core.email_validation import is_personal_email

        if not is_personal_email(str(value)):
            raise ValueError(
                "Only personal email providers are allowed for individual "
                "accounts"
            )
        return value


class OrganizationRegisterRequest(BaseAccount):
    organization_name: str = Field(..., min_length=1, max_length=255)
    account_type: Literal["organization"]

    @field_validator("organization_name")
    @classmethod
    def strip_org_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("organization_name is required")
        return value

    @field_validator("email")
    @classmethod
    def business_email_only(cls, value: EmailStr) -> EmailStr:
        from app.core.email_validation import is_business_email

        if not is_business_email(str(value)):
            raise ValueError(
                "Only official business email providers are allowed for "
                "organization accounts"
            )
        return value


class OTPFieldMixin(BaseModel):
    otp: str = Field(..., min_length=6, max_length=6)

    @field_validator("otp")
    @classmethod
    def otp_must_be_digits(cls, value: str) -> str:
        if not value.isdigit():
            raise ValueError("OTP must contain only digits")
        return value


class VerifyAccountRequest(OTPFieldMixin):
    """Completes registration following a successful OTP verification.

    The full registration payload is re-submitted here (rather than embedded
    in the OTP JWT) so the plain-text password is never stored or carried in a
    token.
    """

    full_name: str = Field(..., min_length=1, max_length=150)
    email: EmailStr
    password: str = Field(..., min_length=PASSWORD_MIN_LENGTH)
    confirm_password: str = Field(..., min_length=PASSWORD_MIN_LENGTH)
    account_type: Literal["individual", "organization"]
    organization_name: str | None = Field(default=None, max_length=255)

    @field_validator("full_name")
    @classmethod
    def strip_full_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("full_name is required")
        return value

    @field_validator("organization_name")
    @classmethod
    def strip_org_name(cls, value: str | None) -> str | None:
        if value is None:
            return value
        value = value.strip()
        return value or None

    @field_validator("password")
    @classmethod
    def password_policy(cls, value: str) -> str:
        return validate_password_policy(value)

    @model_validator(mode="after")
    def validate_all(self) -> "VerifyAccountRequest":
        from app.core.email_validation import is_business_email, is_personal_email

        if self.password != self.confirm_password:
            raise ValueError("password and confirm_password must match")

        email = str(self.email).lower()
        if self.account_type == "individual":
            if not is_personal_email(email):
                raise ValueError(
                    "Only personal email providers are allowed for "
                    "individual accounts"
                )
        elif self.account_type == "organization":
            if not is_business_email(email):
                raise ValueError(
                    "Only official business email providers are allowed for "
                    "organization accounts"
                )
            if not self.organization_name:
                raise ValueError("organization_name is required")
        return self


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class VerifyForgotOTPRequest(OTPFieldMixin):
    pass


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    password: str = Field(..., min_length=PASSWORD_MIN_LENGTH)
    confirm_password: str = Field(..., min_length=PASSWORD_MIN_LENGTH)

    @field_validator("password")
    @classmethod
    def password_policy(cls, value: str) -> str:
        return validate_password_policy(value)

    @model_validator(mode="after")
    def passwords_match(self) -> "ResetPasswordRequest":
        if self.password != self.confirm_password:
            raise ValueError("password and confirm_password must match")
        return self


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    full_name: str
    email: str
    account_type: str
    role: str
    tenant_id: int | None
    is_active: bool
    is_verified: bool


class TokenPairOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RegisterResponse(BaseModel):
    message: str
    email: str
    account_type: str
    otp_expires_in_minutes: int


class OTPVerifyResponse(BaseModel):
    message: str
    user: UserOut | None = None
    tenant_id: int | None = None


class ResendOTPResponse(BaseModel):
    message: str
    email: str
    otp_expires_in_minutes: int


class LoginResponse(BaseModel):
    message: str
    user: UserOut


class MessageResponse(BaseModel):
    message: str


class RefreshTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LogoutResponse(BaseModel):
    message: str
