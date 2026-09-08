from pydantic import BaseModel, EmailStr, Field, field_validator


class OTPEmailRequest(BaseModel):
    email: EmailStr
    subject: str = Field(..., min_length=1, max_length=200)
    body: str = Field(..., min_length=1, max_length=4000)
    purpose: str = Field(..., min_length=1, max_length=50)

    @field_validator("purpose")
    @classmethod
    def allowed_purposes(cls, value: str) -> str:
        allowed = {"registration", "reset_password", "login"}
        if value not in allowed:
            raise ValueError(
                "purpose must be one of: registration, reset_password, login"
            )
        return value


class OTPEmailResponse(BaseModel):
    message: str
    email: str
    purpose: str