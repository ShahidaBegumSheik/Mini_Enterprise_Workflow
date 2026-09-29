from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


Name = Annotated[str, Field(min_length=1, max_length=100)]
FullName = Annotated[str, Field(min_length=1, max_length=201)]


class InternalUserCreate(BaseModel):
    """Payload the Authentication Service posts after a verified sign-up.

    Only the profile fields owned by this service are consumed. Authentication
    specific fields (``password_hash``, tokens, OTP state) are owned by the
    Authentication Service and are intentionally ignored.
    """

    email: EmailStr
    full_name: FullName | None = None
    first_name: Name | None = None
    last_name: Annotated[str, Field(max_length=100)] | None = None
    is_active: bool = True

    model_config = ConfigDict(extra="ignore")

    @field_validator("full_name", "first_name", "last_name", mode="before")
    @classmethod
    def _strip(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    def split_name(self) -> tuple[str, str | None]:
        """Resolve ``first_name`` / ``last_name`` from either representation."""

        if self.first_name:
            first_name = self.first_name
        elif self.full_name:
            parts = self.full_name.split()
            first_name = parts[0]
        else:
            first_name = self.email.split("@", 1)[0] or "Unknown"

        last_name = self.last_name
        if last_name is None and not self.first_name and self.full_name:
            parts = self.full_name.split()
            last_name = " ".join(parts[1:]) or None

        return first_name[:100], (last_name[:100] if last_name else None)


class InternalUserResponse(BaseModel):
    """Minimal internal projection.

    The Authentication Service only needs the identifier and a few profile
    fields; the email is included because it is the correlation key it owns.
    """

    user_id: int
    id: int
    email: EmailStr
    first_name: str
    last_name: str | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_user(cls, user: Any) -> "InternalUserResponse":
        return cls(
            user_id=user.id,
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            is_active=user.is_active,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )


class InternalUserSync(BaseModel):
    """Best-effort user sync event pushed by the Authentication Service."""

    action: Literal[
        "created",
        "activated",
        "deactivated",
        "password_changed",
        "updated",
        "deleted",
    ] = "updated"
    email: EmailStr | None = None
    full_name: str | None = None

    model_config = ConfigDict(extra="ignore")


class InternalNotification(BaseModel):
    """Notification request forwarded by the Authentication Service."""

    title: Annotated[str, Field(min_length=1, max_length=200)]
    message: Annotated[str, Field(min_length=1, max_length=2000)]
    notification_type: Annotated[str, Field(min_length=1, max_length=50)] = "info"

    model_config = ConfigDict(extra="ignore")


class InternalAccepted(BaseModel):
    """Acknowledgement returned by the best-effort internal endpoints."""

    status: str = "accepted"
