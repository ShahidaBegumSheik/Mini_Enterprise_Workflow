from datetime import datetime
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    StrictBool,
    StringConstraints,
    field_validator,
)


Name = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=100),
]
OptionalName = Annotated[
    str,
    StringConstraints(strip_whitespace=True, max_length=100),
]
PhoneNumber = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=7,
        max_length=30,
        pattern=r"^\+?[0-9().\-\s]+$",
    ),
]
Bio = Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000)]


class UserResponse(BaseModel):
    """Public representation of a user.

    Contains profile data only; no credential or token material is ever
    serialised, and the Authentication Service keeps ownership of those.
    """

    id: int
    email: EmailStr
    first_name: str
    last_name: str | None = None
    phone_number: str | None = None
    bio: str | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserUpdate(BaseModel):
    """Editable profile fields.

    Protected fields (``id``, ``email``, ``is_active``, ``created_at``,
    ``updated_at``) are rejected: ``extra="forbid"`` turns any attempt to send
    them into a 422 instead of silently ignoring them.
    """

    first_name: Name | None = None
    last_name: OptionalName | None = None
    phone_number: PhoneNumber | None = None
    bio: Bio | None = None

    model_config = ConfigDict(extra="forbid")

    @field_validator("first_name")
    @classmethod
    def validate_first_name(cls, value: str | None) -> str:
        if value is None:
            raise ValueError("first_name cannot be null")
        if not value.strip():
            raise ValueError("first_name cannot be blank")
        return value

    @field_validator("last_name")
    @classmethod
    def normalize_last_name(cls, value: str | None) -> str | None:
        return value or None

    @field_validator("phone_number")
    @classmethod
    def validate_phone_number(cls, value: str | None) -> str | None:
        if value is not None and sum(
            character.isdigit() for character in value
        ) < 7:
            raise ValueError("phone_number must contain at least seven digits")
        return value

    @field_validator("bio")
    @classmethod
    def normalize_bio(cls, value: str | None) -> str | None:
        return value or None


class UserProfileUpdate(UserUpdate):
    """Profile payload for ``PUT /users/profile`` (the current user)."""


class UserStatusUpdate(BaseModel):
    """Activate / deactivate a user."""

    is_active: StrictBool = Field(
        description="True activates the user, false deactivates the user.",
    )

    model_config = ConfigDict(extra="forbid")


class UserListResponse(BaseModel):
    """Paginated collection of users."""

    items: list[UserResponse] = Field(default_factory=list)
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    pages: int = Field(ge=0)

    @classmethod
    def build(
        cls,
        *,
        items: list[UserResponse],
        total: int,
        page: int,
        page_size: int,
    ) -> "UserListResponse":
        pages = (total + page_size - 1) // page_size if page_size else 0
        return cls(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            pages=pages,
        )
