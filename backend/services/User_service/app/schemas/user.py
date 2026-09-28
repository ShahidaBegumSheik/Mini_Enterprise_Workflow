from datetime import datetime
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
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
