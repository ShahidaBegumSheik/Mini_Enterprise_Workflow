from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    String,
    Text,
    func,
    true,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


#: Columns this service is allowed to write through the public update APIs.
PROFILE_COLUMNS = ("first_name", "last_name", "phone_number", "bio")

#: Columns that are never accepted from a request body.
IMMUTABLE_COLUMNS = ("id", "email", "is_active", "created_at", "updated_at")


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    """Individual user profile.

    This service owns profile data only. Passwords, credentials, OTP state
    and tokens live in the Authentication Service and are never stored here.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    first_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    last_name: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    phone_number: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    bio: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=true(),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=utc_now,
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=utc_now,
        onupdate=utc_now,
        server_default=func.now(),
        nullable=False,
    )

    __table_args__ = (
        # Supports the "list active users" access pattern without a full scan.
        Index("ix_users_is_active", "is_active"),
        # Supports stable, ordered pagination.
        Index("ix_users_created_at", "created_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<User id={self.id} email={self.email!r} active={self.is_active}>"
