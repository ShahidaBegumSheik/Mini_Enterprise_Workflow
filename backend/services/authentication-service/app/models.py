"""Database models owned by the Authentication Service (single source file).

Service boundaries
-------------------
The Authentication Service owns ``auth_db`` exclusively. Nothing here creates a
foreign-key constraint or query against the User Service or Tenant Admin
Service databases: ``user_id`` and ``organization_id`` are plain integer
columns carrying *external service identifiers*, held here only because the
authentication flows need them. No raw credentials, OTPs or tokens ever
cross into or out of these tables.

Timestamp convention
--------------------
All timestamps are UTC instants stored as naive ``DATETIME`` (the
UTC-by-convention used across the service). Every write path uses
``app.core.utils.utcnow()``, which returns naive UTC, so comparisons and
expiry checks are always against UTC wall-clock values regardless of the
database server's local timezone.
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.utils import utcnow
from app.database.base import Base

__all__ = ["AuthCredential", "RefreshSession", "PasswordReset"]

# Field width for the SHA-256 hex digest of a token's ``jti`` (the only token
# material ever persisted).
TOKEN_HASH_LENGTH = 64

# Field width for a UUID4-style token/session id (also the token's ``jti``).
JTI_LENGTH = 36


class AuthCredential(Base):
    """Authentication-specific data owned by this service only.

    The canonical user profile lives in the User Service; this table only
    holds the credential state needed to authenticate a principal. The
    password is stored exclusively as a ``password_hash`` (bcrypt via
    ``app.core.security.hash_password``) — never the plaintext.
    """

    __tablename__ = "auth_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, unique=True)  # unique index covers equality lookups
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    account_type: Mapped[str] = mapped_column(String(30), default="individual")
    organization_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class RefreshSession(Base):
    """Safe metadata for one refresh-token session (never the raw token).

    Implements the service contract's ``refresh_tokens`` persistence surface
    merged with the optional session-metadata surface:

    - ``id`` (the refresh token's ``jti``), ``token_hash`` (SHA-256 of the jti)
    - ``user_id`` as an external service identifier
    - ``issued_at`` / ``expires_at`` / ``revoked_at`` / ``replaced_by``
    - ``created_at`` / ``updated_at``
    - ``device_info`` / ``ip_address`` (session metadata)

    Only the SHA-256 digest of the refresh token's ``jti`` is stored, so a
    database leak cannot be replayed as a valid refresh token. ``expires_at``
    (cleanup/expiry lookups) and ``revoked_at`` (active-session scans) are
    indexed.
    """

    __tablename__ = "refresh_sessions"

    id: Mapped[str] = mapped_column(String(JTI_LENGTH), primary_key=True)  # also the refresh token jti
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    token_hash: Mapped[str] = mapped_column(String(TOKEN_HASH_LENGTH), unique=True)
    device_info: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    replaced_by: Mapped[str | None] = mapped_column(String(JTI_LENGTH), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class PasswordReset(Base):
    """Safe metadata for a single-use password-reset flow.

    The verified reset token is a short-lived JWT; only a SHA-256 digest of
    its jti is stored here, alongside the single-use ``consumed_at`` marker
    that makes a reused reset token detectable. ``expires_at`` and
    ``consumed_at`` (the reset-flow revoke status) are indexed.
    """

    __tablename__ = "password_resets"

    id: Mapped[str] = mapped_column(String(JTI_LENGTH), primary_key=True)  # also the reset-token jti
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    token_hash: Mapped[str] = mapped_column(String(TOKEN_HASH_LENGTH), unique=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)