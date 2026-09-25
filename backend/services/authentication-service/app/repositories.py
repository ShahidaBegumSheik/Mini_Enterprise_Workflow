"""Data access owned by the Authentication Service (single source file)."""

import hashlib
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.utils import utcnow
from app.models import AuthCredential, RefreshSession

__all__ = ["AuthRepository"]


def token_hash(jti: str) -> str:
    """Deterministic SHA-256 digest of a refresh token's ``jti``.

    This is the only form of the refresh token ever persisted.
    """
    return hashlib.sha256(jti.encode("utf-8")).hexdigest()


class AuthRepository:
    """Data access for authentication-owned state.

    Owns auth_credentials only. It never touches User Service or Tenant
    Admin Service databases.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def credential_by_email(self, email: str) -> AuthCredential | None:
        return self.db.scalar(
            select(AuthCredential).where(AuthCredential.email == email.lower())
        )

    def credential_by_user_id(self, user_id: int) -> AuthCredential | None:
        return self.db.scalar(
            select(AuthCredential).where(AuthCredential.user_id == user_id)
        )

    def create_credential(
        self,
        *,
        user_id: int,
        email: str,
        password_hash: str,
        account_type: str,
        organization_id: int | None = None,
        is_active: bool = True,
        is_verified: bool = True,
    ) -> AuthCredential:
        credential = AuthCredential(
            user_id=user_id,
            email=email.lower(),
            password_hash=password_hash,
            account_type=account_type,
            organization_id=organization_id,
            is_active=is_active,
            is_verified=is_verified,
        )
        self.db.add(credential)
        self.db.commit()
        self.db.refresh(credential)
        return credential

    # ------------------------------------------------------------------
    # Refresh sessions (safe metadata only - never raw tokens)
    # ------------------------------------------------------------------

    def create_refresh_session(
        self,
        *,
        session_id: str,
        user_id: int,
        expires_at: datetime,
        device_info: str | None = None,
        ip_address: str | None = None,
    ) -> RefreshSession:
        session = RefreshSession(
            id=session_id,
            user_id=user_id,
            token_hash=token_hash(session_id),
            device_info=device_info,
            ip_address=ip_address,
            issued_at=utcnow(),
            expires_at=expires_at,
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session

    def refresh_session_by_id(self, session_id: str) -> RefreshSession | None:
        return self.db.scalar(
            select(RefreshSession).where(RefreshSession.id == session_id)
        )

    def refresh_session_by_token_hash(self, token_hash: str) -> RefreshSession | None:
        return self.db.scalar(
            select(RefreshSession).where(RefreshSession.token_hash == token_hash)
        )

    def revoke_refresh_session(
        self,
        session_id: str,
        *,
        replaced_by: str | None = None,
    ) -> None:
        """Revoke a session; optionally record which session replaced it (rotation)."""
        session = self.refresh_session_by_id(session_id)
        if session is None:
            return
        session.revoked_at = utcnow()
        if replaced_by:
            session.replaced_by = replaced_by
        self.db.commit()

    def revoke_refresh_family(self, session_id: str) -> None:
        """Revoke an entire refresh-token family.

        Follows the ``replaced_by`` chain starting at ``session_id``. Used when
        an already-rotated/revoked token is presented (reuse): the whole chain
        of sessions minted for that login family is killed.
        """
        current_id = session_id
        seen: set[str] = set()
        while current_id and current_id not in seen:
            seen.add(current_id)
            session = self.refresh_session_by_id(current_id)
            if session is None:
                break
            if session.revoked_at is None:
                session.revoked_at = utcnow()
            current_id = session.replaced_by
        self.db.commit()