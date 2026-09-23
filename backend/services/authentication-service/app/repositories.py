"""Data access owned by the Authentication Service (single source file)."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuthCredential

__all__ = ["AuthRepository"]


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