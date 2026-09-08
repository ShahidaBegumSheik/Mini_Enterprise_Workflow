from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.user import User
from app.services.tenant_service import TenantAdminService


class UserService:
    """User Service: individual and tenant user management."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.tenant_service = TenantAdminService(db)

    def get_by_email(self, email: str) -> User | None:
        return self.db.query(User).filter(User.email == email).first()

    def email_exists(self, email: str) -> bool:
        return self.get_by_email(email) is not None

    def get_by_id(self, user_id: int) -> User | None:
        return self.db.get(User, user_id)

    def _create_user(
        self,
        *,
        full_name: str,
        email: str,
        password: str,
        account_type: str,
        role: str,
        tenant_id: int | None = None,
        activate: bool = True,
        verified: bool = True,
        commit: bool = True,
    ) -> User:
        user = User(
            full_name=full_name,
            email=email.lower(),
            password_hash=hash_password(password),
            account_type=account_type,
            role=role,
            tenant_id=tenant_id,
            is_active=activate,
            is_verified=verified,
        )
        self.db.add(user)
        if commit:
            self.db.commit()
            self.db.refresh(user)
        return user

    def create_individual_user(
        self,
        *,
        full_name: str,
        email: str,
        password: str,
    ) -> User:
        """Create and activate an individual user (no tenant required)."""
        if self.email_exists(email):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email already exists",
            )
        return self._create_user(
            full_name=full_name,
            email=email,
            password=password,
            account_type="individual",
            role="individual",
            tenant_id=None,
            activate=True,
            verified=True,
        )

    def create_tenant_admin_user(
        self,
        *,
        full_name: str,
        email: str,
        password: str,
        organization_name: str,
    ) -> User:
        """Create a Tenant Admin user linked to a newly created tenant.

        The tenant and the tenant admin are created in a single transaction so
        an orphan tenant is never left behind if user creation fails.
        """
        if self.email_exists(email):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email already exists",
            )

        if self.tenant_service.get_tenant_by_name(organization_name):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An organization with this name already exists",
            )

        try:
            tenant = self.tenant_service.create_tenant(
                organization_name,
                commit=False,
            )
            self.db.flush()
            user = self._create_user(
                full_name=full_name,
                email=email,
                password=password,
                account_type="organization",
                role="tenant_admin",
                tenant_id=tenant.id,
                activate=True,
                verified=True,
                commit=False,
            )
            self.db.commit()
            self.db.refresh(user)
            return user
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "An account with this email or an organization with this "
                    "name already exists"
                ),
            )

    def activate_user(self, user_id: int) -> User:
        user = self.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        user.is_active = True
        user.is_verified = True
        self.db.commit()
        self.db.refresh(user)
        return user

    def set_password(self, user: User, new_password: str) -> None:
        user.password_hash = hash_password(new_password)
        self.db.commit()
