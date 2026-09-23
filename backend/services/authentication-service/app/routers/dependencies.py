from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.clients.tenant_admin_service import TenantAdminServiceClient
from app.clients.user_service import UserServiceClient
from app.database.session import get_db
from app.repositories import AuthRepository
from app.services import AuthService


def get_service(
    request: Request,
    db: Session = Depends(get_db),
) -> AuthService:
    """Build the AuthService wired to the shared HTTPX client and DB session."""
    users = UserServiceClient(request.app.state.http)
    tenants = TenantAdminServiceClient(request.app.state.http)
    return AuthService(AuthRepository(db), users, tenants)