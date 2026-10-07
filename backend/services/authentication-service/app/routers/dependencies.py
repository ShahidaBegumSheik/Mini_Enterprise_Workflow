from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.clients.email_service import EmailServiceClient
from app.clients.tenant_admin_service import TenantAdminServiceClient
from app.clients.user_service import UserServiceClient
from app.core.config import settings
from app.core.security import TokenError, validate_access_token
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
    email_client = EmailServiceClient()
    return AuthService(AuthRepository(db), users, tenants, email_client)
async def get_current_user(
    request: Request,
    service: AuthService = Depends(get_service),
) -> dict:
    token = request.cookies.get(settings.access_cookie_name)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        claims = validate_access_token(token)
    except TokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    credential = service.repo.credential_by_user_id(int(claims["sub"]))
    if credential is None or not credential.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No valid session")
    if claims.get("ver", 0) != credential.token_version:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session has been revoked")
    user = await service.users.get_user(int(claims["sub"]))
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User no longer exists")
    user["user_id"] = user.get("user_id", int(claims["sub"]))
    return user
