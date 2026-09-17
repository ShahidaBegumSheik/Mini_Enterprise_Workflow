from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import decode_token
from app.database.session import get_db
from app.models.auth_credential import AuthCredential
from app.repositories.auth_repository import AuthRepository

bearer = HTTPBearer(auto_error=False, scheme_name="BearerAuth")


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer),
    db: Session = Depends(get_db),
) -> AuthCredential:
    token = credentials.credentials if credentials else request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Access token is missing")

    try:
        payload = decode_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid access token")

    credential = AuthRepository(db).credential_by_user_id(int(payload["sub"]))
    if (
        not credential
        or not credential.is_active
        or credential.token_version != int(payload.get("ver", -1))
    ):
        raise HTTPException(status_code=401, detail="Token is invalid or revoked")
    return credential