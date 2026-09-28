from typing import Annotated, Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.core.config import settings


bearer_scheme = HTTPBearer(auto_error=False)
AUTHENTICATE_HEADER = {"WWW-Authenticate": "Bearer"}


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers=AUTHENTICATE_HEADER,
    )


def _parse_user_id(subject: Any) -> int:
    if isinstance(subject, bool):
        raise ValueError

    user_id = int(str(subject).strip())
    if user_id < 1:
        raise ValueError

    return user_id


def get_current_user_id(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
) -> int:
    if credentials is None:
        raise _unauthorized("Not authenticated")

    if credentials.scheme.lower() != "bearer":
        raise _unauthorized("Not authenticated")

    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except (JWTError, TypeError, ValueError) as exc:
        raise _unauthorized("Invalid or expired token") from exc

    subject = payload.get("sub") if isinstance(payload, dict) else None
    if subject is None or subject == "":
        raise _unauthorized("Invalid token")

    try:
        return _parse_user_id(subject)
    except (TypeError, ValueError) as exc:
        raise _unauthorized("Invalid token") from exc
