import secrets
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import InternalApiDisabledError
from app.database.session import get_db
from app.models.user import User
from app.services.user_service import get_user


bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="BearerAuth",
    description="JWT issued by the Authentication Service.",
)
AUTHENTICATE_HEADER = {"WWW-Authenticate": "Bearer"}


@dataclass(frozen=True)
class Principal:
    """The verified identity carried by an access token.

    Only claims the Authentication Service actually puts in its tokens are
    read; unknown claims are ignored.
    """

    user_id: int
    roles: frozenset[str] = field(default_factory=frozenset)
    email: str | None = None
    account_type: str | None = None

    @property
    def is_admin(self) -> bool:
        """True when a role claim maps to a configured admin role."""

        normalized = {role.strip().lower() for role in self.roles}
        return bool(normalized.intersection(settings.admin_role_set))


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers=AUTHENTICATE_HEADER,
    )


def _forbidden(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def _parse_user_id(subject: Any) -> int:
    if subject is None or isinstance(subject, bool):
        raise ValueError

    user_id = int(str(subject).strip())
    if user_id < 1:
        raise ValueError

    return user_id


def _extract_roles(payload: dict[str, Any]) -> frozenset[str]:
    raw: list[Any] = []

    for claim in ("roles", "role", "account_type"):
        value = payload.get(claim)
        if isinstance(value, str):
            raw.append(value)
        elif isinstance(value, (list, tuple, set)):
            raw.extend(item for item in value if isinstance(item, str))

    return frozenset(item.strip().lower() for item in raw if item.strip())


def decode_token(token: str) -> dict[str, Any]:
    """Verify signature, algorithm, expiry and registered claims.

    Raises ``HTTPException(401)`` for every failure mode so the reason is never
    leaked to the caller beyond a generic message.
    """

    decode_kwargs: dict[str, Any] = {}
    if settings.jwt_audience_or_none:
        decode_kwargs["audience"] = settings.jwt_audience_or_none
    if settings.jwt_issuer_or_none:
        decode_kwargs["issuer"] = settings.jwt_issuer_or_none

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"verify_aud": bool(settings.jwt_audience_or_none)},
            **decode_kwargs,
        )
    except (JWTError, TypeError, ValueError) as exc:
        raise _unauthorized("Invalid or expired token") from exc

    if not isinstance(payload, dict):
        raise _unauthorized("Invalid token")

    return payload


def get_token_payload(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
) -> dict[str, Any]:
    """FastAPI dependency: ``Authorization: Bearer <JWT>`` -> decoded claims."""

    if credentials is None:
        raise _unauthorized("Not authenticated")

    if (credentials.scheme or "").lower() != "bearer":
        raise _unauthorized("Not authenticated")

    return decode_token(credentials.credentials)


def get_current_user_id(
    payload: Annotated[dict[str, Any], Depends(get_token_payload)],
) -> int:
    """FastAPI dependency: the ``sub`` claim as a positive integer id."""

    subject = payload.get("sub")
    if subject is None or subject == "":
        raise _unauthorized("Invalid token")

    try:
        return _parse_user_id(subject)
    except (TypeError, ValueError) as exc:
        raise _unauthorized("Invalid token") from exc


def get_current_principal(
    payload: Annotated[dict[str, Any], Depends(get_token_payload)],
) -> Principal:
    """FastAPI dependency: the verified caller identity."""

    user_id = get_current_user_id(payload)
    roles = _extract_roles(payload)

    return Principal(
        user_id=user_id,
        roles=roles,
        email=payload.get("email") if isinstance(payload.get("email"), str) else None,
        account_type=(
            payload.get("account_type")
            if isinstance(payload.get("account_type"), str)
            else None
        ),
    )


def require_admin(
    principal: Annotated[Principal, Depends(get_current_principal)],
) -> Principal:
    """FastAPI dependency: the caller must hold an admin-level role."""

    if not principal.is_admin:
        raise _forbidden("Admin-level permissions are required")

    return principal


def get_current_user_record(
    db: Annotated[Session, Depends(get_db)],
    principal: Annotated[Principal, Depends(get_current_principal)],
) -> User:
    """FastAPI dependency: the caller's own, active user record."""

    user = get_user(db, principal.user_id)

    if not user.is_active:
        raise _forbidden("User account is deactivated")

    return user


def require_internal_api_key(
    x_internal_api_key: Annotated[
        str | None,
        Header(
            alias="X-Internal-API-Key",
            description="Shared service-to-service credential.",
        ),
    ] = None,
) -> None:
    """FastAPI dependency guarding the internal Authentication Service routes.

    The credential only ever comes from configuration; it is never hardcoded
    and never returned in a response.
    """

    expected = settings.internal_api_key.strip()
    if not expected:
        raise InternalApiDisabledError

    if not x_internal_api_key:
        raise _unauthorized("Missing internal API key")

    if not secrets.compare_digest(x_internal_api_key, expected):
        raise _unauthorized("Invalid internal API key")


def ensure_can_access_user(
    principal: Principal,
    target_user_id: int,
) -> None:
    """Allow self access, or any access for an admin-level caller."""

    if principal.user_id == target_user_id or principal.is_admin:
        return

    raise _forbidden("You are not allowed to access this user")


__all__ = [
    "Principal",
    "AUTHENTICATE_HEADER",
    "bearer_scheme",
    "decode_token",
    "ensure_can_access_user",
    "get_current_user_id",
    "get_current_user_record",
    "get_current_principal",
    "get_token_payload",
    "require_admin",
    "require_internal_api_key",
]
