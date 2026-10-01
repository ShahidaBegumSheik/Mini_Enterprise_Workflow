from typing import Any

from fastapi import Depends

from app.core.security import (
    verify_access_token,
    verify_internal_api_key,
)


def require_internal_api_key(
    _: str = Depends(verify_internal_api_key),
) -> None:
    return None


def require_authenticated_user(
    _: str = Depends(verify_internal_api_key),
    token_payload: dict[str, Any] = Depends(verify_access_token),
) -> dict[str, Any]:
    return token_payload