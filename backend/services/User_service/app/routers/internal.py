"""Service-to-service endpoints consumed by the Authentication Service.

These routes implement the contract declared in the Authentication Service
``UserServiceContract`` (registration flow). They are not part of the public
user API: they are authenticated with the shared internal API key coming from
configuration, never with a user JWT, and they are disabled entirely when no
key is configured.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Path, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.dependencies.auth import require_internal_api_key
from app.schemas.internal import (
    InternalAccepted,
    InternalNotification,
    InternalUserCreate,
    InternalUserResponse,
    InternalUserSync,
)
from app.services import user_service


router = APIRouter(
    prefix="/api/v1/internal",
    tags=["Internal"],
    dependencies=[Depends(require_internal_api_key)],
)

DbSession = Annotated[Session, Depends(get_db)]
InternalUserId = Annotated[int, Path(ge=1, description="Numeric user identifier.")]

ERROR_RESPONSES: dict[int | str, dict[str, str]] = {
    401: {"description": "Missing or invalid internal API key"},
    404: {"description": "User not found"},
    409: {"description": "User already exists"},
    422: {"description": "Request validation error"},
    503: {"description": "Internal API disabled or database operation failed"},
}


@router.post(
    "/users",
    response_model=InternalUserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a user profile (internal)",
    description=(
        "Creates the profile owned by this service. Called by the "
        "Authentication Service once registration is verified. No credential "
        "material is accepted or stored here."
    ),
    responses=ERROR_RESPONSES,
)
def create_user(
    payload: InternalUserCreate,
    db: DbSession,
) -> InternalUserResponse:
    first_name, last_name = payload.split_name()
    user = user_service.create_user_profile(
        db=db,
        email=payload.email,
        first_name=first_name,
        last_name=last_name,
        is_active=payload.is_active,
    )

    return InternalUserResponse.from_user(user)


@router.get(
    "/users/{user_id}",
    response_model=InternalUserResponse,
    summary="Fetch a user profile (internal)",
    responses=ERROR_RESPONSES,
)
def get_user(user_id: InternalUserId, db: DbSession) -> InternalUserResponse:
    user = user_service.get_user(db, user_id)

    return InternalUserResponse.from_user(user)


@router.post(
    "/users/{user_id}/bootstrap",
    response_model=InternalUserResponse,
    summary="Bootstrap a user profile (internal)",
    description="Marks the profile as usable; idempotent.",
    responses=ERROR_RESPONSES,
)
def bootstrap_user(
    user_id: InternalUserId,
    db: DbSession,
) -> InternalUserResponse:
    user = user_service.bootstrap_user(db, user_id)

    return InternalUserResponse.from_user(user)


@router.post(
    "/sync/users/{user_id}",
    response_model=InternalAccepted,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive a user sync event (internal)",
    description="Best-effort endpoint; it never fails the caller's operation.",
    responses=ERROR_RESPONSES,
)
def sync_user(
    user_id: InternalUserId,
    payload: InternalUserSync,
    db: DbSession,
) -> InternalAccepted:
    user = user_service.get_user(db, user_id)
    data: dict[str, object] = {}

    if payload.action in {"activated", "deactivated"}:
        data = {"is_active": payload.action == "activated"}
    elif payload.action == "updated" and payload.full_name:
        parts = payload.full_name.split()
        data = {
            "first_name": parts[0][:100],
            "last_name": (" ".join(parts[1:]) or None) if len(parts) > 1 else None,
        }

    if data:
        user = user_service.sync_user_from_event(
            db=db,
            user=user,
            data=data,
            is_status_change="is_active" in data,
        )

    return InternalAccepted(status="accepted")


@router.post(
    "/users/{user_id}/notifications",
    response_model=InternalAccepted,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Accept a notification request (internal)",
    description=(
        "Acknowledges a notification request forwarded by the Authentication "
        "Service. Delivery itself is owned by the Notification Service."
    ),
    responses=ERROR_RESPONSES,
)
def notify_user(
    user_id: InternalUserId,
    payload: InternalNotification,
    db: DbSession,
) -> InternalAccepted:
    user_service.get_user(db, user_id)

    return InternalAccepted(status="accepted")


__all__ = ["router"]
