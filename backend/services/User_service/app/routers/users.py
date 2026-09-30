from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy.orm import Session

from app.core.config import settings
from app.dependencies.auth import Principal, ensure_can_access_user
from app.dependencies.auth import get_current_principal as get_principal
from app.dependencies.auth import get_current_user_record
from app.database.session import get_db
from app.models.user import User
from app.schemas.user import (
    UserListResponse,
    UserProfileUpdate,
    UserResponse,
    UserStatusUpdate,
    UserUpdate,
)
from app.services import user_service


router = APIRouter(
    prefix="/users",
    tags=["Users"],
)

CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
CurrentUser = Annotated[User, Depends(get_current_user_record)]
DbSession = Annotated[Session, Depends(get_db)]
UserIdPath = Annotated[
    int,
    Path(
        ge=1,
        description="Numeric user identifier taken from the JWT subject.",
        examples=[1],
    ),
]

ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"description": "Missing, malformed, or invalid/expired JWT"},
    403: {"description": "Authenticated but insufficient permissions"},
    404: {"description": "User not found"},
    422: {"description": "Request validation error"},
    503: {"description": "Database operation failed"},
}

PROFILE_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    code: detail for code, detail in ERROR_RESPONSES.items() if code != 404
}


@router.get(
    "/profile",
    response_model=UserResponse,
    summary="Get the current user profile",
    description=(
        "Returns the profile of the user identified by the `sub` claim of the "
        "JWT issued by the Authentication Service."
    ),
    responses=PROFILE_ERROR_RESPONSES,
)
def read_current_profile(current_user: CurrentUser) -> UserResponse:
    return UserResponse.model_validate(current_user)


@router.put(
    "/profile",
    response_model=UserResponse,
    summary="Update the current user profile",
    description=(
        "Updates the editable profile fields of the authenticated user. "
        "`id`, `email`, `is_active` and the timestamps are rejected."
    ),
    responses=ERROR_RESPONSES,
)
def update_current_profile(
    payload: UserProfileUpdate,
    db: DbSession,
    current_user: CurrentUser,
) -> UserResponse:
    user = user_service.update_current_profile(
        db=db,
        user_id=current_user.id,
        data=payload.model_dump(exclude_unset=True),
    )

    return UserResponse.model_validate(user)


@router.get(
    "",
    response_model=UserListResponse,
    summary="List users",
    description="Returns a paginated list of user profiles.",
    responses=ERROR_RESPONSES,
)
def list_users(
    db: DbSession,
    current_user: CurrentUser,
    page: Annotated[int, Query(ge=1, description="1-based page number.")] = 1,
    page_size: Annotated[
        int,
        Query(
            ge=1,
            le=settings.max_page_size,
            description="Number of records per page.",
        ),
    ] = settings.default_page_size,
    is_active: Annotated[
        bool | None,
        Query(description="Filter on the account status."),
    ] = None,
    search: Annotated[
        str | None,
        Query(min_length=1, max_length=100, description="Filter on email or name."),
    ] = None,
) -> UserListResponse:
    return user_service.list_users(
        db=db,
        actor_id=current_user.id,
        page=page,
        page_size=page_size,
        is_active=is_active,
        search=search,
    )


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get a user by id",
    description=(
        "Returns a single user profile. A user may always read their own "
        "record; reading another user's record requires an admin-level role."
    ),
    responses=ERROR_RESPONSES,
)
def read_user(
    user_id: UserIdPath,
    db: DbSession,
    principal: CurrentPrincipal,
    _current_user: CurrentUser,
) -> UserResponse:
    ensure_can_access_user(principal, user_id)

    user = user_service.get_user(db, user_id)

    return UserResponse.model_validate(user)


@router.put(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update a user by id",
    description=(
        "Updates the editable profile fields of a user. Self-service is "
        "allowed; modifying another user requires an admin-level role. "
        "`id`, `email`, `is_active` and the timestamps are rejected."
    ),
    responses=ERROR_RESPONSES,
)
def update_user(
    user_id: UserIdPath,
    payload: UserUpdate,
    db: DbSession,
    principal: CurrentPrincipal,
    _current_user: CurrentUser,
) -> UserResponse:
    user = user_service.update_user(
        db=db,
        actor_id=principal.user_id,
        target_id=user_id,
        data=payload.model_dump(exclude_unset=True),
        actor_roles=principal.roles,
        admin_roles=settings.admin_role_set,
    )

    return UserResponse.model_validate(user)


@router.patch(
    "/{user_id}/status",
    response_model=UserResponse,
    summary="Activate or deactivate a user",
    description=(
        "Flips the `is_active` flag of a user. Requires an admin-level role."
    ),
    responses=ERROR_RESPONSES,
)
def update_user_status(
    user_id: UserIdPath,
    payload: UserStatusUpdate,
    db: DbSession,
    principal: CurrentPrincipal,
    _current_user: CurrentUser,
) -> UserResponse:
    user = user_service.update_user_status(
        db=db,
        actor_id=principal.user_id,
        target_id=user_id,
        is_active=payload.is_active,
        actor_roles=principal.roles,
        admin_roles=settings.admin_role_set,
    )

    return UserResponse.model_validate(user)


__all__ = ["router"]
