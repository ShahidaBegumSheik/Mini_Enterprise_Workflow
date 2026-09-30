from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.exceptions import (
    DatabaseOperationError,
    PermissionDeniedError,
    UserConflictError,
    UserNotFoundError,
)
from app.models.user import User
from app.repositories.user_repository import (
    count_users as count_users_query,
)
from app.repositories.user_repository import (
    create_user as create_user_record,
)
from app.repositories.user_repository import get_user_by_email, get_user_by_id
from app.repositories.user_repository import (
    list_users as list_users_query,
)
from app.repositories.user_repository import (
    set_user_status as set_user_status_record,
)
from app.repositories.user_repository import (
    update_user as update_user_record,
)
from app.schemas.user import UserListResponse, UserResponse


# ---------------------------------------------------------------------------
# Internal helpers (private on purpose: no public function may call another
# public function of this module with the same intent, which is how the
# previous version could recurse into itself).
# ---------------------------------------------------------------------------


def _load_user_or_404(db: Session, user_id: int) -> User:
    try:
        user = get_user_by_id(db, user_id)
    except SQLAlchemyError as exc:
        db.rollback()
        raise DatabaseOperationError from exc

    if user is None:
        raise UserNotFoundError

    return user


def _apply_profile_update(
    db: Session,
    user: User,
    data: Mapping[str, Any],
) -> User:
    try:
        return update_user_record(db, user, data)
    except SQLAlchemyError as exc:
        db.rollback()
        raise DatabaseOperationError from exc


def _ensure_can_manage(
    *,
    actor_id: int,
    target_id: int,
    actor_roles: frozenset[str],
    admin_roles: frozenset[str],
) -> None:
    if actor_id == target_id:
        return

    if admin_roles.intersection(actor_roles):
        return

    raise PermissionDeniedError(
        "You are not allowed to modify this user",
    )


def _ensure_actor_is_active(db: Session, actor_id: int) -> User:
    """Reject a caller whose account has been deactivated.

    A deactivated account must not be able to act on the public API even while
    its access token is still within its expiry window. Internal, best-effort
    flows (bootstrap, sync) deliberately bypass this so they can bring a user
    back to life.
    """

    actor = _load_user_or_404(db, actor_id)

    if not actor.is_active:
        raise PermissionDeniedError("User account is deactivated")

    return actor


# ---------------------------------------------------------------------------
# Public service API
# ---------------------------------------------------------------------------


def get_user(db: Session, user_id: int) -> User:
    """Return a user by id or raise ``UserNotFoundError`` (404)."""

    return _load_user_or_404(db, user_id)


def get_user_by_email_address(db: Session, email: str) -> User:
    """Return a user by email or raise ``UserNotFoundError`` (404)."""

    try:
        user = get_user_by_email(db, email)
    except SQLAlchemyError as exc:
        db.rollback()
        raise DatabaseOperationError from exc

    if user is None:
        raise UserNotFoundError

    return user


def get_current_user(db: Session, user_id: int) -> User:
    """Return the profile behind the presented JWT subject."""

    user = _load_user_or_404(db, user_id)

    if not user.is_active:
        raise PermissionDeniedError("User account is deactivated")

    return user


def list_users(
    db: Session,
    *,
    actor_id: int,
    page: int = 1,
    page_size: int = 20,
    is_active: bool | None = None,
    search: str | None = None,
) -> UserListResponse:
    """Return one page of users plus the total matching count."""

    _ensure_actor_is_active(db, actor_id)

    try:
        users = list_users_query(
            db,
            page=page,
            page_size=page_size,
            is_active=is_active,
            search=search,
        )
        total = count_users_query(db, is_active=is_active, search=search)
    except SQLAlchemyError as exc:
        db.rollback()
        raise DatabaseOperationError from exc

    return UserListResponse.build(
        items=[UserResponse.model_validate(user) for user in users],
        total=total,
        page=page,
        page_size=page_size,
    )


def update_current_profile(
    db: Session,
    user_id: int,
    data: Mapping[str, Any],
) -> User:
    """Update the profile of the authenticated user."""

    user = _ensure_actor_is_active(db, user_id)
    return _apply_profile_update(db, user, data)


def update_user(
    db: Session,
    *,
    actor_id: int,
    target_id: int,
    data: Mapping[str, Any],
    actor_roles: Sequence[str] = (),
    admin_roles: Sequence[str] = (),
) -> User:
    """Update another user's profile, enforcing the ownership rules."""

    _ensure_actor_is_active(db, actor_id)

    _ensure_can_manage(
        actor_id=actor_id,
        target_id=target_id,
        actor_roles=frozenset(role.lower() for role in actor_roles),
        admin_roles=frozenset(role.lower() for role in admin_roles),
    )

    user = _load_user_or_404(db, target_id)
    return _apply_profile_update(db, user, data)


def update_user_status(
    db: Session,
    *,
    actor_id: int,
    target_id: int,
    is_active: bool,
    actor_roles: Sequence[str] = (),
    admin_roles: Sequence[str] = (),
) -> User:
    """Activate / deactivate a user. Requires an admin-level role."""

    normalized_roles = frozenset(role.lower() for role in actor_roles)
    normalized_admins = frozenset(role.lower() for role in admin_roles)

    if not normalized_roles.intersection(normalized_admins):
        raise PermissionDeniedError(
            "Admin-level permissions are required to change user status"
        )

    _ensure_actor_is_active(db, actor_id)

    _ensure_can_manage(
        actor_id=actor_id,
        target_id=target_id,
        actor_roles=normalized_roles,
        admin_roles=normalized_admins,
    )

    user = _load_user_or_404(db, target_id)
    try:
        return set_user_status_record(db, user, is_active)
    except SQLAlchemyError as exc:
        db.rollback()
        raise DatabaseOperationError from exc


def bootstrap_user(db: Session, user_id: int) -> User:
    """Idempotently mark a profile as usable. Used by the internal contract."""

    user = _load_user_or_404(db, user_id)

    if user.is_active:
        return user

    try:
        return set_user_status_record(db, user, True)
    except SQLAlchemyError as exc:
        db.rollback()
        raise DatabaseOperationError from exc


def sync_user_from_event(
    db: Session,
    user: User,
    data: Mapping[str, Any],
    *,
    is_status_change: bool = False,
) -> User:
    """Apply a best-effort sync event coming from the Authentication Service."""

    if not data:
        return user

    if is_status_change:
        return set_user_status_record(db, user, bool(data.get("is_active")))

    return _apply_profile_update(db, user, data)


def create_user_profile(
    db: Session,
    *,
    email: str,
    first_name: str,
    last_name: str | None = None,
    is_active: bool = True,
) -> User:
    """Create a profile on behalf of the Authentication Service."""

    normalized_email = email.strip().lower()

    try:
        existing = get_user_by_email(db, normalized_email)
    except SQLAlchemyError as exc:
        db.rollback()
        raise DatabaseOperationError from exc

    if existing is not None:
        raise UserConflictError("Email is already registered")

    try:
        return create_user_record(
            db,
            email=normalized_email,
            first_name=first_name,
            last_name=last_name,
            is_active=is_active,
        )
    except IntegrityError as exc:
        db.rollback()
        raise UserConflictError("Email is already registered") from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise DatabaseOperationError from exc
