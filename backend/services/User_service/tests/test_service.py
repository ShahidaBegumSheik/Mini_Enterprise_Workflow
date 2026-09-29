"""Service layer: business rules, error mapping and authorization."""

import ast
from pathlib import Path

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.exceptions import (
    DatabaseOperationError,
    PermissionDeniedError,
    UserConflictError,
    UserNotFoundError,
)
from app.schemas.user import UserListResponse
from app.services import user_service
from tests.conftest import seed_user


MODULE_NAME = user_service.__name__.rsplit(".", 1)[-1]
ADMIN_ROLES = ("admin",)


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


def test_get_user_returns_the_user(db: Session) -> None:
    user = seed_user(db)

    assert user_service.get_user(db, user.id).id == user.id


def test_get_user_raises_user_not_found(db: Session) -> None:
    seed_user(db)

    with pytest.raises(UserNotFoundError):
        user_service.get_user(db, 424242)


def test_get_user_by_email_address(db: Session) -> None:
    user = seed_user(db)

    assert user_service.get_user_by_email_address(db, user.email).id == user.id

    with pytest.raises(UserNotFoundError):
        user_service.get_user_by_email_address(db, "nobody@example.com")


def test_get_current_user_rejects_deactivated(db: Session) -> None:
    user = seed_user(db, is_active=False)

    with pytest.raises(PermissionDeniedError):
        user_service.get_current_user(db, user.id)


def test_database_failure_is_wrapped(
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise SQLAlchemyError("connection refused")

    monkeypatch.setattr(user_service, "get_user_by_id", boom)

    with pytest.raises(DatabaseOperationError):
        user_service.get_user(db, 1)


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------


def test_list_users_returns_paginated_response(db: Session) -> None:
    for index in range(1, 4):
        seed_user(db, index)

    result = user_service.list_users(db, actor_id=1, page=1, page_size=2)

    assert isinstance(result, UserListResponse)
    assert result.total == 3
    assert result.page == 1
    assert result.page_size == 2
    assert result.pages == 2
    assert [item.id for item in result.items] == [1, 2]


def test_list_users_with_no_data(db: Session) -> None:
    # The caller is an active user, so the filter still has to match nothing.
    actor = seed_user(db, 1, is_active=True)

    result = user_service.list_users(db, actor_id=actor.id, is_active=False)

    assert result.items == []
    assert result.total == 0
    assert result.pages == 0


def test_list_users_items_never_include_credentials(db: Session) -> None:
    actor = seed_user(db)

    result = user_service.list_users(db, actor_id=actor.id, page=1, page_size=20)

    assert set(result.items[0].model_dump()) == {
        "id",
        "email",
        "first_name",
        "last_name",
        "phone_number",
        "bio",
        "is_active",
        "created_at",
        "updated_at",
    }


# ---------------------------------------------------------------------------
# Profile updates
# ---------------------------------------------------------------------------


def test_update_current_profile(db: Session) -> None:
    user = seed_user(db)

    updated = user_service.update_current_profile(
        db,
        user.id,
        {"first_name": "Grace"},
    )

    assert updated.first_name == "Grace"
    assert updated.email == user.email


def test_update_current_profile_unknown_user(db: Session) -> None:
    seed_user(db)

    with pytest.raises(UserNotFoundError):
        user_service.update_current_profile(db, 424242, {"first_name": "Ghost"})


def test_update_user_allows_self(db: Session) -> None:
    user = seed_user(db)

    updated = user_service.update_user(
        db,
        actor_id=user.id,
        target_id=user.id,
        data={"bio": "Self"},
    )

    assert updated.bio == "Self"


def test_update_user_allows_admin(db: Session) -> None:
    admin = seed_user(db, 1, email="admin@example.com")
    target = seed_user(db, 2, email="member@example.com")

    updated = user_service.update_user(
        db,
        actor_id=admin.id,
        target_id=target.id,
        data={"bio": "Managed"},
        actor_roles=["admin"],
        admin_roles=ADMIN_ROLES,
    )

    assert updated.bio == "Managed"


def test_update_user_forbids_non_admin(db: Session) -> None:
    seed_user(db, 1, email="one@example.com")
    target = seed_user(db, 2, email="two@example.com")

    with pytest.raises(PermissionDeniedError):
        user_service.update_user(
            db,
            actor_id=1,
            target_id=target.id,
            data={"bio": "Hacked"},
            actor_roles=["employee"],
            admin_roles=ADMIN_ROLES,
        )


def test_update_user_role_check_is_case_insensitive(db: Session) -> None:
    admin = seed_user(db, 1, email="admin@example.com")
    target = seed_user(db, 2, email="member@example.com")

    updated = user_service.update_user(
        db,
        actor_id=admin.id,
        target_id=target.id,
        data={"bio": "Managed"},
        actor_roles=["ADMIN"],
        admin_roles=ADMIN_ROLES,
    )

    assert updated.bio == "Managed"


# ---------------------------------------------------------------------------
# Status management
# ---------------------------------------------------------------------------


def test_update_user_status_requires_admin_role(db: Session) -> None:
    seed_user(db, 1, email="one@example.com")
    target = seed_user(db, 2, email="two@example.com")

    with pytest.raises(PermissionDeniedError):
        user_service.update_user_status(
            db,
            actor_id=1,
            target_id=target.id,
            is_active=False,
            actor_roles=["employee"],
            admin_roles=ADMIN_ROLES,
        )

    assert user_service.get_user(db, target.id).is_active is True


def test_update_user_status_as_admin(db: Session) -> None:
    admin = seed_user(db, 1, email="admin@example.com")
    target = seed_user(db, 2, email="member@example.com")

    updated = user_service.update_user_status(
        db,
        actor_id=admin.id,
        target_id=target.id,
        is_active=False,
        actor_roles=["admin"],
        admin_roles=ADMIN_ROLES,
    )

    assert updated.is_active is False


def test_update_user_status_unknown_user(db: Session) -> None:
    admin = seed_user(db, 1, email="admin@example.com")

    with pytest.raises(UserNotFoundError):
        user_service.update_user_status(
            db,
            actor_id=admin.id,
            target_id=424242,
            is_active=False,
            actor_roles=["admin"],
            admin_roles=ADMIN_ROLES,
        )


# ---------------------------------------------------------------------------
# Deactivated callers
# ---------------------------------------------------------------------------


def test_list_users_rejects_deactivated_actor(db: Session) -> None:
    seed_user(db, 1, is_active=False)

    with pytest.raises(PermissionDeniedError) as excinfo:
        user_service.list_users(db, actor_id=1)

    assert excinfo.value.status_code == 403
    assert excinfo.value.detail == "User account is deactivated"


def test_update_current_profile_rejects_deactivated_user(db: Session) -> None:
    user = seed_user(db, is_active=False)

    with pytest.raises(PermissionDeniedError) as excinfo:
        user_service.update_current_profile(db, user.id, {"first_name": "Ghost"})

    assert excinfo.value.status_code == 403
    assert user_service.get_user(db, user.id).first_name == "Ada"


def test_update_user_rejects_deactivated_actor(db: Session) -> None:
    actor = seed_user(db, 1, is_active=False)
    target = seed_user(db, 2)

    with pytest.raises(PermissionDeniedError) as excinfo:
        user_service.update_user(
            db,
            actor_id=actor.id,
            target_id=target.id,
            data={"first_name": "Overwritten"},
            actor_roles=["admin"],
            admin_roles=ADMIN_ROLES,
        )

    assert excinfo.value.status_code == 403
    assert user_service.get_user(db, target.id).first_name == "Ada"


def test_update_user_rejects_deactivated_self_updater(db: Session) -> None:
    user = seed_user(db, is_active=False)

    with pytest.raises(PermissionDeniedError) as excinfo:
        user_service.update_user(
            db,
            actor_id=user.id,
            target_id=user.id,
            data={"first_name": "Overwritten"},
            actor_roles=[],
            admin_roles=ADMIN_ROLES,
        )

    assert excinfo.value.status_code == 403


def test_update_user_status_rejects_deactivated_admin(db: Session) -> None:
    admin = seed_user(db, 1, is_active=False)
    target = seed_user(db, 2)

    with pytest.raises(PermissionDeniedError) as excinfo:
        user_service.update_user_status(
            db,
            actor_id=admin.id,
            target_id=target.id,
            is_active=False,
            actor_roles=["admin"],
            admin_roles=ADMIN_ROLES,
        )

    assert excinfo.value.status_code == 403
    assert user_service.get_user(db, target.id).is_active is True


def test_non_admin_actor_still_gets_the_admin_error(db: Session) -> None:
    """A deactivated non-admin must not mask the missing-role error."""

    seed_user(db, 1, is_active=False)
    seed_user(db, 2)

    with pytest.raises(PermissionDeniedError) as excinfo:
        user_service.update_user_status(
            db,
            actor_id=1,
            target_id=2,
            is_active=False,
            actor_roles=[],
            admin_roles=ADMIN_ROLES,
        )

    assert excinfo.value.detail == (
        "Admin-level permissions are required to change user status"
    )


def test_internal_bootstrap_still_reactivates_a_deactivated_user(
    db: Session,
) -> None:
    """The internal contract must be able to bring a user back."""

    user = seed_user(db, is_active=False)

    assert user_service.bootstrap_user(db, user.id).is_active is True
    assert user_service.list_users(db, actor_id=user.id).total == 1


# ---------------------------------------------------------------------------
# Internal contract helpers
# ---------------------------------------------------------------------------


def test_bootstrap_user_activates_inactive_profile(db: Session) -> None:
    user = seed_user(db, is_active=False)

    bootstrapped = user_service.bootstrap_user(db, user.id)

    assert bootstrapped.is_active is True
    assert user_service.bootstrap_user(db, user.id).is_active is True


def test_create_user_profile_normalizes_email(db: Session) -> None:
    user = user_service.create_user_profile(
        db,
        email="  New@Example.COM  ",
        first_name="New",
        last_name="User",
    )

    assert user.email == "new@example.com"
    assert user.is_active is True


def test_create_user_profile_rejects_duplicates(db: Session) -> None:
    seed_user(db, 1, email="taken@example.com")

    with pytest.raises(UserConflictError):
        user_service.create_user_profile(
            db,
            email="taken@example.com",
            first_name="Copy",
        )


def test_sync_user_from_event_updates_status(db: Session) -> None:
    user = seed_user(db)

    synced = user_service.sync_user_from_event(
        db,
        user,
        {"is_active": False},
        is_status_change=True,
    )

    assert synced.is_active is False


def test_sync_user_from_event_updates_names(db: Session) -> None:
    user = seed_user(db)

    synced = user_service.sync_user_from_event(
        db,
        user,
        {"first_name": "Synced", "last_name": "Name"},
    )

    assert synced.first_name == "Synced"
    assert synced.last_name == "Name"


# ---------------------------------------------------------------------------
# No accidental self-recursion
# ---------------------------------------------------------------------------


def _self_calls(function: ast.FunctionDef) -> list[str]:
    """Names called inside ``function`` that resolve back to ``function``."""

    found: list[str] = []

    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue

        target = node.func
        if isinstance(target, ast.Name):
            if target.id == function.name:
                found.append(target.id)
        elif isinstance(target, ast.Attribute):
            owner = target.value
            is_self_reference = (
                isinstance(owner, ast.Name) and owner.id in {"self", "cls"}
            ) or (
                isinstance(owner, ast.Name) and owner.id == MODULE_NAME
            )
            if is_self_reference and target.attr == function.name:
                found.append(target.attr)

    return found


def test_no_service_function_calls_itself() -> None:
    source = Path(user_service.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    offenders = {
        node.name: _self_calls(node)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and _self_calls(node)
    }

    assert offenders == {}


def test_public_service_api_is_exported() -> None:
    expected = {
        "get_user",
        "get_current_user",
        "get_user_by_email_address",
        "list_users",
        "update_current_profile",
        "update_user",
        "update_user_status",
        "create_user_profile",
        "bootstrap_user",
        "sync_user_from_event",
    }

    assert expected.issubset(set(dir(user_service)))
