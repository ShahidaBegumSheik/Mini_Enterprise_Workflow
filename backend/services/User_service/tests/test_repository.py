"""Repository layer: every database operation used by the service."""

import pytest
from sqlalchemy.orm import Session

from app.models.user import User
from app.repositories.user_repository import (
    PROFILE_FIELDS,
    PROTECTED_FIELDS,
    count_users,
    create_user,
    get_user_by_email,
    get_user_by_id,
    get_user_by_ids,
    list_users,
    set_user_status,
    update_user,
)
from tests.conftest import seed_user


def test_get_user_by_id_returns_the_user(db: Session) -> None:
    user = seed_user(db)

    assert get_user_by_id(db, user.id) is not None
    assert get_user_by_id(db, user.id).email == user.email


def test_get_user_by_id_returns_none_when_missing(db: Session) -> None:
    seed_user(db)

    assert get_user_by_id(db, 424242) is None


def test_get_user_by_email(db: Session) -> None:
    user = seed_user(db)

    assert get_user_by_email(db, user.email).id == user.id
    assert get_user_by_email(db, "  nobody@example.com  ") is None


def test_get_user_by_ids_preserves_order(db: Session) -> None:
    seed_user(db, 1)
    seed_user(db, 2)
    seed_user(db, 3)

    found = get_user_by_ids(db, [3, 1, 99])

    assert [user.id for user in found] == [3, 1]


def test_get_user_by_ids_with_empty_input(db: Session) -> None:
    seed_user(db)

    assert get_user_by_ids(db, []) == []


def test_list_users_paginates(db: Session) -> None:
    for index in range(1, 6):
        seed_user(db, index)

    first_page = list_users(db, page=1, page_size=2)
    second_page = list_users(db, page=2, page_size=2)
    overflow = list_users(db, page=99, page_size=2)

    assert [user.id for user in first_page] == [1, 2]
    assert [user.id for user in second_page] == [3, 4]
    assert overflow == []


def test_list_users_filters(db: Session) -> None:
    seed_user(db, 1, email="ada@example.com", first_name="Ada")
    seed_user(db, 2, email="grace@example.com", first_name="Grace", is_active=False)

    assert [user.id for user in list_users(db, is_active=True)] == [1]
    assert [user.id for user in list_users(db, is_active=False)] == [2]
    assert [user.id for user in list_users(db, search="grace")] == [2]
    assert [user.id for user in list_users(db, search="ada@example")] == [1]
    assert list_users(db, search="nobody") == []


def test_count_users(db: Session) -> None:
    assert count_users(db) == 0

    seed_user(db, 1)
    seed_user(db, 2)
    seed_user(db, 3, is_active=False)

    assert count_users(db) == 3
    assert count_users(db, is_active=True) == 2
    assert count_users(db, is_active=False) == 1
    assert count_users(db, search="user2") == 1


def test_create_user(db: Session) -> None:
    user = create_user(
        db,
        email="  new@example.com  ",
        first_name="New",
        last_name="User",
    )

    assert user.id is not None
    assert user.email == "new@example.com"
    assert user.is_active is True
    assert user.created_at is not None
    assert user.updated_at is not None
    assert get_user_by_email(db, "new@example.com") is not None


def test_create_user_rejects_duplicate_email(db: Session) -> None:
    seed_user(db, 1, email="taken@example.com")

    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        create_user(db, email="taken@example.com", first_name="Copy")
    db.rollback()


def test_update_user_applies_only_allowed_fields(db: Session) -> None:
    user = seed_user(db)

    updated = update_user(db, user, {"first_name": "Grace", "bio": "New bio"})

    assert updated.first_name == "Grace"
    assert updated.bio == "New bio"
    assert updated.email == user.email
    assert get_user_by_id(db, user.id).first_name == "Grace"


def test_update_user_refreshes_updated_at(db: Session) -> None:
    user = seed_user(db)
    original = user.updated_at

    updated = update_user(db, user, {"bio": "Touched"})

    assert updated.updated_at >= original


@pytest.mark.parametrize("field", sorted(PROTECTED_FIELDS))
def test_update_user_rejects_protected_fields(db: Session, field: str) -> None:
    user = seed_user(db)

    with pytest.raises(ValueError):
        update_user(db, user, {field: "hacked"})

    db.rollback()
    assert getattr(get_user_by_id(db, user.id), field) == getattr(user, field)


def test_update_user_all_fields_together_is_rejected(db: Session) -> None:
    user = seed_user(db)

    with pytest.raises(ValueError):
        update_user(
            db,
            user,
            {**dict.fromkeys(PROFILE_FIELDS, "ok"), "is_active": False},
            allowed_fields=PROFILE_FIELDS,
        )

    db.rollback()


def test_update_user_accepts_status_fields_when_allowed(db: Session) -> None:
    user = seed_user(db)

    updated = update_user(
        db,
        user,
        {"is_active": False},
        allowed_fields=("is_active",),
    )

    assert updated.is_active is False


def test_set_user_status(db: Session) -> None:
    user = seed_user(db)

    deactivated = set_user_status(db, user, False)
    assert deactivated.is_active is False
    assert get_user_by_id(db, user.id).is_active is False

    reactivated = set_user_status(db, deactivated, True)

    assert reactivated.is_active is True
    assert get_user_by_id(db, user.id).is_active is True


def test_repository_round_trip_preserves_created_at(db: Session) -> None:
    user = seed_user(db)
    created_at = user.created_at

    update_user(db, user, {"bio": "Changed"})

    assert get_user_by_id(db, user.id).created_at == created_at


def test_user_model_has_no_credential_columns() -> None:
    columns = set(User.__table__.columns.keys())

    for forbidden in ("password", "password_hash", "token", "refresh_token", "otp"):
        assert forbidden not in columns
