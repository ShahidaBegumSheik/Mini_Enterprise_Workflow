from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from app.models.user import User


#: Profile fields a request body is allowed to change.
PROFILE_FIELDS: tuple[str, ...] = (
    "first_name",
    "last_name",
    "phone_number",
    "bio",
)

#: Field allowed by the status endpoint.
STATUS_FIELDS: tuple[str, ...] = ("is_active",)

#: Never writable through any code path in this service.
PROTECTED_FIELDS: frozenset[str] = frozenset(
    {
        "id",
        "email",
        "is_active",
        "created_at",
        "updated_at",
    }
)


def _apply_filters(
    statement: Select[tuple[User]],
    *,
    is_active: bool | None = None,
    search: str | None = None,
) -> Select[tuple[User]]:
    if is_active is not None:
        statement = statement.where(User.is_active.is_(is_active))

    if search:
        pattern = f"%{search.strip()}%"
        statement = statement.where(
            or_(
                User.email.like(pattern),
                User.first_name.like(pattern),
                User.last_name.like(pattern),
            )
        )

    return statement


def get_user_by_id(db: Session, user_id: int) -> User | None:
    """Return a single user by primary key, or ``None``."""

    return db.get(User, user_id)


def get_user_by_email(db: Session, email: str) -> User | None:
    """Return a single user by email, or ``None``."""

    statement = select(User).where(User.email == email.strip())

    return db.scalar(statement)


def get_user_by_ids(db: Session, user_ids: Sequence[int]) -> list[User]:
    """Return the users matching ``user_ids`` (empty input yields no query)."""

    if not user_ids:
        return []

    statement = select(User).where(User.id.in_(list(user_ids)))
    by_id = {user.id: user for user in db.scalars(statement)}

    return [by_id[user_id] for user_id in user_ids if user_id in by_id]


def list_users(
    db: Session,
    *,
    page: int = 1,
    page_size: int = 20,
    is_active: bool | None = None,
    search: str | None = None,
) -> list[User]:
    """Return one page of users ordered by ``id`` (stable pagination)."""

    statement = _apply_filters(
        select(User),
        is_active=is_active,
        search=search,
    ).order_by(User.id)

    offset = (max(page, 1) - 1) * max(page_size, 1)

    return list(db.scalars(statement.limit(page_size).offset(offset)))


def count_users(
    db: Session,
    *,
    is_active: bool | None = None,
    search: str | None = None,
) -> int:
    """Return the total number of users matching the same filters."""

    statement = _apply_filters(
        select(func.count()).select_from(User),
        is_active=is_active,
        search=search,
    )

    return int(db.scalar(statement) or 0)


def create_user(
    db: Session,
    *,
    email: str,
    first_name: str,
    last_name: str | None = None,
    phone_number: str | None = None,
    bio: str | None = None,
    is_active: bool = True,
) -> User:
    """Insert a new user profile. No password or token material is stored."""

    user = User(
        email=email.strip(),
        first_name=first_name,
        last_name=last_name,
        phone_number=phone_number,
        bio=bio,
        is_active=is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def update_user(
    db: Session,
    user: User,
    data: Mapping[str, Any],
    *,
    allowed_fields: Sequence[str] = PROFILE_FIELDS,
) -> User:
    """Apply ``data`` to ``user`` and persist it.

    ``allowed_fields`` is an allow-list: any key outside it (in particular the
    protected ``id`` / ``email`` / ``is_active`` / timestamps) raises before
    anything is written.
    """

    allowed = frozenset(allowed_fields)
    rejected = sorted(set(data) - allowed)
    if rejected:
        raise ValueError(
            f"Fields cannot be updated: {', '.join(rejected)}"
        )

    for field, value in data.items():
        setattr(user, field, value)

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def set_user_status(db: Session, user: User, is_active: bool) -> User:
    """Activate or deactivate a user."""

    return update_user(
        db,
        user,
        {"is_active": bool(is_active)},
        allowed_fields=STATUS_FIELDS,
    )
