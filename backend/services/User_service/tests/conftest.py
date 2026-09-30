"""Shared test fixtures.

The suite runs against an in-memory SQLite database so it never touches the
MySQL instance used in development. ``Base.metadata.create_all`` builds the
same tables the Alembic migrations create, which keeps the tests fast and
side-effect free.
"""

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.database.base import Base
from app.database.session import get_db
from app.main import app
from app.models.user import User


TEST_DATABASE_URL = "sqlite+pysqlite:///:memory:"

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def create_token(
    user_id: int | str | None = 1,
    *,
    expires_at: datetime | None = None,
    roles: list[str] | None = None,
    email: str | None = None,
    extra_claims: dict[str, Any] | None = None,
    secret: str | None = None,
    algorithm: str | None = None,
) -> str:
    """Build a token shaped like the ones the Authentication Service issues."""

    claims: dict[str, Any] = {}
    if user_id is not None:
        claims["sub"] = str(user_id)
    if expires_at is not None:
        claims["exp"] = expires_at
    else:
        claims["exp"] = datetime.now(timezone.utc) + timedelta(minutes=15)
    if roles:
        claims["roles"] = roles
    if email:
        claims["email"] = email
    if extra_claims:
        claims.update(extra_claims)

    return jwt.encode(
        claims,
        secret or settings.jwt_secret_key,
        algorithm=algorithm or settings.jwt_algorithm,
    )


def auth_headers(
    user_id: int | str = 1,
    *,
    roles: list[str] | None = None,
) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_token(user_id, roles=roles)}"}


def seed_user(
    db: Session,
    user_id: int = 1,
    *,
    email: str | None = None,
    first_name: str = "Ada",
    last_name: str | None = "Lovelace",
    phone_number: str | None = "+15551234567",
    bio: str | None = "Original bio",
    is_active: bool = True,
) -> User:
    user = User(
        id=user_id,
        email=email or f"user{user_id}@example.com",
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


def reload_user(db: Session, user_id: int) -> User:
    """Re-read a row written by the request's own session.

    The API under test uses its own ``Session``; the fixture session may still
    hold the previously loaded instance in its identity map.
    """

    db.expire_all()
    return db.get(User, user_id)


@pytest.fixture(autouse=True)
def reset_database() -> Iterator[None]:
    Base.metadata.create_all(bind=engine)
    try:
        yield
    finally:
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def override_get_db() -> Iterator[None]:
    def _override() -> Iterator[Session]:
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override
    try:
        yield
    finally:
        app.dependency_overrides.clear()


@pytest.fixture()
def client(override_get_db: None) -> Iterator[TestClient]:
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture()
def db() -> Iterator[Session]:
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
