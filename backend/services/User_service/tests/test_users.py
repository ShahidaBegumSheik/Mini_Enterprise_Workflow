from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session, sessionmaker

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


def create_token(user_id: int | str) -> str:
    return jwt.encode(
        {"sub": str(user_id)},
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def override_get_db() -> Iterator[Session]:
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def reset_database() -> Iterator[None]:
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client() -> Iterator[TestClient]:
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def db() -> Iterator[Session]:
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def seed_user(db: Session, user_id: int = 1) -> User:
    user = User(
        id=user_id,
        email=f"user{user_id}@example.com",
        first_name="Ada",
        last_name="Lovelace",
        phone_number="+15551234567",
        bio="Original bio",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def auth_headers(user_id: int | str = 1) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_token(user_id)}"}


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {"service": settings.app_name, "status": "running"}


def test_get_profile(client: TestClient, db: Session) -> None:
    user = seed_user(db)

    response = client.get("/users/profile", headers=auth_headers(user.id))

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == user.id
    assert body["email"] == user.email
    assert body["first_name"] == "Ada"
    assert "password_hash" not in body


def test_update_profile(client: TestClient, db: Session) -> None:
    user = seed_user(db)

    response = client.put(
        "/users/profile",
        headers=auth_headers(user.id),
        json={
            "first_name": "Grace",
            "last_name": None,
            "phone_number": "+15557654321",
            "bio": "Updated bio",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["first_name"] == "Grace"
    assert body["last_name"] is None
    assert body["phone_number"] == "+15557654321"
    assert body["bio"] == "Updated bio"


def test_profile_user_not_found(client: TestClient) -> None:
    response = client.get("/users/profile", headers=auth_headers(999))

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"


def test_profile_requires_authentication(client: TestClient) -> None:
    response = client.get("/users/profile")

    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"


def test_profile_rejects_invalid_token(client: TestClient) -> None:
    response = client.get(
        "/users/profile",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token"


def test_update_profile_validates_input(client: TestClient, db: Session) -> None:
    user = seed_user(db)

    response = client.put(
        "/users/profile",
        headers=auth_headers(user.id),
        json={"first_name": ""},
    )

    assert response.status_code == 422
