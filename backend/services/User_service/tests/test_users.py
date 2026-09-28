from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.database.base import Base
from app.database.session import get_db
from app.main import app
from app.models.user import User
from app.repositories.user_repository import get_user_by_email, update_user
from app.services.user_service import get_user, update_user_profile


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
) -> str:
    claims: dict[str, str | datetime] = {}
    if user_id is not None:
        claims["sub"] = str(user_id)
    if expires_at is not None:
        claims["exp"] = expires_at

    return jwt.encode(
        claims,
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


def test_openapi_includes_profile_routes(client: TestClient) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/users/profile" in paths
    assert "get" in paths["/users/profile"]
    assert "put" in paths["/users/profile"]


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


def test_update_profile_preserves_omitted_fields(
    client: TestClient,
    db: Session,
) -> None:
    user = seed_user(db)

    response = client.put(
        "/users/profile",
        headers=auth_headers(user.id),
        json={"bio": "Only bio changed"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["first_name"] == user.first_name
    assert body["last_name"] == user.last_name
    assert body["bio"] == "Only bio changed"


def test_profile_user_not_found(client: TestClient) -> None:
    response = client.get("/users/profile", headers=auth_headers(999))

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"


def test_profile_requires_authentication(client: TestClient) -> None:
    response = client.get("/users/profile")

    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"
    assert response.headers["www-authenticate"] == "Bearer"


def test_profile_rejects_invalid_bearer_format(client: TestClient) -> None:
    response = client.get(
        "/users/profile",
        headers={"Authorization": "Basic not-a-bearer-token"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"


def test_profile_rejects_invalid_token(client: TestClient) -> None:
    response = client.get(
        "/users/profile",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token"


def test_profile_rejects_invalid_signature(client: TestClient) -> None:
    token = jwt.encode(
        {"sub": "1"},
        "wrong-signing-secret",
        algorithm=settings.jwt_algorithm,
    )

    response = client.get(
        "/users/profile",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token"


def test_profile_rejects_expired_token(client: TestClient) -> None:
    token = create_token(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))

    response = client.get(
        "/users/profile",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token"


def test_profile_rejects_missing_subject(client: TestClient) -> None:
    token = create_token(user_id=None)

    response = client.get(
        "/users/profile",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token"


def test_profile_rejects_wrong_algorithm(client: TestClient) -> None:
    token = jwt.encode(
        {"sub": "1"},
        settings.jwt_secret_key,
        algorithm="HS384",
    )

    response = client.get(
        "/users/profile",
        headers={"Authorization": f"Bearer {token}"},
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


def test_update_profile_rejects_protected_fields(
    client: TestClient,
    db: Session,
) -> None:
    user = seed_user(db)

    response = client.put(
        "/users/profile",
        headers=auth_headers(user.id),
        json={"email": "changed@example.com", "is_active": False},
    )

    assert response.status_code == 422
    assert db.get(User, user.id).email == user.email


def test_update_profile_rejects_null_first_name(
    client: TestClient,
    db: Session,
) -> None:
    user = seed_user(db)

    response = client.put(
        "/users/profile",
        headers=auth_headers(user.id),
        json={"first_name": None},
    )

    assert response.status_code == 422


def test_update_profile_validates_phone_number(
    client: TestClient,
    db: Session,
) -> None:
    user = seed_user(db)

    response = client.put(
        "/users/profile",
        headers=auth_headers(user.id),
        json={"phone_number": "not-a-phone"},
    )

    assert response.status_code == 422


def test_service_raises_not_found(db: Session) -> None:
    with pytest.raises(HTTPException) as error:
        get_user(db, 404)

    assert error.value.status_code == 404


def test_repository_and_service_update_user(db: Session) -> None:
    user = seed_user(db)

    updated = update_user_profile(
        db=db,
        user_id=user.id,
        data={"first_name": "Katherine"},
    )
    repository_updated = update_user(
        db=db,
        user=updated,
        data={"bio": "Repository update"},
    )
    fetched = get_user_by_email(db, user.email)

    assert updated.first_name == "Katherine"
    assert repository_updated.bio == "Repository update"
    assert fetched is not None
    assert fetched.first_name == "Katherine"
    assert fetched.bio == "Repository update"


def test_database_error_is_not_exposed(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_database_error(*args: object, **kwargs: object) -> None:
        raise SQLAlchemyError("sensitive database details")

    monkeypatch.setattr(
        "app.services.user_service.get_user_by_id",
        raise_database_error,
    )

    response = client.get("/users/profile", headers=auth_headers())

    assert response.status_code == 503
    assert response.json() == {"detail": "Database operation failed"}
    assert "sensitive database details" not in response.text
