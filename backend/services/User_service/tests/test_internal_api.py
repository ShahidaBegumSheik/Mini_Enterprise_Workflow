"""Internal service-to-service contract consumed by the Authentication Service."""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import InternalApiDisabledError
from app.dependencies.auth import Principal
from app.models.user import User
from tests.conftest import reload_user, seed_user


INTERNAL_PREFIX = "/api/v1/internal"


def internal_headers(key: str = "test-internal-key") -> dict[str, str]:
    return {"X-Internal-API-Key": key}


def use_internal_key(
    monkeypatch: object,
    key: str = "test-internal-key",
) -> None:
    monkeypatch.setattr(settings, "internal_api_key", key)


# ---------------------------------------------------------------------------
# Authentication of the internal router
# ---------------------------------------------------------------------------


def test_internal_route_requires_the_api_key(client: TestClient, monkeypatch) -> None:
    use_internal_key(monkeypatch)

    response = client.post(f"{INTERNAL_PREFIX}/users", json={"email": "a@b.com"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Missing internal API key"


def test_internal_route_rejects_a_wrong_api_key(
    client: TestClient,
    monkeypatch,
) -> None:
    use_internal_key(monkeypatch)

    response = client.post(
        f"{INTERNAL_PREFIX}/users",
        headers=internal_headers("wrong"),
        json={"email": "a@b.com"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid internal API key"


def test_internal_route_is_disabled_without_configuration(
    client: TestClient,
    monkeypatch,
) -> None:
    use_internal_key(monkeypatch, "")

    response = client.post(
        f"{INTERNAL_PREFIX}/users",
        headers=internal_headers(),
        json={"email": "a@b.com"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Internal API is disabled"


# ---------------------------------------------------------------------------
# Registration flow used by the Authentication Service
# ---------------------------------------------------------------------------


def test_create_user_from_full_name(client: TestClient, monkeypatch, db: Session) -> None:
    use_internal_key(monkeypatch)

    response = client.post(
        f"{INTERNAL_PREFIX}/users",
        headers=internal_headers(),
        json={
            "email": "Grace.Hopper@Example.com",
            "full_name": "Grace Hopper",
            "account_type": "individual",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["user_id"] == body["id"]
    assert body["first_name"] == "Grace"
    assert body["last_name"] == "Hopper"
    assert body["email"] == "grace.hopper@example.com"
    assert "password_hash" not in body


def test_create_user_from_explicit_name(client: TestClient, monkeypatch) -> None:
    use_internal_key(monkeypatch)

    response = client.post(
        f"{INTERNAL_PREFIX}/users",
        headers=internal_headers(),
        json={
            "email": "ada@example.com",
            "first_name": "Ada",
            "last_name": "Lovelace",
        },
    )

    assert response.status_code == 201
    assert response.json()["first_name"] == "Ada"


def test_create_user_falls_back_to_the_email_local_part(
    client: TestClient,
    monkeypatch,
) -> None:
    use_internal_key(monkeypatch)

    response = client.post(
        f"{INTERNAL_PREFIX}/users",
        headers=internal_headers(),
        json={"email": "nameless@example.com"},
    )

    assert response.status_code == 201
    assert response.json()["first_name"] == "nameless"
    assert response.json()["last_name"] is None


def test_create_user_ignores_credential_fields(
    client: TestClient,
    monkeypatch,
) -> None:
    use_internal_key(monkeypatch)

    response = client.post(
        f"{INTERNAL_PREFIX}/users",
        headers=internal_headers(),
        json={
            "email": "safe@example.com",
            "full_name": "Safe User",
            "password_hash": "argon2$should-not-be-stored",
            "role_code": "tenant_admin",
        },
    )

    assert response.status_code == 201
    assert "password" not in response.text
    assert "should-not-be-stored" not in response.text


def test_create_user_duplicate_returns_409(
    client: TestClient,
    monkeypatch,
    db: Session,
) -> None:
    use_internal_key(monkeypatch)
    seed_user(db, 1, email="taken@example.com")

    response = client.post(
        f"{INTERNAL_PREFIX}/users",
        headers=internal_headers(),
        json={"email": "taken@example.com", "full_name": "Copy Cat"},
    )

    assert response.status_code == 409


def test_create_user_validates_email(
    client: TestClient,
    monkeypatch,
) -> None:
    use_internal_key(monkeypatch)

    response = client.post(
        f"{INTERNAL_PREFIX}/users",
        headers=internal_headers(),
        json={"email": "not-an-email"},
    )

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Read / bootstrap / sync / notify
# ---------------------------------------------------------------------------


def test_get_internal_user(client: TestClient, monkeypatch, db: Session) -> None:
    use_internal_key(monkeypatch)
    user = seed_user(db)

    response = client.get(
        f"{INTERNAL_PREFIX}/users/{user.id}",
        headers=internal_headers(),
    )

    assert response.status_code == 200
    assert response.json()["user_id"] == user.id


def test_get_internal_user_not_found(client: TestClient, monkeypatch) -> None:
    use_internal_key(monkeypatch)

    response = client.get(
        f"{INTERNAL_PREFIX}/users/424242",
        headers=internal_headers(),
    )

    assert response.status_code == 404


def test_bootstrap_internal_user(client: TestClient, monkeypatch, db: Session) -> None:
    use_internal_key(monkeypatch)
    user = seed_user(db, is_active=False)

    response = client.post(
        f"{INTERNAL_PREFIX}/users/{user.id}/bootstrap",
        headers=internal_headers(),
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is True
    assert reload_user(db, user.id).is_active is True


def test_sync_user_deactivation(
    client: TestClient,
    monkeypatch,
    db: Session,
) -> None:
    use_internal_key(monkeypatch)
    user = seed_user(db)

    response = client.post(
        f"{INTERNAL_PREFIX}/sync/users/{user.id}",
        headers=internal_headers(),
        json={"action": "deactivated"},
    )

    assert response.status_code == 202
    assert response.json() == {"status": "accepted"}
    assert reload_user(db, user.id).is_active is False


def test_sync_user_name_change(client: TestClient, monkeypatch, db: Session) -> None:
    use_internal_key(monkeypatch)
    user = seed_user(db)

    response = client.post(
        f"{INTERNAL_PREFIX}/sync/users/{user.id}",
        headers=internal_headers(),
        json={"action": "updated", "full_name": "Renamed Person"},
    )

    assert response.status_code == 202
    stored = reload_user(db, user.id)
    assert stored.first_name == "Renamed"
    assert stored.last_name == "Person"


def test_sync_user_unknown_id(client: TestClient, monkeypatch) -> None:
    use_internal_key(monkeypatch)

    response = client.post(
        f"{INTERNAL_PREFIX}/sync/users/424242",
        headers=internal_headers(),
        json={"action": "created"},
    )

    assert response.status_code == 404


def test_notify_user_is_accepted(client: TestClient, monkeypatch, db: Session) -> None:
    use_internal_key(monkeypatch)
    user = seed_user(db)

    response = client.post(
        f"{INTERNAL_PREFIX}/users/{user.id}/notifications",
        headers=internal_headers(),
        json={
            "title": "Welcome",
            "message": "Your account is ready",
            "notification_type": "info",
        },
    )

    assert response.status_code == 202
    assert response.json() == {"status": "accepted"}


# ---------------------------------------------------------------------------
# Dependency unit tests
# ---------------------------------------------------------------------------


def test_principal_is_admin_for_configured_roles() -> None:
    principal = Principal(user_id=1, roles=frozenset({"admin"}))

    assert principal.is_admin is True


def test_principal_is_not_admin_without_roles() -> None:
    assert Principal(user_id=1).is_admin is False


def test_internal_api_disabled_error_default_detail() -> None:
    assert InternalApiDisabledError().status_code == 503


def test_internal_routes_are_tagged_for_service_owners(
    client: TestClient,
) -> None:
    spec = client.get("/openapi.json").json()
    operations = spec["paths"][f"{INTERNAL_PREFIX}/users"]

    assert set(operations) == {"post"}
    assert operations["post"]["tags"] == ["Internal"]
