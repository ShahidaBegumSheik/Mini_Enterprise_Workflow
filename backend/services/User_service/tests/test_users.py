"""End-to-end coverage of the public User Service API."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from tests.conftest import auth_headers, create_token, reload_user, seed_user


# ---------------------------------------------------------------------------
# 1. Health
# ---------------------------------------------------------------------------


def test_health(client: TestClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {"service": "User Service", "status": "running"}


# ---------------------------------------------------------------------------
# 2. Current profile
# ---------------------------------------------------------------------------


def test_get_current_profile(client: TestClient, db: Session) -> None:
    user = seed_user(db)

    response = client.get("/users/profile", headers=auth_headers(user.id))

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == user.id
    assert body["email"] == user.email
    assert body["first_name"] == "Ada"
    assert body["last_name"] == "Lovelace"
    assert body["is_active"] is True
    assert set(body) == {
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


def test_get_current_profile_does_not_expose_secrets(
    client: TestClient,
    db: Session,
) -> None:
    user = seed_user(db)

    body = client.get("/users/profile", headers=auth_headers(user.id)).json()

    for forbidden in ("password", "password_hash", "token", "secret"):
        assert forbidden not in body


def test_get_current_profile_unknown_subject_returns_404(
    client: TestClient,
) -> None:
    response = client.get("/users/profile", headers=auth_headers(999))

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"


def test_get_current_profile_deactivated_user_returns_403(
    client: TestClient,
    db: Session,
) -> None:
    user = seed_user(db, is_active=False)

    response = client.get("/users/profile", headers=auth_headers(user.id))

    assert response.status_code == 403


# ---------------------------------------------------------------------------
# 3. Update current profile
# ---------------------------------------------------------------------------


def test_update_current_profile(client: TestClient, db: Session) -> None:
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
    assert body["email"] == user.email
    assert body["id"] == user.id


def test_update_current_profile_preserves_omitted_fields(
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
    assert body["first_name"] == "Ada"
    assert body["last_name"] == "Lovelace"
    assert body["phone_number"] == "+15551234567"
    assert body["bio"] == "Only bio changed"


def test_update_current_profile_updates_timestamp(
    client: TestClient,
    db: Session,
) -> None:
    user = seed_user(db)
    original = user.updated_at

    response = client.put(
        "/users/profile",
        headers=auth_headers(user.id),
        json={"bio": "Touched"},
    )

    assert response.status_code == 200
    updated_at = datetime.fromisoformat(response.json()["updated_at"])
    assert updated_at >= original


@pytest.mark.parametrize(
    "payload",
    [
        {"first_name": ""},
        {"first_name": "   "},
        {"first_name": None},
        {"first_name": "x" * 101},
        {"last_name": "y" * 101},
        {"phone_number": "not-a-phone"},
        {"phone_number": "12345"},
        {"phone_number": "+" * 31},
        {"bio": "z" * 2001},
    ],
)
def test_update_current_profile_rejects_invalid_data(
    client: TestClient,
    db: Session,
    payload: dict[str, object],
) -> None:
    user = seed_user(db)

    response = client.put(
        "/users/profile",
        headers=auth_headers(user.id),
        json=payload,
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "changed@example.com"},
        {"is_active": False},
        {"id": 99},
        {"created_at": "2020-01-01T00:00:00"},
        {"updated_at": "2020-01-01T00:00:00"},
        {"password": "hunter2"},
        {"password_hash": "hunter2"},
    ],
)
def test_update_current_profile_rejects_protected_fields(
    client: TestClient,
    db: Session,
    payload: dict[str, object],
) -> None:
    user = seed_user(db)

    response = client.put(
        "/users/profile",
        headers=auth_headers(user.id),
        json=payload,
    )

    assert response.status_code == 422

    stored = reload_user(db, user.id)
    assert stored.email == user.email
    assert stored.is_active is True
    assert stored.id == user.id


def test_update_current_profile_requires_authentication(
    client: TestClient,
    db: Session,
) -> None:
    seed_user(db)

    response = client.put("/users/profile", json={"bio": "anonymous"})

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


# ---------------------------------------------------------------------------
# 4. Get user by id
# ---------------------------------------------------------------------------


def test_get_user_by_id(client: TestClient, db: Session) -> None:
    user = seed_user(db)
    admin = seed_user(db, 2, email="admin@example.com")

    response = client.get(
        f"/users/{user.id}",
        headers=auth_headers(admin.id, roles=["admin"]),
    )

    assert response.status_code == 200
    assert response.json()["id"] == user.id


def test_get_own_user_by_id(client: TestClient, db: Session) -> None:
    user = seed_user(db)

    response = client.get(f"/users/{user.id}", headers=auth_headers(user.id))

    assert response.status_code == 200
    assert response.json()["id"] == user.id


def test_get_user_by_id_not_found(client: TestClient, db: Session) -> None:
    admin = seed_user(db, 1, email="admin@example.com")

    response = client.get(
        "/users/424242",
        headers=auth_headers(admin.id, roles=["admin"]),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"


def test_get_user_by_id_requires_authentication(client: TestClient) -> None:
    response = client.get("/users/1")

    assert response.status_code == 401


def test_get_user_by_id_forbidden_for_other_users(
    client: TestClient,
    db: Session,
) -> None:
    seed_user(db, 1, email="one@example.com")
    target = seed_user(db, 2, email="two@example.com")

    response = client.get(f"/users/{target.id}", headers=auth_headers(1))

    assert response.status_code == 403
    assert response.json()["detail"] == "You are not allowed to access this user"


@pytest.mark.parametrize("user_id", ["abc", "0", "-1", "1.5", "1e3", "%20"])
def test_get_user_by_id_rejects_invalid_identifier(
    client: TestClient,
    db: Session,
    user_id: str,
) -> None:
    user = seed_user(db)

    response = client.get(f"/users/{user_id}", headers=auth_headers(user.id))

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# 5. List users
# ---------------------------------------------------------------------------


def test_list_users(client: TestClient, db: Session) -> None:
    for index in range(1, 4):
        seed_user(db, index)

    response = client.get("/users", headers=auth_headers(1))

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert body["page"] == 1
    assert body["page_size"] == 20
    assert body["pages"] == 1
    assert [item["id"] for item in body["items"]] == [1, 2, 3]


def test_list_users_pagination(client: TestClient, db: Session) -> None:
    for index in range(1, 8):
        seed_user(db, index)

    first = client.get("/users?page=1&page_size=3", headers=auth_headers(1)).json()
    second = client.get("/users?page=2&page_size=3", headers=auth_headers(1)).json()
    third = client.get("/users?page=3&page_size=3", headers=auth_headers(1)).json()

    assert [item["id"] for item in first["items"]] == [1, 2, 3]
    assert [item["id"] for item in second["items"]] == [4, 5, 6]
    assert [item["id"] for item in third["items"]] == [7]
    assert first["total"] == second["total"] == 7
    assert first["pages"] == 3


def test_list_users_page_beyond_range(client: TestClient, db: Session) -> None:
    seed_user(db)

    response = client.get("/users?page=9&page_size=5", headers=auth_headers(1))

    assert response.status_code == 200
    assert response.json()["items"] == []


@pytest.mark.parametrize("query", ["page=0", "page=-1", "page_size=0", "page_size=500"])
def test_list_users_rejects_invalid_pagination(
    client: TestClient,
    db: Session,
    query: str,
) -> None:
    seed_user(db)

    response = client.get(f"/users?{query}", headers=auth_headers(1))

    assert response.status_code == 422


def test_list_users_filters(client: TestClient, db: Session) -> None:
    seed_user(db, 1, email="active@example.com")
    seed_user(db, 2, email="disabled@example.com", is_active=False)

    active = client.get("/users?is_active=true", headers=auth_headers(1)).json()
    inactive = client.get("/users?is_active=false", headers=auth_headers(1)).json()
    searched = client.get("/users?search=disabled", headers=auth_headers(1)).json()

    assert [item["id"] for item in active["items"]] == [1]
    assert [item["id"] for item in inactive["items"]] == [2]
    assert [item["id"] for item in searched["items"]] == [2]


def test_list_users_does_not_leak_credentials(
    client: TestClient,
    db: Session,
) -> None:
    seed_user(db)

    items = client.get("/users", headers=auth_headers(1)).json()["items"]

    assert "password_hash" not in items[0]
    assert set(items[0]) == {
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


def test_list_users_requires_authentication(client: TestClient) -> None:
    response = client.get("/users")

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# 6. Update user by id
# ---------------------------------------------------------------------------


def test_update_own_user_by_id(client: TestClient, db: Session) -> None:
    user = seed_user(db)

    response = client.put(
        f"/users/{user.id}",
        headers=auth_headers(user.id),
        json={"first_name": "Katherine", "bio": "Self service"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["first_name"] == "Katherine"
    assert body["bio"] == "Self service"


def test_update_other_user_as_admin(client: TestClient, db: Session) -> None:
    seed_user(db, 1, email="admin@example.com")
    target = seed_user(db, 2, email="member@example.com")

    response = client.put(
        f"/users/{target.id}",
        headers=auth_headers(1, roles=["admin"]),
        json={"first_name": "Managed"},
    )

    assert response.status_code == 200
    assert response.json()["first_name"] == "Managed"


def test_update_other_user_forbidden(client: TestClient, db: Session) -> None:
    seed_user(db, 1, email="one@example.com")
    target = seed_user(db, 2, email="two@example.com")

    response = client.put(
        f"/users/{target.id}",
        headers=auth_headers(1),
        json={"first_name": "Hacked"},
    )

    assert response.status_code == 403
    assert reload_user(db, target.id).first_name == "Ada"


def test_update_user_by_id_not_found(client: TestClient, db: Session) -> None:
    seed_user(db, 1, email="admin@example.com")

    response = client.put(
        "/users/424242",
        headers=auth_headers(1, roles=["admin"]),
        json={"first_name": "Ghost"},
    )

    assert response.status_code == 404


def test_update_user_by_id_validates_input(
    client: TestClient,
    db: Session,
) -> None:
    user = seed_user(db)

    response = client.put(
        f"/users/{user.id}",
        headers=auth_headers(user.id),
        json={"first_name": ""},
    )

    assert response.status_code == 422


def test_update_user_by_id_rejects_protected_fields(
    client: TestClient,
    db: Session,
) -> None:
    admin = seed_user(db, 1, email="admin@example.com")
    target = seed_user(db, 2, email="member@example.com")

    response = client.put(
        f"/users/{target.id}",
        headers=auth_headers(admin.id, roles=["admin"]),
        json={"email": "hijack@example.com", "is_active": False},
    )

    assert response.status_code == 422
    assert reload_user(db, target.id).email == "member@example.com"
    assert reload_user(db, target.id).is_active is True


def test_update_user_by_id_requires_authentication(
    client: TestClient,
    db: Session,
) -> None:
    user = seed_user(db)

    response = client.put(f"/users/{user.id}", json={"bio": "anonymous"})

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# 7. Status management
# ---------------------------------------------------------------------------


def test_patch_user_status_deactivate_as_admin(
    client: TestClient,
    db: Session,
) -> None:
    seed_user(db, 1, email="admin@example.com")
    target = seed_user(db, 2, email="member@example.com")

    response = client.patch(
        f"/users/{target.id}/status",
        headers=auth_headers(1, roles=["admin"]),
        json={"is_active": False},
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is False
    assert reload_user(db, target.id).is_active is False


def test_patch_user_status_activate_as_admin(
    client: TestClient,
    db: Session,
) -> None:
    seed_user(db, 1, email="admin@example.com")
    target = seed_user(db, 2, email="member@example.com", is_active=False)

    response = client.patch(
        f"/users/{target.id}/status",
        headers=auth_headers(1, roles=["admin"]),
        json={"is_active": True},
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is True


def test_patch_user_status_forbidden_for_normal_user(
    client: TestClient,
    db: Session,
) -> None:
    seed_user(db, 1, email="one@example.com")
    target = seed_user(db, 2, email="two@example.com")

    response = client.patch(
        f"/users/{target.id}/status",
        headers=auth_headers(1),
        json={"is_active": False},
    )

    assert response.status_code == 403
    assert reload_user(db, target.id).is_active is True


def test_patch_own_status_forbidden_without_role(
    client: TestClient,
    db: Session,
) -> None:
    user = seed_user(db)

    response = client.patch(
        f"/users/{user.id}/status",
        headers=auth_headers(user.id),
        json={"is_active": False},
    )

    assert response.status_code == 403


def test_patch_user_status_not_found(client: TestClient, db: Session) -> None:
    seed_user(db, 1, email="admin@example.com")

    response = client.patch(
        "/users/424242/status",
        headers=auth_headers(1, roles=["admin"]),
        json={"is_active": False},
    )

    assert response.status_code == 404


def test_patch_user_status_requires_authentication(
    client: TestClient,
    db: Session,
) -> None:
    user = seed_user(db)

    response = client.patch(f"/users/{user.id}/status", json={"is_active": False})

    assert response.status_code == 401


@pytest.mark.parametrize(
    "payload",
    [{}, {"is_active": "false"}, {"is_active": 1}, {"is_active": None}, {"is_active": True, "id": 5}],
)
def test_patch_user_status_validates_input(
    client: TestClient,
    db: Session,
    payload: dict[str, object],
) -> None:
    seed_user(db, 1, email="admin@example.com")
    target = seed_user(db, 2, email="member@example.com")

    response = client.patch(
        f"/users/{target.id}/status",
        headers=auth_headers(1, roles=["admin"]),
        json=payload,
    )

    assert response.status_code == 422
    assert reload_user(db, target.id).is_active is True


def _deactivate_via_api(client: TestClient, db: Session, admin_id: int, user_id: int) -> None:
    """Flip a user's ``is_active`` through the status endpoint."""

    response = client.patch(
        f"/users/{user_id}/status",
        headers=auth_headers(admin_id, roles=["admin"]),
        json={"is_active": False},
    )
    assert response.status_code == 200
    assert reload_user(db, user_id).is_active is False


def test_deactivated_user_cannot_read_their_profile(
    client: TestClient,
    db: Session,
) -> None:
    admin = seed_user(db, 1)
    user = seed_user(db, 2)
    _deactivate_via_api(client, db, admin.id, user.id)

    response = client.get("/users/profile", headers=auth_headers(user.id))

    assert response.status_code == 403
    assert response.json()["detail"] == "User account is deactivated"


def test_deactivated_user_cannot_list_users(
    client: TestClient,
    db: Session,
) -> None:
    admin = seed_user(db, 1)
    user = seed_user(db, 2)
    _deactivate_via_api(client, db, admin.id, user.id)

    response = client.get("/users", headers=auth_headers(user.id))

    assert response.status_code == 403
    assert response.json()["detail"] == "User account is deactivated"


def test_deactivated_user_cannot_read_their_own_record(
    client: TestClient,
    db: Session,
) -> None:
    admin = seed_user(db, 1)
    user = seed_user(db, 2)
    _deactivate_via_api(client, db, admin.id, user.id)

    response = client.get(f"/users/{user.id}", headers=auth_headers(user.id))

    assert response.status_code == 403
    assert response.json()["detail"] == "User account is deactivated"


def test_deactivated_user_cannot_update_their_own_record(
    client: TestClient,
    db: Session,
) -> None:
    admin = seed_user(db, 1)
    user = seed_user(db, 2)
    _deactivate_via_api(client, db, admin.id, user.id)

    response = client.put(
        f"/users/{user.id}",
        headers=auth_headers(user.id),
        json={"first_name": "Mallory"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "User account is deactivated"
    assert reload_user(db, user.id).first_name == "Ada"


def test_deactivated_user_cannot_update_their_profile(
    client: TestClient,
    db: Session,
) -> None:
    admin = seed_user(db, 1)
    user = seed_user(db, 2)
    _deactivate_via_api(client, db, admin.id, user.id)

    response = client.put(
        "/users/profile",
        headers=auth_headers(user.id),
        json={"first_name": "Mallory"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "User account is deactivated"
    assert reload_user(db, user.id).first_name == "Ada"


def test_deactivated_admin_cannot_change_someone_elses_status(
    client: TestClient,
    db: Session,
) -> None:
    admin = seed_user(db, 1)
    target = seed_user(db, 2)
    client.patch(
        f"/users/{admin.id}/status",
        headers=auth_headers(admin.id, roles=["admin"]),
        json={"is_active": False},
    )
    assert reload_user(db, admin.id).is_active is False

    response = client.patch(
        f"/users/{target.id}/status",
        headers=auth_headers(admin.id, roles=["admin"]),
        json={"is_active": False},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "User account is deactivated"
    assert reload_user(db, target.id).is_active is True


def test_deactivated_admin_cannot_update_another_user(
    client: TestClient,
    db: Session,
) -> None:
    admin = seed_user(db, 1)
    target = seed_user(db, 2)
    client.patch(
        f"/users/{admin.id}/status",
        headers=auth_headers(admin.id, roles=["admin"]),
        json={"is_active": False},
    )
    assert reload_user(db, admin.id).is_active is False

    response = client.put(
        f"/users/{target.id}",
        headers=auth_headers(admin.id, roles=["admin"]),
        json={"first_name": "Overwritten"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "User account is deactivated"
    assert reload_user(db, target.id).first_name == "Ada"


def test_deactivated_admin_cannot_read_another_user(
    client: TestClient,
    db: Session,
) -> None:
    admin = seed_user(db, 1)
    target = seed_user(db, 2)
    client.patch(
        f"/users/{admin.id}/status",
        headers=auth_headers(admin.id, roles=["admin"]),
        json={"is_active": False},
    )

    response = client.get(f"/users/{target.id}", headers=auth_headers(admin.id, roles=["admin"]))

    assert response.status_code == 403
    assert response.json()["detail"] == "User account is deactivated"


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("get", "/users", None),
        ("get", "/users/profile", None),
        ("put", "/users/profile", {"first_name": "StillWorks"}),
    ],
)
def test_active_user_keeps_full_access(
    client: TestClient,
    db: Session,
    method: str,
    path: str,
    payload: dict[str, str] | None,
) -> None:
    user = seed_user(db)

    response = client.request(
        method.upper(),
        path,
        headers=auth_headers(user.id),
        json=payload,
    )

    assert response.status_code == 200


def test_active_admin_keeps_managing_other_users(
    client: TestClient,
    db: Session,
) -> None:
    admin = seed_user(db, 1)
    target = seed_user(db, 2)
    headers = auth_headers(admin.id, roles=["admin"])

    assert client.get("/users", headers=headers).status_code == 200
    assert client.get(f"/users/{target.id}", headers=headers).status_code == 200

    updated = client.put(
        f"/users/{target.id}",
        headers=headers,
        json={"first_name": "Managed"},
    )
    assert updated.status_code == 200
    assert reload_user(db, target.id).first_name == "Managed"

    status = client.patch(
        f"/users/{target.id}/status",
        headers=headers,
        json={"is_active": False},
    )
    assert status.status_code == 200
    assert reload_user(db, target.id).is_active is False


def test_active_user_can_still_deactivate_themselves_as_admin(
    client: TestClient,
    db: Session,
) -> None:
    """Deactivation succeeds; only the *next* request is rejected."""

    admin = seed_user(db, 1)

    response = client.patch(
        f"/users/{admin.id}/status",
        headers=auth_headers(admin.id, roles=["admin"]),
        json={"is_active": False},
    )

    assert response.status_code == 200
    assert reload_user(db, admin.id).is_active is False


# ---------------------------------------------------------------------------
# 8. JWT verification
# ---------------------------------------------------------------------------


def test_missing_token_returns_401(client: TestClient) -> None:
    response = client.get("/users/profile")

    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "header",
    [
        "Basic not-a-bearer-token",
        "Bearer",
        "bearer",
        "Token abc.def.ghi",
        "Bearer a b",
    ],
)
def test_invalid_bearer_format_returns_401(
    client: TestClient,
    header: str,
) -> None:
    response = client.get("/users/profile", headers={"Authorization": header})

    assert response.status_code == 401


def test_invalid_token_returns_401(client: TestClient) -> None:
    response = client.get(
        "/users/profile",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token"


def test_token_signed_with_wrong_secret_returns_401(client: TestClient) -> None:
    token = create_token(1, secret="wrong-signing-secret")

    response = client.get("/users/profile", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


def test_token_signed_with_wrong_algorithm_returns_401(
    client: TestClient,
) -> None:
    token = create_token(1, algorithm="HS384")

    response = client.get("/users/profile", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


def test_expired_token_returns_401(client: TestClient) -> None:
    token = create_token(
        1,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    response = client.get("/users/profile", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token"


def test_missing_subject_returns_401(client: TestClient) -> None:
    token = create_token(None)

    response = client.get("/users/profile", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token"


@pytest.mark.parametrize("subject", ["", "  ", "abc", "0", "-4", "1.5", "null"])
def test_non_numeric_subject_returns_401(
    client: TestClient,
    subject: str,
) -> None:
    token = create_token(subject)

    response = client.get("/users/profile", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


def test_token_without_signature_returns_401(client: TestClient) -> None:
    response = client.get(
        "/users/profile",
        headers={"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."},
    )

    assert response.status_code == 401


def test_valid_token_for_unknown_user_returns_404(client: TestClient) -> None:
    response = client.get("/users/profile", headers=auth_headers(12345))

    assert response.status_code == 404


def test_role_claim_as_list_grants_admin_access(
    client: TestClient,
    db: Session,
) -> None:
    seed_user(db, 1, email="one@example.com")
    target = seed_user(db, 2, email="two@example.com")

    response = client.get(f"/users/{target.id}", headers=auth_headers(1, roles=["admin"]))

    assert response.status_code == 200


def test_role_claim_as_string_grants_admin_access(
    client: TestClient,
    db: Session,
) -> None:
    seed_user(db, 1, email="one@example.com")
    target = seed_user(db, 2, email="two@example.com")
    token = create_token(1, extra_claims={"role": "admin"})

    response = client.get(
        f"/users/{target.id}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200


def test_non_admin_role_does_not_grant_access(
    client: TestClient,
    db: Session,
) -> None:
    seed_user(db, 1, email="one@example.com")
    target = seed_user(db, 2, email="two@example.com")

    response = client.get(
        f"/users/{target.id}",
        headers=auth_headers(1, roles=["employee"]),
    )

    assert response.status_code == 403


# ---------------------------------------------------------------------------
# 9. Error handling
# ---------------------------------------------------------------------------


def test_database_error_is_not_exposed(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.exc import SQLAlchemyError

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


def test_unexpected_error_returns_500_without_stack_trace(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("leaky-internal-detail")

    monkeypatch.setattr("app.dependencies.auth.get_user", boom)

    response = client.get("/users/profile", headers=auth_headers())

    assert response.status_code == 500
    assert "leaky-internal-detail" not in response.text
    assert "Traceback" not in response.text
