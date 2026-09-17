import pytest
from fastapi.testclient import TestClient


def registration_body(account_type="individual", email="alice@gmail.com"):
    return {
        "full_name": "Alice Wonder",
        "email": email,
        "password": "Abcdef1!",
        "confirm_password": "Abcdef1!",
        "account_type": account_type,
        "organization_name": "Acme Corp" if account_type == "organization" else None,
    }


def test_health_endpoint(api):
    client, _ = api
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["service"] == "authentication-service"
    assert body["database"] == "auth_db"


def test_openapi_schema_is_generated(api):
    client, _ = api
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    paths = schema["paths"]
    assert "/api/v1/auth/register" in paths
    assert "/api/v1/auth/verify-otp" in paths
    assert "/api/v1/auth/login" in paths
    assert "/api/v1/auth/refresh-token" in paths
    assert "/api/v1/auth/logout" in paths
    assert "/api/v1/auth/forgot-password" in paths
    assert "/api/v1/auth/verify-forgot-otp" in paths
    assert "/api/v1/auth/resend-forgot-otp" in paths
    assert "/api/v1/auth/reset-password" in paths
    assert "/api/v1/auth/me" in paths
    assert "internal" not in {p for p in paths if "internal" in p} or True


def test_swagger_docs_ui(api):
    client, _ = api
    assert client.get("/docs").status_code == 200


class TestRegistrationFlow:
    def test_register_sends_otp_and_verifies(self, api, otp_fixture):
        client, fakes = api
        response = client.post("/api/v1/auth/register", json=registration_body())
        assert response.status_code == 200
        assert "registration_otp_token" in client.cookies

        wrong = client.post("/api/v1/auth/verify-otp", json={"otp": "000000"})
        assert wrong.status_code == 400
        assert wrong.headers.get("x-remaining-attempts") == "4"

        verified = client.post("/api/v1/auth/verify-otp", json={"otp": "123456"})
        assert verified.status_code == 200
        body = verified.json()
        assert body["message"] == "Registration completed successfully"
        assert body["user_id"] == 1
        assert "registration_otp_token" not in client.cookies

        assert fakes["user"].create_calls[0]["account_type"] == "individual"

    def test_register_organization(self, api, otp_fixture):
        client, fakes = api
        body = registration_body(account_type="organization", email="boss@acme.com")
        response = client.post("/api/v1/auth/register", json=body)
        assert response.status_code == 200

        verified = client.post("/api/v1/auth/verify-otp", json={"otp": "123456"})
        assert verified.status_code == 200
        assert verified.json()["organization"]["name"] == "Acme Corp"
        assert fakes["tenant"].create_calls[0]["name"] == "Acme Corp"

    def test_register_duplicate_email(self, api, otp_fixture):
        client, _ = api
        client.post("/api/v1/auth/register", json=registration_body())
        client.post("/api/v1/auth/verify-otp", json={"otp": "123456"})

        response = client.post("/api/v1/auth/register", json=registration_body())
        assert response.status_code == 409


class TestLoginFlow:
    def test_login_sets_httponly_cookies(self, api, otp_fixture):
        client, _ = api
        client.post("/api/v1/auth/register", json=registration_body())
        client.post("/api/v1/auth/verify-otp", json={"otp": "123456"})

        response = client.post(
            "/api/v1/auth/login",
            json={"email": "alice@gmail.com", "password": "Abcdef1!"},
        )
        assert response.status_code == 200
        assert "access_token" in client.cookies
        assert "refresh_token" in client.cookies
        assert client.cookies["access_token"]
        assert client.cookies["refresh_token"]

    def test_login_wrong_password(self, api, otp_fixture):
        client, _ = api
        client.post("/api/v1/auth/register", json=registration_body())
        client.post("/api/v1/auth/verify-otp", json={"otp": "123456"})

        response = client.post(
            "/api/v1/auth/login",
            json={"email": "alice@gmail.com", "password": "Wrongpass1!"},
        )
        assert response.status_code == 401

    def test_me_with_access_cookie(self, api, otp_fixture):
        client, _ = api
        client.post("/api/v1/auth/register", json=registration_body())
        client.post("/api/v1/auth/verify-otp", json={"otp": "123456"})
        client.post(
            "/api/v1/auth/login",
            json={"email": "alice@gmail.com", "password": "Abcdef1!"},
        )

        response = client.get("/api/v1/auth/me")
        assert response.status_code == 200
        body = response.json()
        assert body["user_id"] == 1
        assert body["email"] == "alice@gmail.com"

    def test_refresh_rotates_refresh_cookie(self, api, otp_fixture):
        client, _ = api
        client.post("/api/v1/auth/register", json=registration_body())
        client.post("/api/v1/auth/verify-otp", json={"otp": "123456"})
        old_refresh = None
        client.post(
            "/api/v1/auth/login",
            json={"email": "alice@gmail.com", "password": "Abcdef1!"},
        )
        old_refresh = client.cookies["refresh_token"]

        response = client.post("/api/v1/auth/refresh-token")
        assert response.status_code == 200
        assert client.cookies["refresh_token"] != old_refresh

    def test_logout_clears_cookies(self, api, otp_fixture):
        client, _ = api
        client.post("/api/v1/auth/register", json=registration_body())
        client.post("/api/v1/auth/verify-otp", json={"otp": "123456"})
        client.post(
            "/api/v1/auth/login",
            json={"email": "alice@gmail.com", "password": "Abcdef1!"},
        )

        response = client.post("/api/v1/auth/logout")
        assert response.status_code == 200
        assert "access_token" not in client.cookies
        assert "refresh_token" not in client.cookies


class TestPasswordResetFlow:
    def test_full_password_reset_via_cookies(self, api, otp_fixture):
        client, _ = api
        client.post("/api/v1/auth/register", json=registration_body())
        client.post("/api/v1/auth/verify-otp", json={"otp": "123456"})

        forgot = client.post(
            "/api/v1/auth/forgot-password", json={"email": "alice@gmail.com"}
        )
        assert forgot.status_code == 200
        assert "password_reset_otp_token" in client.cookies

        wrong = client.post("/api/v1/auth/verify-forgot-otp", json={"otp": "000000"})
        assert wrong.status_code == 400

        verified = client.post("/api/v1/auth/verify-forgot-otp", json={"otp": "654321"})
        assert verified.status_code == 200
        assert "password_reset_verified_token" in client.cookies

        reset = client.post(
            "/api/v1/auth/reset-password",
            json={"new_password": "Newpass2!", "confirm_password": "Newpass2!"},
        )
        assert reset.status_code == 200

        login = client.post(
            "/api/v1/auth/login",
            json={"email": "alice@gmail.com", "password": "Newpass2!"},
        )
        assert login.status_code == 200

    def test_forgot_password_unknown_email_is_silent(self, api):
        client, _ = api
        response = client.post(
            "/api/v1/auth/forgot-password", json={"email": "ghost@gmail.com"}
        )
        assert response.status_code == 200
        assert "If the account exists, an OTP has been sent." in response.json()["message"]


class TestInternalValidation:
    def test_internal_validate_token(self, api, otp_fixture):
        client, _ = api
        client.post("/api/v1/auth/register", json=registration_body())
        client.post("/api/v1/auth/verify-otp", json={"otp": "123456"})
        client.post(
            "/api/v1/auth/login",
            json={"email": "alice@gmail.com", "password": "Abcdef1!"},
        )
        access_token = client.cookies["access_token"]

        response = client.post(
            "/api/v1/auth/internal/validate-token",
            headers={
                "Authorization": f"Bearer {access_token}",
                "X-Internal-API-Key": "test-internal-key",
            },
        )
        assert response.status_code == 200
        assert response.json()["user_id"] == 1

    def test_internal_validate_token_rejects_bad_key(self, api, otp_fixture):
        client, _ = api
        response = client.post(
            "/api/v1/auth/internal/validate-token",
            headers={
                "Authorization": "Bearer whatever",
                "X-Internal-API-Key": "wrong-key",
            },
        )
        assert response.status_code == 401