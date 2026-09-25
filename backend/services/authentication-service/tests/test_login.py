from datetime import timedelta

import pytest
from fastapi import HTTPException

from app.core.security import (
    TokenError,
    create_access_token,
    create_refresh_token,
    validate_access_token,
    validate_refresh_token,
)
from app.repositories import AuthRepository, token_hash
from tests.conftest import login_payload, seed_credential

LOGIN_PASSWORD = "Str0ngPassw#ord"


class TestLoginService:
    async def test_successful_login_returns_session_metadata(self, service, session_factory):
        credential = seed_credential(session_factory, password=LOGIN_PASSWORD)
        result = await service.login(credential.email, LOGIN_PASSWORD)
        assert result["user_id"] == credential.user_id
        assert result["email"] == credential.email
        assert result["access_token"]
        assert result["refresh_token"]
        assert result["session_id"]
        assert result["access_token_expires_in"] > 0

    async def test_invalid_email_rejected(self, service, session_factory):
        seed_credential(session_factory, password=LOGIN_PASSWORD)
        with pytest.raises(HTTPException) as exc:
            await service.login("nobody@gmail.com", LOGIN_PASSWORD)
        assert exc.value.status_code == 401

    async def test_invalid_password_rejected(self, service, session_factory):
        credential = seed_credential(session_factory, password=LOGIN_PASSWORD)
        with pytest.raises(HTTPException) as exc:
            await service.login(credential.email, "WrongPassw#ord1")
        assert exc.value.status_code == 401

    async def test_inactive_user_rejected(self, service, session_factory):
        credential = seed_credential(session_factory, password=LOGIN_PASSWORD, is_active=False)
        with pytest.raises(HTTPException) as exc:
            await service.login(credential.email, LOGIN_PASSWORD)
        assert exc.value.status_code == 403
        assert "inactive" in exc.value.detail

    async def test_unverified_user_rejected(self, service, session_factory):
        credential = seed_credential(session_factory, password=LOGIN_PASSWORD, is_verified=False)
        with pytest.raises(HTTPException) as exc:
            await service.login(credential.email, LOGIN_PASSWORD)
        assert exc.value.status_code == 403
        assert "not verified" in exc.value.detail

    async def test_login_stores_only_hash_metadata(self, service, session_factory):
        credential = seed_credential(session_factory, password=LOGIN_PASSWORD)
        result = await service.login(credential.email, LOGIN_PASSWORD)
        repo = AuthRepository(session_factory())
        row = repo.refresh_session_by_id(result["session_id"])
        assert row is not None
        assert row.user_id == credential.user_id
        assert row.token_hash == token_hash(result["session_id"])
        assert row.token_hash != result["refresh_token"]


class TestLoginApi:
    async def test_login_success_sets_cookies_and_safe_body(self, client, session_factory):
        credential = seed_credential(session_factory, password=LOGIN_PASSWORD)
        response = await client.post(
            "/api/v1/auth/login", json=login_payload(credential.email, LOGIN_PASSWORD)
        )
        assert response.status_code == 200
        body = response.json()
        assert body["email"] == credential.email
        assert body["user_id"] == credential.user_id
        assert set(body) == {
            "message",
            "user_id",
            "email",
            "account_type",
            "session_id",
            "access_token_expires_in",
            "refresh_token_expires_in",
        }
        assert "token" not in body
        assert client.cookies.get("access_token")
        assert client.cookies.get("refresh_token")

    async def test_login_failure_does_not_issue_cookies(self, client, session_factory):
        credential = seed_credential(session_factory, password=LOGIN_PASSWORD)
        response = await client.post(
            "/api/v1/auth/login",
            json=login_payload(credential.email, "WrongPassw#ord1"),
        )
        assert response.status_code == 401
        assert client.cookies.get("access_token") is None
        assert client.cookies.get("refresh_token") is None

    async def test_cookie_attributes(self, client, session_factory):
        credential = seed_credential(session_factory, password=LOGIN_PASSWORD)
        response = await client.post(
            "/api/v1/auth/login", json=login_payload(credential.email, LOGIN_PASSWORD)
        )
        cookies_header = response.headers.get_list("set-cookie")
        access = next(c for c in cookies_header if c.startswith("access_token="))
        refresh = next(c for c in cookies_header if c.startswith("refresh_token="))
        for raw in (access, refresh):
            assert "HttpOnly" in raw
            assert "SameSite=lax" in raw
        assert "Max-Age=1800" in access
        assert "Max-Age=604800" in refresh

    async def test_access_token_claims(self, client, session_factory):
        credential = seed_credential(session_factory, password=LOGIN_PASSWORD)
        await client.post(
            "/api/v1/auth/login", json=login_payload(credential.email, LOGIN_PASSWORD)
        )
        claims = validate_access_token(client.cookies.get("access_token"))
        assert claims["type"] == "access"
        assert claims["sub"] == str(credential.user_id)
        assert claims["iat"]
        assert claims["exp"]
        assert claims["jti"]
        assert "sid" in claims
        assert 1799 <= claims["exp"] - claims["iat"] <= 1801

    async def test_refresh_token_claims(self, client, session_factory):
        credential = seed_credential(session_factory, password=LOGIN_PASSWORD)
        await client.post(
            "/api/v1/auth/login", json=login_payload(credential.email, LOGIN_PASSWORD)
        )
        claims = validate_refresh_token(client.cookies.get("refresh_token"))
        assert claims["type"] == "refresh"
        assert claims["sub"] == str(credential.user_id)
        assert "iat" in claims
        assert "exp" in claims
        lifetime = claims["exp"] - claims["iat"]
        assert 7 * 24 * 3600 - 1 <= lifetime <= 7 * 24 * 3600 + 1

    async def test_me_without_cookie_rejected(self, client):
        assert client.cookies.get("access_token") is None
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 401

    async def test_me_with_invalid_token_rejected(self, client):
        client.cookies.set("access_token", "not.a.jwt")
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 401

    async def test_me_with_expired_token_rejected(self, client, session_factory):
        credential = seed_credential(session_factory, password=LOGIN_PASSWORD)
        client.cookies.set(
            "access_token",
            create_access_token(credential.user_id, ttl=timedelta(seconds=-1)),
        )
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 401

    async def test_me_with_access_token_succeeds(self, client, session_factory):
        credential = seed_credential(session_factory, password=LOGIN_PASSWORD)
        await client.post(
            "/api/v1/auth/login", json=login_payload(credential.email, LOGIN_PASSWORD)
        )
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 200
        assert response.json()["user_id"] == credential.user_id


class TestTokenUtilities:
    def test_expired_access_token_raises(self):
        token = create_access_token(1, ttl=timedelta(minutes=-5))
        with pytest.raises(TokenError):
            validate_access_token(token)

    def test_invalid_jwt_raises(self):
        with pytest.raises(TokenError):
            validate_access_token("eyJhbGciOiJIUzI1NiJ9.invalid.payload")

    def test_wrong_type_access_on_refresh_raises(self):
        refresh = create_refresh_token(1)
        with pytest.raises(TokenError):
            validate_access_token(refresh)

    def test_wrong_type_refresh_on_access_raises(self):
        access = create_access_token(1)
        with pytest.raises(TokenError):
            validate_refresh_token(access)

    def test_access_contains_purpose_and_subject(self):
        claims = validate_access_token(create_access_token(42))
        assert claims["type"] == "access"
        assert claims["sub"] == "42"

    def test_refresh_contains_purpose_and_subject(self):
        claims = validate_refresh_token(create_refresh_token(42))
        assert claims["type"] == "refresh"
        assert claims["sub"] == "42"

    def test_token_version_and_session_id_embedded(self):
        claims = validate_access_token(
            create_access_token(1, token_version=3, session_id="abc123")
        )
        assert claims["ver"] == 3
        assert claims["sid"] == "abc123"