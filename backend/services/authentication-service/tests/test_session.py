from datetime import timedelta

from sqlalchemy import select

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    validate_refresh_token,
)
from app.models import RefreshSession
from app.repositories import AuthRepository, token_hash
from tests.conftest import login_payload, seed_credential

ACCESS_COOKIE = settings.access_cookie_name
REFRESH_COOKIE = settings.refresh_cookie_name
OTP_COOKIE = settings.otp_token_cookie_name
PASSWORD = "Str0ngPassw#ord"


async def _login(client, session_factory):
    credential = seed_credential(session_factory, password=PASSWORD)
    response = await client.post(
        "/api/v1/auth/login", json=login_payload(credential.email, PASSWORD)
    )
    assert response.status_code == 200
    return credential


class TestRefreshToken:
    async def test_successful_refresh_sets_new_cookies_and_safe_body(self, client, session_factory):
        await _login(client, session_factory)
        old_refresh = client.cookies.get(REFRESH_COOKIE)

        response = await client.post("/api/v1/auth/refresh-token")
        assert response.status_code == 200

        body = response.json()
        assert set(body) == {
            "message",
            "user_id",
            "session_id",
            "access_token_expires_in",
            "refresh_token_expires_in",
        }
        assert "refresh_token" not in body
        assert "access_token" not in body

        new_refresh = client.cookies.get(REFRESH_COOKIE)
        assert new_refresh and new_refresh != old_refresh
        assert client.cookies.get(ACCESS_COOKIE)

    async def test_expired_refresh_token_rejected(self, client, session_factory):
        credential = await _login(client, session_factory)
        expired = create_refresh_token(credential.user_id, ttl=timedelta(days=-1))
        client.cookies.set(REFRESH_COOKIE, expired)
        response = await client.post("/api/v1/auth/refresh-token")
        assert response.status_code == 401

    async def test_invalid_refresh_token_rejected(self, client, session_factory):
        await _login(client, session_factory)
        client.cookies.set(REFRESH_COOKIE, "not.a.jwt")
        response = await client.post("/api/v1/auth/refresh-token")
        assert response.status_code == 401

    async def test_access_token_cannot_be_used_as_refresh(self, client, session_factory):
        await _login(client, session_factory)
        client.cookies.set(REFRESH_COOKIE, client.cookies.get(ACCESS_COOKIE))
        response = await client.post("/api/v1/auth/refresh-token")
        assert response.status_code == 401

    async def test_revoked_refresh_token_rejected(self, client, session_factory):
        await _login(client, session_factory)
        revoked = client.cookies.get(REFRESH_COOKIE)
        await client.post("/api/v1/auth/logout")
        client.cookies.set(REFRESH_COOKIE, revoked)
        response = await client.post("/api/v1/auth/refresh-token")
        assert response.status_code == 401
        assert "revoked" in response.json()["detail"]

    async def test_refresh_rotates_session_in_db(self, client, session_factory):
        await _login(client, session_factory)
        old_sid = validate_refresh_token(client.cookies.get(REFRESH_COOKIE))["sid"]

        response = await client.post("/api/v1/auth/refresh-token")
        assert response.status_code == 200
        new_sid = response.json()["session_id"]
        assert new_sid != old_sid
        assert validate_refresh_token(client.cookies.get(REFRESH_COOKIE))["sid"] == new_sid

        repo = AuthRepository(session_factory())
        old_row = repo.refresh_session_by_id(old_sid)
        assert old_row.revoked_at is not None
        assert old_row.replaced_by == new_sid
        new_row = repo.refresh_session_by_id(new_sid)
        assert new_row is not None
        assert new_row.revoked_at is None
        assert new_row.token_hash == token_hash(new_sid)

    async def test_reuse_of_rotated_token_detected_and_family_revoked(self, client, session_factory):
        await _login(client, session_factory)
        original = client.cookies.get(REFRESH_COOKIE)
        original_sid = validate_refresh_token(original)["sid"]

        first = await client.post("/api/v1/auth/refresh-token")
        assert first.status_code == 200
        newest_sid = first.json()["session_id"]

        client.cookies.set(REFRESH_COOKIE, original)
        second = await client.post("/api/v1/auth/refresh-token")
        assert second.status_code == 401
        assert "revoked" in second.json()["detail"]

        repo = AuthRepository(session_factory())
        assert repo.refresh_session_by_id(original_sid).revoked_at is not None
        assert repo.refresh_session_by_id(newest_sid).revoked_at is not None

    async def test_refresh_rejected_when_user_became_inactive(self, client, session_factory):
        from app.models import AuthCredential

        credential = await _login(client, session_factory)
        db = session_factory()
        row = db.scalar(
            select(AuthCredential).where(AuthCredential.user_id == credential.user_id)
        )
        row.is_active = False
        db.commit()

        response = await client.post("/api/v1/auth/refresh-token")
        assert response.status_code == 401


class TestLogout:
    async def test_logout_revokes_session_and_clears_cookies(self, client, session_factory):
        await _login(client, session_factory)
        sid = validate_refresh_token(client.cookies.get(REFRESH_COOKIE))["sid"]

        response = await client.post("/api/v1/auth/logout")
        assert response.status_code == 200
        assert response.json()["message"] == "Logged out successfully"

        assert client.cookies.get(ACCESS_COOKIE) is None
        assert client.cookies.get(REFRESH_COOKIE) is None
        assert AuthRepository(session_factory()).refresh_session_by_id(sid).revoked_at is not None

    async def test_logout_with_missing_cookies_is_safe(self, client, session_factory):
        assert client.cookies.get(REFRESH_COOKIE) is None
        response = await client.post("/api/v1/auth/logout")
        assert response.status_code == 200

    async def test_logout_clears_cookies_with_matching_attributes(self, client, session_factory):
        await _login(client, session_factory)
        response = await client.post("/api/v1/auth/logout")
        cookies_header = response.headers.get_list("set-cookie")
        names = [c.split("=", 1)[0] for c in cookies_header]
        assert ACCESS_COOKIE in names
        assert REFRESH_COOKIE in names
        assert OTP_COOKIE in names
        for raw in cookies_header:
            assert "Max-Age=0" in raw
            assert "Path=/" in raw
            assert "HttpOnly" in raw

    async def test_logout_repeated_is_idempotent(self, client, session_factory):
        await _login(client, session_factory)
        first = await client.post("/api/v1/auth/logout")
        second = await client.post("/api/v1/auth/logout")
        assert first.status_code == 200
        assert second.status_code == 200


class TestStorage:
    async def test_db_stores_only_hash_metadata_never_raw_token(self, client, session_factory):
        await _login(client, session_factory)
        refresh = client.cookies.get(REFRESH_COOKIE)
        sid = validate_refresh_token(refresh)["sid"]

        repo = AuthRepository(session_factory())
        row = repo.refresh_session_by_id(sid)
        assert row.id == sid
        assert row.token_hash == token_hash(sid)
        assert row.token_hash != refresh

        all_rows = session_factory().scalars(select(RefreshSession)).all()
        for r in all_rows:
            assert refresh not in (r.id, r.token_hash, r.replaced_by or "", r.ip_address or "")
            assert len(r.token_hash) == 64

    async def test_rotated_sessions_keep_only_hashes(self, client, session_factory):
        await _login(client, session_factory)
        olds = client.cookies.get(REFRESH_COOKIE)
        old_sid = validate_refresh_token(olds)["sid"]
        await client.post("/api/v1/auth/refresh-token")
        newest = client.cookies.get(REFRESH_COOKIE)
        new_sid = validate_refresh_token(newest)["sid"]

        all_rows = session_factory().scalars(select(RefreshSession)).all()
        ids = {r.id for r in all_rows}
        assert {old_sid, new_sid}.issubset(ids)
        assert old_sid not in newest
        for r in all_rows:
            assert r.token_hash == token_hash(r.id)
            assert r.token_hash not in (olds, newest)