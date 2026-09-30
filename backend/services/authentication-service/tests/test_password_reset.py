from datetime import timedelta

from sqlalchemy import select

from app.core.config import settings
from app.core.security import open_otp_flow, seal_otp_flow, validate_refresh_token
from app.core.utils import utcnow
from app.models import PasswordReset
from app.repositories import AuthRepository, token_hash
from app.services import PASSWORD_RESET_PURPOSE, PASSWORD_RESET_VERIFIED_PURPOSE
from tests.conftest import login_payload, seed_credential

PASSWORD = "Str0ngPassw#ord"
NEW_PASSWORD = "N3wP@ssw0rd!"
RESET_OTP_COOKIE = settings.reset_otp_token_cookie_name
RESET_FLOW_COOKIE = settings.reset_flow_token_cookie_name
ACCESS_COOKIE = settings.access_cookie_name
REFRESH_COOKIE = settings.refresh_cookie_name
FORGOT_MESSAGE = "If the account exists, an OTP has been sent."


def _reset_otp(client) -> str:
    token = client.cookies.get(RESET_OTP_COOKIE)
    assert token, "expected a password-reset OTP cookie"
    return open_otp_flow(token)["otp"]


def _wrong_otp(otp: str) -> str:
    return str((int(otp) + 1) % 10**settings.otp_length).zfill(settings.otp_length)


async def _forgot(client, email="alice.session@gmail.com"):
    response = await client.post(
        "/api/v1/auth/forgot-password", json={"email": email}
    )
    assert response.status_code == 200
    return response


async def _verify(client):
    response = await client.post(
        "/api/v1/auth/verify-forgot-otp", json={"otp": _reset_otp(client)}
    )
    assert response.status_code == 200
    return response


async def _reset(client, password=NEW_PASSWORD):
    response = await client.post(
        "/api/v1/auth/reset-password",
        json={"new_password": password, "confirm_password": password},
    )
    return response


class TestForgotPassword:
    async def test_existing_email_sets_cookie(self, client, session_factory):
        credential = seed_credential(session_factory, password=PASSWORD)
        response = await _forgot(client, credential.email)
        assert response.json()["message"] == FORGOT_MESSAGE
        assert client.cookies.get(RESET_OTP_COOKIE)

    async def test_non_existing_email_no_cookie(self, client, session_factory):
        response = await _forgot(client, "nobody.user@gmail.com")
        assert response.json()["message"] == FORGOT_MESSAGE
        assert client.cookies.get(RESET_OTP_COOKIE) is None

    async def test_generic_response_is_identical(self, client, session_factory):
        seed_credential(session_factory, password=PASSWORD)
        existing = await _forgot(client, "alice.session@gmail.com")
        missing = await _forgot(client, "nobody.user@gmail.com")
        assert existing.status_code == missing.status_code
        assert existing.json() == missing.json()

    async def test_otp_is_generated_and_numeric(self, client, session_factory):
        seed_credential(session_factory, password=PASSWORD)
        await _forgot(client)
        otp = _reset_otp(client)
        assert len(otp) == settings.otp_length
        assert otp.isdigit()

    async def test_resend_limit_stops_new_otps(self, client, session_factory):
        seed_credential(session_factory, password=PASSWORD)
        token_after_limit = None
        for _ in range(settings.otp_max_resends + 2):
            await _forgot(client)
            token_after_limit = client.cookies.get(RESET_OTP_COOKIE)
        before = client.cookies.get(RESET_OTP_COOKIE)
        assert token_after_limit == before


class TestVerifyForgotOtp:
    async def test_invalid_otp_rejected_with_remaining_attempts(self, client, session_factory):
        seed_credential(session_factory, password=PASSWORD)
        await _forgot(client)
        response = await client.post(
            "/api/v1/auth/verify-forgot-otp", json={"otp": _wrong_otp(_reset_otp(client))}
        )
        assert response.status_code == 400
        assert response.headers.get("x-remaining-attempts") == str(
            settings.otp_max_attempts - 1
        )

    async def test_retry_limit_exhausts(self, client, session_factory):
        seed_credential(session_factory, password=PASSWORD)
        await _forgot(client)
        wrong = _wrong_otp(_reset_otp(client))
        last_status = None
        for _ in range(settings.otp_max_attempts + 1):
            response = await client.post(
                "/api/v1/auth/verify-forgot-otp", json={"otp": wrong}
            )
            last_status = response.status_code
        assert last_status == 429

    async def test_expired_otp_rejected(self, client, session_factory):
        seed_credential(session_factory, password=PASSWORD)
        expired = seal_otp_flow(
            {
                "purpose": PASSWORD_RESET_PURPOSE,
                "email": "alice.session@gmail.com",
                "otp": "123456",
                "attempts": 0,
                "resends": 0,
            },
            ttl=timedelta(seconds=-30),
        )
        client.cookies.set(RESET_OTP_COOKIE, expired)
        response = await client.post(
            "/api/v1/auth/verify-forgot-otp", json={"otp": "123456"}
        )
        assert response.status_code == 400

    async def test_successful_verify_issues_flow_cookie(self, client, session_factory):
        seed_credential(session_factory, password=PASSWORD)
        await _forgot(client)
        await _verify(client)
        assert client.cookies.get(RESET_OTP_COOKIE) is None
        assert client.cookies.get(RESET_FLOW_COOKIE)


class TestResetPassword:
    async def test_password_mismatch_rejected(self, client, session_factory):
        seed_credential(session_factory, password=PASSWORD)
        await _forgot(client)
        await _verify(client)
        response = await client.post(
            "/api/v1/auth/reset-password",
            json={"new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD.upper()},
        )
        assert response.status_code == 422

    async def test_weak_password_rejected(self, client, session_factory):
        seed_credential(session_factory, password=PASSWORD)
        await _forgot(client)
        await _verify(client)
        response = await client.post(
            "/api/v1/auth/reset-password",
            json={"new_password": "weak", "confirm_password": "weak"},
        )
        assert response.status_code == 422

    async def test_successful_reset_and_new_password_login(self, client, session_factory):
        seed_credential(session_factory, password=PASSWORD)
        await _forgot(client)
        await _verify(client)
        response = await _reset(client)
        assert response.status_code == 200
        assert response.json()["message"] == "Password has been reset successfully."

        old_login = await client.post(
            "/api/v1/auth/login", json=login_payload("alice.session@gmail.com", PASSWORD)
        )
        assert old_login.status_code == 401
        new_login = await client.post(
            "/api/v1/auth/login",
            json=login_payload("alice.session@gmail.com", NEW_PASSWORD),
        )
        assert new_login.status_code == 200

    async def test_missing_reset_token_rejected(self, client, session_factory):
        response = await _reset(client)
        assert response.status_code == 400

    async def test_expired_reset_token_rejected(self, client, session_factory):
        credential = seed_credential(session_factory, password=PASSWORD)
        AuthRepository(session_factory()).create_password_reset(
            reset_id="a" * 32,
            user_id=credential.user_id,
            expires_at=utcnow() - timedelta(minutes=1),
        )
        token = seal_otp_flow(
            {
                "purpose": PASSWORD_RESET_VERIFIED_PURPOSE,
                "email": credential.email,
                "reset_id": "a" * 32,
            },
            ttl=timedelta(seconds=-30),
        )
        client.cookies.set(RESET_FLOW_COOKIE, token)
        response = await _reset(client)
        assert response.status_code == 400

    async def test_reused_reset_token_rejected(self, client, session_factory):
        seed_credential(session_factory, password=PASSWORD)
        await _forgot(client)
        await _verify(client)
        flow_token = client.cookies.get(RESET_FLOW_COOKIE)
        first = await _reset(client)
        assert first.status_code == 200

        client.cookies.set(RESET_FLOW_COOKIE, flow_token)
        second = await _reset(client)
        assert second.status_code == 400
        assert "already been used" in second.json()["detail"]

    async def test_old_sessions_invalidated(self, client, session_factory):
        credential = seed_credential(session_factory, password=PASSWORD)
        await client.post(
            "/api/v1/auth/login", json=login_payload(credential.email, PASSWORD)
        )
        old_access = client.cookies.get(ACCESS_COOKIE)
        old_sid = validate_refresh_token(client.cookies.get(REFRESH_COOKIE))["sid"]

        await _forgot(client)
        await _verify(client)
        await _reset(client)

        client.cookies.set(ACCESS_COOKIE, old_access)
        me = await client.get("/api/v1/auth/me")
        assert me.status_code == 401
        assert (
            AuthRepository(session_factory()).refresh_session_by_id(old_sid).revoked_at
            is not None
        )

    async def test_db_stores_only_reset_metadata(self, client, session_factory):
        seed_credential(session_factory, password=PASSWORD)
        await _forgot(client)
        await _verify(client)
        flow_token = client.cookies.get(RESET_FLOW_COOKIE)
        reset_id = open_otp_flow(flow_token)["reset_id"]

        rows = session_factory().scalars(select(PasswordReset)).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.id == reset_id
        assert row.token_hash == token_hash(reset_id)
        assert row.token_hash != flow_token
        assert row.consumed_at is None