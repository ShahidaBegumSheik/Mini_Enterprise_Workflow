import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.core.security import (
    create_access_token,
    decode_token,
    hash_token,
    verify_password,
)
from app.models.otp_flow import OTPFlow
from app.models.refresh_session import RefreshSession
from app.schemas.auth import RegisterRequest
from app.services.auth import PASSWORD_RESET_PURPOSE, REGISTRATION_PURPOSE

PASSWORD = "Abcdef1!"
EMAIL = "alice@gmail.com"


def registration_payload(account_type="individual", email=EMAIL, password=PASSWORD):
    return RegisterRequest(
        full_name="Alice Wonder",
        email=email,
        password=password,
        confirm_password=password,
        account_type=account_type,
        organization_name="Acme Corp" if account_type == "organization" else None,
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    async def test_register_creates_otp_flow(self, auth_service, session, otp_fixture):
        result = await auth_service.register(registration_payload())

        flow = session.get(OTPFlow, result["flow_id"])
        assert flow is not None
        assert flow.purpose == REGISTRATION_PURPOSE
        assert flow.email == EMAIL
        assert flow.is_used is False

    async def test_register_duplicate_email_conflicts(self, auth_service, otp_fixture):
        result = await auth_service.register(registration_payload())
        await auth_service.verify_registration(result["flow_id"], "123456")
        with pytest.raises(HTTPException) as exc:
            await auth_service.register(registration_payload())
        assert exc.value.status_code == 409

    async def test_verify_registration_conflicts_when_email_taken(
        self, auth_service, otp_fixture, user_client
    ):
        # Alice starts a flow but never verifies; Bob takes the email meanwhile.
        alice = await auth_service.register(registration_payload())
        second = await auth_service.register(registration_payload())
        await auth_service.verify_registration(second["flow_id"], "654321")
        with pytest.raises(HTTPException) as exc:
            await auth_service.verify_registration(alice["flow_id"], "123456")
        assert exc.value.status_code == 409

    async def test_verify_registration_wrong_otp_decrements_attempts(
        self, auth_service, otp_fixture
    ):
        result = await auth_service.register(registration_payload())
        verification = await auth_service.verify_registration(result["flow_id"], "000000")
        assert verification["verified"] is False
        assert verification["remaining_attempts"] == 4

    async def test_verify_registration_individual_creates_user_and_credential(
        self, auth_service, repo, user_client, otp_fixture
    ):
        result = await auth_service.register(registration_payload())
        verification = await auth_service.verify_registration(result["flow_id"], "123456")

        assert verification["verified"] is True
        assert verification["user_id"] == 1
        assert user_client.create_calls[0]["email"] == EMAIL

        credential = repo.credential_by_email(EMAIL)
        assert credential is not None
        assert credential.user_id == 1
        assert credential.account_type == "individual"
        assert credential.organization_id is None

    async def test_verify_registration_organization_creates_tenant(
        self, auth_service, repo, tenant_client, otp_fixture
    ):
        payload = registration_payload(account_type="organization", email="boss@acme.com")
        result = await auth_service.register(payload)
        verification = await auth_service.verify_registration(result["flow_id"], "123456")

        assert verification["verified"] is True
        assert tenant_client.create_calls[0]["name"] == "Acme Corp"

        credential = repo.credential_by_email("boss@acme.com")
        assert credential.organization_id == 1

    async def test_verify_registration_upstream_failure_allows_retry(
        self, auth_service, user_client, otp_fixture
    ):
        result = await auth_service.register(registration_payload())
        user_client.fail_create = True
        with pytest.raises(HTTPException) as exc:
            await auth_service.verify_registration(result["flow_id"], "123456")
        assert exc.value.status_code == 502

        user_client.fail_create = False
        verification = await auth_service.verify_registration(result["flow_id"], "123456")
        assert verification["verified"] is True

    async def test_otp_flow_exhausts_after_max_attempts(
        self, auth_service, otp_fixture
    ):
        result = await auth_service.register(registration_payload())
        for attempt in range(5):
            verification = await auth_service.verify_registration(result["flow_id"], "000000")
            assert verification["remaining_attempts"] == 4 - attempt
        with pytest.raises(HTTPException) as exc:
            await auth_service.verify_registration(result["flow_id"], "123456")
        assert exc.value.status_code == 429

    async def test_resend_otp_rotates_code_and_resets_attempts(
        self, auth_service, otp_fixture
    ):
        result = await auth_service.register(registration_payload())
        resend = await auth_service.resend_registration_otp(result["flow_id"])
        assert resend["resend_count"] == 1

        # Old code no longer valid, new code works.
        old = await auth_service.verify_registration(result["flow_id"], "123456")
        assert old["verified"] is False
        new = await auth_service.verify_registration(result["flow_id"], "654321")
        assert new["verified"] is True

    async def test_resend_otp_limit(self, auth_service, otp_fixture):
        result = await auth_service.register(registration_payload())
        for _ in range(settings_otp_max_resends()):
            await auth_service.resend_registration_otp(result["flow_id"])
        with pytest.raises(HTTPException) as exc:
            await auth_service.resend_registration_otp(result["flow_id"])
        assert exc.value.status_code == 429


def settings_otp_max_resends():
    from app.core.config import settings

    return settings.otp_max_resends


# ---------------------------------------------------------------------------
# Login / refresh / logout
# ---------------------------------------------------------------------------


async def registered_user(auth_service, otp_fixture, user_client=None):
    result = await auth_service.register(registration_payload())
    await auth_service.verify_registration(result["flow_id"], "123456")


class TestLogin:
    async def test_login_success_issues_tokens_and_session(
        self, auth_service, session, otp_fixture
    ):
        await registered_user(auth_service, otp_fixture)
        result = await auth_service.login(EMAIL, PASSWORD, ip_address="127.0.0.1", user_agent="pytest")
        assert result["access_token"]
        assert result["refresh_token"]
        payload = decode_token(result["access_token"])
        assert payload["type"] == "access"

        stored = session.scalar(select(RefreshSession))
        assert stored is not None
        assert stored.token_hash == hash_token(result["refresh_token"])
        assert stored.ip_address == "127.0.0.1"

    async def test_login_wrong_password(self, auth_service, otp_fixture):
        await registered_user(auth_service, otp_fixture)
        with pytest.raises(HTTPException) as exc:
            await auth_service.login(EMAIL, "Wrongpass1!")
        assert exc.value.status_code == 401

    async def test_login_unknown_email(self, auth_service):
        with pytest.raises(HTTPException) as exc:
            await auth_service.login("nobody@gmail.com", PASSWORD)
        assert exc.value.status_code == 401

    async def test_login_inactive_account_forbidden(self, auth_service, repo, otp_fixture):
        await registered_user(auth_service, otp_fixture)
        credential = repo.credential_by_email(EMAIL)
        credential.is_active = False
        repo.db.commit()
        with pytest.raises(HTTPException) as exc:
            await auth_service.login(EMAIL, PASSWORD)
        assert exc.value.status_code == 403


class TestRefresh:
    async def test_refresh_rotates_session(self, auth_service, repo, otp_fixture):
        await registered_user(auth_service, otp_fixture)
        result = await auth_service.login(EMAIL, PASSWORD)
        old_token = result["refresh_token"]

        refreshed = auth_service.refresh(old_token)
        assert refreshed["access_token"]
        assert refreshed["refresh_token"] != old_token

        old_session = repo.refresh_session_by_hash(hash_token(old_token))
        assert old_session.is_revoked is True

        with pytest.raises(HTTPException) as exc:
            auth_service.refresh(old_token)
        assert exc.value.status_code == 401

    async def test_logout_revokes_tokens(self, auth_service, repo, otp_fixture):
        await registered_user(auth_service, otp_fixture)
        result = await auth_service.login(EMAIL, PASSWORD)
        access = result["access_token"]
        refresh = result["refresh_token"]

        auth_service.logout(refresh)

        session = repo.refresh_session_by_hash(hash_token(refresh))
        assert session.is_revoked is True

        with pytest.raises(HTTPException) as exc:
            auth_service.validate_access(access)
        assert exc.value.status_code == 401


# ---------------------------------------------------------------------------
# Forgot password / reset
# ---------------------------------------------------------------------------


class TestPasswordReset:
    async def test_forgot_password_unknown_email_hides_account(self, auth_service):
        result = await auth_service.forgot_password("ghost@gmail.com")
        assert result is None

    async def test_full_reset_flow(self, auth_service, repo, otp_fixture):
        await registered_user(auth_service, otp_fixture)
        await auth_service.login(EMAIL, PASSWORD)

        flow = await auth_service.forgot_password(EMAIL)
        assert flow is not None

        stored = repo.otp_flow_by_id(flow["flow_id"])
        assert stored.purpose == PASSWORD_RESET_PURPOSE
        assert stored.context == {"user_id": 1}

        failed = auth_service.verify_reset_otp(flow["flow_id"], "000000")
        assert failed["verified"] is False
        assert failed["remaining_attempts"] == 4

        verified = auth_service.verify_reset_otp(flow["flow_id"], "654321")
        assert verified["verified"] is True
        assert verified["verified_token"]

        new_password = "Newpass2!"
        auth_service.reset_password(verified["verified_token"], new_password)

        credential = repo.credential_by_email(EMAIL)
        assert verify_password(new_password, credential.password_hash)

        with pytest.raises(HTTPException):
            await auth_service.login(EMAIL, PASSWORD)
        login = await auth_service.login(EMAIL, new_password)
        assert login["access_token"]

    async def test_reset_password_rejects_current_password(
        self, auth_service, otp_fixture
    ):
        await registered_user(auth_service, otp_fixture)
        flow = await auth_service.forgot_password(EMAIL)
        verified = auth_service.verify_reset_otp(flow["flow_id"], "654321")
        with pytest.raises(HTTPException) as exc:
            auth_service.reset_password(verified["verified_token"], PASSWORD)
        assert exc.value.status_code == 400


# ---------------------------------------------------------------------------
# Session validation
# ---------------------------------------------------------------------------


class TestValidateAccess:
    async def test_validate_access_happy_path(self, auth_service, otp_fixture):
        await registered_user(auth_service, otp_fixture)
        token = create_access_token(1, 0)
        credential = auth_service.validate_access(token)
        assert credential.user_id == 1

    async def test_validate_access_rejects_wrong_version(self, auth_service, otp_fixture):
        await registered_user(auth_service, otp_fixture)
        token = create_access_token(1, version=99)
        with pytest.raises(HTTPException) as exc:
            auth_service.validate_access(token)
        assert exc.value.status_code == 401

    async def test_validate_access_rejects_garbage(self, auth_service):
        with pytest.raises(HTTPException):
            auth_service.validate_access("garbage-token")