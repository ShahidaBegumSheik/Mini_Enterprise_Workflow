from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.core.security import open_otp_flow, seal_otp_flow, verify_password
from app.schemas import RegisterRequest
from app.services import (
    InvalidOTPError,
    OTPAttemptsExhaustedError,
    OTPResendLimitExceededError,
)
from tests.conftest import VALID_INDIVIDUAL, VALID_ORGANIZATION


def model(payload: dict) -> RegisterRequest:
    return RegisterRequest(**payload)


class TestRegister:
    async def test_register_seals_flow_and_does_not_persist_anything(self, service):
        result = await service.register(model(VALID_INDIVIDUAL))
        assert "token" in result
        flow = open_otp_flow(result["token"])
        assert flow["email"] == "alice.personal@gmail.com"
        assert flow["purpose"] == "registration"
        assert flow["attempts"] == 0
        assert flow["resends"] == 0
        assert len(flow["otp"]) == 6
        assert verify_password("Str0ngPassw#ord", flow["password_hash"])
        assert service.repo.credential_by_email("alice.personal@gmail.com") is None

    async def test_duplicate_email_rejected_after_first_verified(self, service):
        result = await service.register(model(VALID_INDIVIDUAL))
        otp = open_otp_flow(result["token"])["otp"]
        await service.verify_otp(result["token"], otp)
        with pytest.raises(HTTPException) as exc:
            await service.register(model(VALID_INDIVIDUAL))
        assert exc.value.status_code == 409


class TestVerifyOtp:
    async def test_wrong_otp_increments_attempts(self, service):
        result = await service.register(model(VALID_INDIVIDUAL))
        flow = open_otp_flow(result["token"])
        wrong = "0" + flow["otp"][1:]
        with pytest.raises(InvalidOTPError) as exc:
            await service.verify_otp(result["token"], wrong)
        assert exc.value.remaining_attempts == 4
        reopened = open_otp_flow(exc.value.new_token)
        assert reopened["attempts"] == 1

    async def test_attempts_exhausted_returns_429(self, service):
        result = await service.register(model(VALID_INDIVIDUAL))
        otp = open_otp_flow(result["token"])["otp"]
        token = result["token"]
        for _ in range(5):
            with pytest.raises(InvalidOTPError) as exc:
                await service.verify_otp(token, "999999")
            token = exc.value.new_token
        with pytest.raises(OTPAttemptsExhaustedError):
            await service.verify_otp(token, otp)

    async def test_valid_otp_individual_creates_user_and_credential(self, service):
        result = await service.register(model(VALID_INDIVIDUAL))
        otp = open_otp_flow(result["token"])["otp"]
        verified = await service.verify_otp(result["token"], otp)
        assert verified["verified"] is True
        assert verified["user_id"] == 1001
        assert verified["account_type"] == "individual"
        assert service.users.created
        assert "organization_id" not in service.users.created[0]
        credential = service.repo.credential_by_email("alice.personal@gmail.com")
        assert credential is not None
        assert credential.user_id == 1001

    async def test_valid_otp_organization_creates_org_then_user(self, service):
        result = await service.register(model(VALID_ORGANIZATION))
        otp = open_otp_flow(result["token"])["otp"]
        verified = await service.verify_otp(result["token"], otp)
        assert verified["organization"]["organization_id"] == 5001
        assert service.tenants.created
        assert service.tenants.created[0]["name"] == "AcmeCorp"
        user_payload = service.users.created[0]
        assert user_payload["organization_id"] == 5001
        assert user_payload["role_code"] == "tenant_admin"
        credential = service.repo.credential_by_email("bob.ops@acmecorp.io")
        assert credential.organization_id == 5001

    async def test_expired_flow_rejected(self, service):
        past = datetime.now(timezone.utc) - timedelta(minutes=1)
        token = seal_otp_flow(
            {
                "purpose": "registration",
                "email": "alice.personal@gmail.com",
                "otp": "123456",
                "attempts": 0,
                "resends": 0,
            },
            exp_at=past,
        )
        with pytest.raises(HTTPException) as exc:
            await service.verify_otp(token, "123456")
        assert exc.value.status_code == 400
        assert "expired" in exc.value.detail.lower()


class TestResendOtp:
    async def test_resend_rotates_otp_and_resets_attempts(self, service):
        result = await service.register(model(VALID_INDIVIDUAL))
        first_otp = open_otp_flow(result["token"])["otp"]
        resent = await service.resend_otp(result["token"])
        assert resent["resend_count"] == 1
        second_otp = open_otp_flow(resent["token"])["otp"]
        assert second_otp != first_otp
        assert open_otp_flow(resent["token"])["attempts"] == 0

    async def test_resend_limit_enforced(self, service):
        result = await service.register(model(VALID_INDIVIDUAL))
        token = result["token"]
        for _ in range(3):
            token = (await service.resend_otp(token))["token"]
        with pytest.raises(OTPResendLimitExceededError):
            await service.resend_otp(token)


class TestUpstreamFailures:
    async def test_user_duplicate_conflicts(self, service):
        service.users.fail_mode = "409"
        result = await service.register(model(VALID_INDIVIDUAL))
        otp = open_otp_flow(result["token"])["otp"]
        with pytest.raises(HTTPException) as exc:
            await service.verify_otp(result["token"], otp)
        assert exc.value.status_code == 409

    async def test_organization_duplicate_conflicts(self, service):
        service.tenants.fail_mode = "409"
        result = await service.register(model(VALID_ORGANIZATION))
        otp = open_otp_flow(result["token"])["otp"]
        with pytest.raises(HTTPException) as exc:
            await service.verify_otp(result["token"], otp)
        assert exc.value.status_code == 409

    async def test_user_server_error_maps_to_502(self, service):
        service.users.fail_mode = "500"
        result = await service.register(model(VALID_INDIVIDUAL))
        otp = open_otp_flow(result["token"])["otp"]
        with pytest.raises(HTTPException) as exc:
            await service.verify_otp(result["token"], otp)
        assert exc.value.status_code == 502

    async def test_user_unreachable_maps_to_503(self, service):
        service.users.fail_mode = "connect"
        result = await service.register(model(VALID_INDIVIDUAL))
        otp = open_otp_flow(result["token"])["otp"]
        with pytest.raises(HTTPException) as exc:
            await service.verify_otp(result["token"], otp)
        assert exc.value.status_code == 503

    async def test_user_invalid_response_maps_to_502(self, service):
        service.users.fail_mode = "invalid"
        result = await service.register(model(VALID_INDIVIDUAL))
        otp = open_otp_flow(result["token"])["otp"]
        with pytest.raises(HTTPException) as exc:
            await service.verify_otp(result["token"], otp)
        assert exc.value.status_code == 502