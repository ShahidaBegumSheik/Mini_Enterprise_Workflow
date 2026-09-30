import json

import httpx
import pytest
from fastapi import HTTPException

from app.clients.contracts import (
    NTF_FORGOT_PASSWORD_OTP,
    NTF_INDIVIDUAL_REGISTRATION_OTP,
    NTF_ORGANIZATION_REGISTRATION_OTP,
    ServiceCallError,
)
from app.clients.notification_service import NotificationServiceClient
from app.schemas import RegisterRequest
from tests.conftest import VALID_INDIVIDUAL, VALID_ORGANIZATION, seed_credential

NOTIFY_URL = "http://notification-test"


def model(payload: dict) -> RegisterRequest:
    return RegisterRequest(**payload)


def _client(handler) -> NotificationServiceClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return NotificationServiceClient(http, base_url=NOTIFY_URL, internal_api_key="test-key")


class TestNotificationClient:
    async def test_registration_otp_notification(self):
        captured = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(200, json={"message": "queued"})

        client = _client(handler)
        await client.send_email_notification(
            recipient_email="alice@gmail.com",
            event_type=NTF_INDIVIDUAL_REGISTRATION_OTP,
            template_variables={"otp": "123456", "expires_in_minutes": 5},
        )

        assert len(captured) == 1
        req = captured[0]
        assert req.method == "POST"
        assert req.url.path == "/api/v1/internal/notifications"
        assert req.headers.get("X-Internal-API-Key") == "test-key"
        body = json.loads(req.read().decode())
        assert body["recipient_email"] == "alice@gmail.com"
        assert body["event_type"] == NTF_INDIVIDUAL_REGISTRATION_OTP
        assert body["template_variables"] == {
            "otp": "123456",
            "expires_in_minutes": 5,
        }

    async def test_organization_otp_notification(self):
        captured = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(200, json={"message": "queued"})

        client = _client(handler)
        await client.send_email_notification(
            recipient_email="bob@acmecorp.io",
            event_type=NTF_ORGANIZATION_REGISTRATION_OTP,
            template_variables={"otp": "654321", "expires_in_minutes": 5},
        )

        body = json.loads(captured[0].read().decode())
        assert body["event_type"] == NTF_ORGANIZATION_REGISTRATION_OTP
        assert body["template_variables"]["otp"] == "654321"

    async def test_forgot_password_otp_notification(self):
        captured = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(200, json={"message": "queued"})

        client = _client(handler)
        await client.send_email_notification(
            recipient_email="alice@gmail.com",
            event_type=NTF_FORGOT_PASSWORD_OTP,
            template_variables={"otp": "111222", "expires_in_minutes": 5},
        )

        body = json.loads(captured[0].read().decode())
        assert body["event_type"] == NTF_FORGOT_PASSWORD_OTP
        assert body["template_variables"]["otp"] == "111222"

    async def test_payload_never_contains_password_or_token_fields(self):
        captured = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(200, json={"message": "queued"})

        client = _client(handler)
        for event in (
            NTF_INDIVIDUAL_REGISTRATION_OTP,
            NTF_ORGANIZATION_REGISTRATION_OTP,
            NTF_FORGOT_PASSWORD_OTP,
        ):
            await client.send_email_notification(
                recipient_email="someone@gmail.com",
                event_type=event,
                template_variables={"otp": "000000", "expires_in_minutes": 5},
            )

        forbidden = {"password", "access_token", "refresh_token", "jwt", "token"}
        for req in captured:
            body = json.loads(req.read().decode())
            assert set(body.keys()) == {"recipient_email", "event_type", "template_variables"}
            assert forbidden.isdisjoint(body.keys())
            assert forbidden.isdisjoint(body["template_variables"].keys())

    async def test_timeout_retried_once_then_succeeds(self):
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise httpx.ReadTimeout("notification-service read timeout")
            return httpx.Response(200, json={"message": "queued"})

        client = _client(handler)
        await client.send_email_notification(
            recipient_email="x@gmail.com",
            event_type=NTF_FORGOT_PASSWORD_OTP,
            template_variables={"otp": "000000"},
        )
        assert calls == 2

    async def test_unavailable_is_not_retried(self):
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            raise httpx.ConnectError("notification-service unreachable")

        client = _client(handler)
        with pytest.raises(httpx.ConnectError):
            await client.send_email_notification(
                recipient_email="x@gmail.com",
                event_type=NTF_FORGOT_PASSWORD_OTP,
                template_variables={"otp": "000000"},
            )
        assert calls == 1

    async def test_4xx_raises_service_call_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(422, text="unknown event_type")

        client = _client(handler)
        with pytest.raises(ServiceCallError) as exc:
            await client.send_email_notification(
                recipient_email="x@gmail.com",
                event_type="bogus_event",
                template_variables={},
            )
        assert exc.value.status_code == 422

    async def test_5xx_raises_service_call_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="smtp unavailable")

        client = _client(handler)
        with pytest.raises(ServiceCallError) as exc:
            await client.send_email_notification(
                recipient_email="x@gmail.com",
                event_type=NTF_FORGOT_PASSWORD_OTP,
                template_variables={"otp": "000000"},
            )
        assert exc.value.status_code == 503


class TestNotificationIntegration:
    async def test_individual_register_sends_notification(self, service, fakes):
        result = await service.register(model(VALID_INDIVIDUAL))
        assert "token" in result
        notifications = fakes[2].sent
        assert len(notifications) == 1
        assert notifications[0]["recipient_email"] == "alice.personal@gmail.com"
        assert notifications[0]["event_type"] == NTF_INDIVIDUAL_REGISTRATION_OTP
        assert "otp" in notifications[0]["template_variables"]
        assert "password" not in notifications[0]["template_variables"]

    async def test_organization_register_sends_notification(self, service, fakes):
        result = await service.register(model(VALID_ORGANIZATION))
        assert "token" in result
        notifications = fakes[2].sent
        assert len(notifications) == 1
        assert notifications[0]["recipient_email"] == "bob.ops@acmecorp.io"
        assert notifications[0]["event_type"] == NTF_ORGANIZATION_REGISTRATION_OTP
        assert "otp" in notifications[0]["template_variables"]

    async def test_forgot_password_sends_notification(self, service, fakes, session_factory):
        credential = seed_credential(session_factory, email="alice.session@gmail.com")
        token = await service.forgot_password(credential.email)
        assert token
        notifications = fakes[2].sent
        assert len(notifications) == 1
        assert notifications[0]["recipient_email"] == credential.email
        assert notifications[0]["event_type"] == NTF_FORGOT_PASSWORD_OTP
        assert "otp" in notifications[0]["template_variables"]

    async def test_register_notification_down_maps_to_503(self, service, fakes):
        fakes[2].fail_mode = "unavailable"
        with pytest.raises(HTTPException) as exc:
            await service.register(model(VALID_INDIVIDUAL))
        assert exc.value.status_code == 503
        assert "notification-service" in exc.value.detail

    async def test_register_notification_5xx_maps_to_502(self, service, fakes):
        fakes[2].fail_mode = "5xx"
        with pytest.raises(HTTPException) as exc:
            await service.register(model(VALID_INDIVIDUAL))
        assert exc.value.status_code == 502

    async def test_forgot_password_never_leaks_account_exists_on_failure(self, service, fakes, session_factory):
        seed_credential(session_factory, email="alice.session@gmail.com")
        fakes[2].fail_mode = "unavailable"
        token = await service.forgot_password("alice.session@gmail.com")
        assert token is not None
        assert len(fakes[2].sent) == 1
