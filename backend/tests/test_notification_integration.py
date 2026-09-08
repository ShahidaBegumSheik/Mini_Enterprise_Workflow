import json
import logging
import urllib.error

from app.core.config import settings
from app.core.email import send_otp_email
from helpers import DEFAULT_OTP, INDIVIDUAL_PERSONAL_EMAIL, individual_payload


class FakeResponse:
    def __init__(self, status=200):
        self.status = status

    def read(self):
        return b"{}"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def raise_for_status(self):
        # urllib raises HTTPError for non-2xx; emulate for 200 only.
        if self.status >= 400:
            raise urllib.error.HTTPError(
                url="", code=self.status, msg="error", hdrs=None, fp=None
            )


def _capture(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=5):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.headers)
        captured["data"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse(200)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return captured


def test_send_otp_email_sends_authorization_header(monkeypatch):
    captured = _capture(monkeypatch)
    send_otp_email("user@example.com", "123456", "registration")

    assert captured["url"] == f"{settings.NOTIFICATION_SERVICE_URL}/send-otp"
    assert captured["headers"]["Authorization"] == (
        f"Bearer {settings.INTERNAL_API_KEY}"
    )
    content_type = {
        k.lower(): v for k, v in captured["headers"].items()
    }["content-type"]
    assert content_type == "application/json"
    assert captured["data"]["email"] == "user@example.com"
    assert captured["data"]["purpose"] == "registration"
    assert "123456" in captured["data"]["body"]


def test_send_otp_email_respects_configured_url(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        settings, "NOTIFICATION_SERVICE_URL", "http://127.0.0.1:8004"
    )

    def fake_urlopen(req, timeout=5):
        captured["url"] = req.full_url
        return FakeResponse(200)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    send_otp_email("a@b.com", "654321", "reset_password")
    assert captured["url"] == "http://127.0.0.1:8004/send-otp"


def test_send_otp_email_network_error_is_swallowed(monkeypatch, caplog):
    def broken_urlopen(req, timeout=5):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", broken_urlopen)
    with caplog.at_level(logging.WARNING):
        send_otp_email("a@b.com", "112233", "registration")
    assert "connection refused" in caplog.text.lower()


def test_send_otp_email_non_2xx_never_logs_otp(monkeypatch, caplog):
    def error_urlopen(req, timeout=5):
        raise urllib.error.HTTPError(
            url=req.full_url,
            code=503,
            msg="Service Unavailable",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr("urllib.request.urlopen", error_urlopen)
    with caplog.at_level(logging.WARNING):
        send_otp_email("a@b.com", "998877", "reset_password")
    assert "998877" not in caplog.text


def test_registration_sends_otp_to_notification_service(client, monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=5):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.headers)
        captured["data"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse(200)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    resp = client.post("/auth/register", json=individual_payload())
    assert resp.status_code == 200
    assert captured["url"].endswith("/send-otp")
    assert captured["headers"]["Authorization"] == (
        f"Bearer {settings.INTERNAL_API_KEY}"
    )
    assert captured["data"]["email"] == INDIVIDUAL_PERSONAL_EMAIL
    assert captured["data"]["purpose"] == "registration"
    assert DEFAULT_OTP in captured["data"]["body"]


def test_registration_never_logs_otp_value(client, monkeypatch, caplog, otp_codes):
    otp_codes[:] = ["424242"]

    def error_urlopen(req, timeout=5):
        raise urllib.error.URLError("down")

    monkeypatch.setattr("urllib.request.urlopen", error_urlopen)

    with caplog.at_level(logging.WARNING):
        resp = client.post("/auth/register", json=individual_payload())
    assert resp.status_code == 200
    assert "424242" not in caplog.text