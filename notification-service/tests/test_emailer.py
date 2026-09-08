import smtplib

import pytest

from app.config import settings
from app.emailer import EmailDeliveryError, smtp_configured
import app.emailer as emailer_module


class FakeSMTP:
    def __init__(self, *args, **kwargs):
        self.sent = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def starttls(self):
        pass

    def login(self, username, password):
        pass

    def send_message(self, message):
        self.sent = True


def test_smtp_not_configured_by_default():
    assert smtp_configured() is False


def test_send_email_raises_when_not_configured():
    assert smtp_configured() is False
    with pytest.raises(EmailDeliveryError):
        emailer_module.send_email(
            to_email="user@example.com",
            subject="subject",
            body="body",
        )


def test_send_email_success_with_tls(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_ENABLED", True)
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(settings, "SMTP_PORT", 587)
    monkeypatch.setattr(settings, "SMTP_USERNAME", "noreply@example.com")
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "secret")
    monkeypatch.setattr(settings, "SMTP_FROM_EMAIL", "noreply@example.com")
    monkeypatch.setattr(settings, "SMTP_USE_TLS", True)

    fake = FakeSMTP()
    monkeypatch.setattr(emailer_module.smtplib, "SMTP", lambda *a, **k: fake)

    try:
        emailer_module.send_email(
            to_email="user@example.com",
            subject="OTP",
            body="Your code is 123456",
        )
    finally:
        monkeypatch.setattr(settings, "SMTP_ENABLED", False)
        monkeypatch.setattr(settings, "SMTP_HOST", "")

    assert fake.sent is True


def test_send_email_smtp_failure_raises(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_ENABLED", True)
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(settings, "SMTP_FROM_EMAIL", "noreply@example.com")

    class BrokenSMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            raise smtplib.SMTPException("boom")

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(emailer_module.smtplib, "SMTP", BrokenSMTP)
    with pytest.raises(EmailDeliveryError):
        emailer_module.send_email(
            to_email="user@example.com",
            subject="OTP",
            body="code",
        )

    monkeypatch.setattr(settings, "SMTP_ENABLED", False)
    monkeypatch.setattr(settings, "SMTP_HOST", "")


def test_send_email_requires_sender(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_ENABLED", True)
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(settings, "SMTP_USERNAME", "")
    monkeypatch.setattr(settings, "SMTP_FROM_EMAIL", "")

    with pytest.raises(EmailDeliveryError):
        emailer_module.send_email(
            to_email="user@example.com",
            subject="OTP",
            body="code",
        )

    monkeypatch.setattr(settings, "SMTP_ENABLED", False)
    monkeypatch.setattr(settings, "SMTP_HOST", "")