from datetime import datetime, timedelta, timezone

import pytest

from app import core
from app.core import security as security_module
from app.core.security import open_otp_flow, seal_otp_flow


def make_flow(exp_at=None):
    payload = {
        "purpose": "registration",
        "email": "alice@test.dev",
        "account_type": "individual",
        "otp": "123456",
        "attempts": 0,
        "resends": 0,
    }
    return seal_otp_flow(payload, exp_at=exp_at)


class TestGenerateOtp:
    def test_digits_only(self):
        otp = security_module.generate_otp()
        assert otp.isdigit()

    def test_default_length_from_settings(self):
        assert len(security_module.generate_otp()) == 6

    def test_custom_length(self):
        assert len(security_module.generate_otp(length=8)) == 8

    def test_probably_unique(self):
        seen = {security_module.generate_otp() for _ in range(50)}
        assert len(seen) > 40


class TestCompareOtp:
    def test_match(self):
        assert security_module.compare_otp("123456", "123456") is True

    def test_mismatch(self):
        assert security_module.compare_otp("123456", "654321") is False


class TestOtpFlowToken:
    def test_roundtrip_returns_payload(self):
        token = make_flow()
        opened = open_otp_flow(token)
        assert opened["purpose"] == "registration"
        assert opened["email"] == "alice@test.dev"
        assert opened["otp"] == "123456"
        assert opened["attempts"] == 0

    def test_otp_not_visible_in_raw_token(self):
        token = make_flow()
        assert "123456" not in token

    def test_expired_token_rejected(self):
        expired = datetime.now(timezone.utc) - timedelta(minutes=1)
        with pytest.raises(ValueError, match="OTP has expired"):
            open_otp_flow(make_flow(exp_at=expired))

    def test_tampered_token_rejected(self):
        token = make_flow()
        tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
        with pytest.raises(ValueError):
            open_otp_flow(tampered)

    def test_wrong_encryption_key_rejected(self):
        from cryptography.fernet import Fernet

        token = make_flow()
        security_module._fernet_instance = None
        original = core.config.settings.otp_encryption_key
        try:
            core.config.settings.otp_encryption_key = Fernet.generate_key().decode()
            with pytest.raises(ValueError):
                open_otp_flow(token)
        finally:
            security_module._fernet_instance = None
            core.config.settings.otp_encryption_key = original


class TestPasswords:
    def test_hash_and_verify(self):
        encoded = security_module.hash_password("Str0ngPassw#ord")
        assert encoded != "Str0ngPassw#ord"
        assert security_module.verify_password("Str0ngPassw#ord", encoded)

    def test_wrong_password(self):
        encoded = security_module.hash_password("Str0ngPassw#ord")
        assert not security_module.verify_password("WrongPassw#ord1", encoded)

    def test_hashes_are_salted(self):
        first = security_module.hash_password("Str0ngPassw#ord")
        second = security_module.hash_password("Str0ngPassw#ord")
        assert first != second