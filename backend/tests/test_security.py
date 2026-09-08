import pytest
from jose import JWTError, jwt

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_otp_token,
    create_refresh_token,
    decode_token,
    generate_otp,
    hash_otp,
    hash_password,
    verify_otp,
    verify_password,
)


def test_hash_password_and_verify():
    hashed = hash_password("Strong!Pass1")
    assert hashed != "Strong!Pass1"
    assert verify_password("Strong!Pass1", hashed)
    assert not verify_password("Wrong!Pass1", hashed)


def test_generate_otp_is_numeric_and_6_digits():
    otps = {generate_otp() for _ in range(50)}
    assert len(otps) > 40
    for otp in otps:
        assert len(otp) == 6
        assert otp.isdigit()


def test_hash_otp_and_verify():
    h = hash_otp("123456")
    assert h != "123456"
    assert verify_otp("123456", h)
    assert not verify_otp("654321", h)


def test_access_token_roundtrip():
    token = create_access_token({"sub": "42"})
    payload = decode_token(token)
    assert payload["sub"] == "42"
    assert payload["type"] == "access"
    assert "exp" in payload


def test_refresh_token_roundtrip_has_jti():
    token = create_refresh_token({"sub": "42"})
    payload = decode_token(token)
    assert payload["sub"] == "42"
    assert payload["type"] == "refresh"
    assert payload["jti"]


def test_otp_token_roundtrip():
    token = create_otp_token({"purpose": "registration", "email": "a@b.com"})
    payload = decode_token(token)
    assert payload["type"] == "otp"
    assert payload["purpose"] == "registration"
    assert payload["email"] == "a@b.com"


def test_decode_invalid_token_raises():
    with pytest.raises(JWTError):
        decode_token("not.a.jwt")


def test_access_token_bad_secret_rejected():
    token = jwt.encode(
        {"sub": "1", "type": "access"},
        "wrong-secret",
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(JWTError):
        decode_token(token)


def test_token_expiry_honored():
    import time

    from datetime import datetime, timedelta, timezone

    expired = jwt.encode(
        {
            "sub": "1",
            "type": "access",
            "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
        },
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(JWTError):
        decode_token(expired)