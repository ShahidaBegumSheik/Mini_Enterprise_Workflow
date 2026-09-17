import pytest

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_otp,
    hash_otp,
    hash_password,
    hash_token,
    verify_otp,
    verify_password,
)


def test_generate_otp_has_configured_length():
    code = generate_otp()
    assert len(code) == settings.otp_length
    assert code.isdigit()


def test_password_hash_and_verify_roundtrip():
    encoded = hash_password("Abcdef1!")
    assert verify_password("Abcdef1!", encoded)
    assert not verify_password("wrong-password", encoded)


def test_otp_hash_and_verify_roundtrip():
    encoded = hash_otp("123456")
    assert verify_otp("123456", encoded)
    assert not verify_otp("000000", encoded)


def test_access_token_roundtrip():
    token = create_access_token(42, version=3)
    payload = decode_token(token)
    assert payload["sub"] == "42"
    assert payload["type"] == "access"
    assert payload["ver"] == 3
    assert payload["iss"] == settings.jwt_issuer
    assert payload["aud"] == settings.jwt_audience


def test_refresh_token_roundtrip():
    token = create_refresh_token(7)
    payload = decode_token(token)
    assert payload["type"] == "refresh"
    assert payload["sub"] == "7"


def test_decode_invalid_token_raises():
    with pytest.raises(ValueError):
        decode_token("not-a-valid-token")


def test_decode_token_wrong_secret_raises():
    from jose import jwt as jose_jwt
    from datetime import datetime, timedelta, timezone

    bogus = jose_jwt.encode(
        {"sub": "1"},
        "totally-different-secret",
        algorithm="HS256",
        headers=None,
    )
    with pytest.raises(ValueError):
        decode_token(bogus)


def test_hash_token_is_sha256_hex():
    assert len(hash_token("some-token")) == 64
    assert hash_token("abc") == hash_token("abc")
    assert hash_token("abc") != hash_token("abd")