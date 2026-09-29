"""Unit tests for the JWT verification dependency."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.dependencies.auth import (
    Principal,
    _parse_user_id,
    decode_token,
    ensure_can_access_user,
    get_current_user_id,
    require_admin,
)
from tests.conftest import create_token


def _call_with_payload(payload: dict[str, object]) -> int:
    return get_current_user_id(payload)


def test_decode_token_returns_the_claims() -> None:
    token = create_token(7, email="ada@example.com")

    payload = decode_token(token)

    assert payload["sub"] == "7"
    assert payload["email"] == "ada@example.com"


def test_decode_token_rejects_a_tampered_token() -> None:
    with pytest.raises(HTTPException) as error:
        decode_token(create_token(1, secret="another-secret"))

    assert error.value.status_code == 401
    assert error.value.detail == "Invalid or expired token"
    assert error.value.headers == {"WWW-Authenticate": "Bearer"}


def test_decode_token_rejects_an_expired_token() -> None:
    with pytest.raises(HTTPException) as error:
        decode_token(
            create_token(1, expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))
        )

    assert error.value.status_code == 401


def test_decode_token_rejects_garbage() -> None:
    for candidate in ("", "not.a.token", "....", "a" * 4096):
        with pytest.raises(HTTPException):
            decode_token(candidate)


@pytest.mark.parametrize("subject,expected", [("1", 1), (42, 42), (" 12 ", 12)])
def test_parse_user_id_accepts_numeric_subjects(
    subject: object,
    expected: int,
) -> None:
    assert _parse_user_id(subject) == expected


@pytest.mark.parametrize(
    "subject",
    ["", "  ", "abc", "0", "-1", "1.5", "1e3", True, False, None, [], {}],
)
def test_parse_user_id_rejects_invalid_subjects(subject: object) -> None:
    with pytest.raises(ValueError):
        _parse_user_id(subject)


def test_get_current_user_id_reads_the_subject() -> None:
    assert _call_with_payload(decode_token(create_token(11))) == 11


@pytest.mark.parametrize("payload", [{}, {"sub": ""}, {"sub": None}, {"sub": "abc"}])
def test_get_current_user_id_rejects_bad_subjects(
    payload: dict[str, object],
) -> None:
    with pytest.raises(HTTPException) as error:
        _call_with_payload(payload)

    assert error.value.status_code == 401


def test_require_admin_rejects_regular_users() -> None:
    with pytest.raises(HTTPException) as error:
        require_admin(Principal(user_id=1, roles=frozenset({"employee"})))

    assert error.value.status_code == 403


def test_require_admin_accepts_admin_role() -> None:
    principal = Principal(user_id=1, roles=frozenset({"ADMIN"}))

    assert require_admin(principal) is principal


def test_ensure_can_access_user_allows_self() -> None:
    ensure_can_access_user(Principal(user_id=5), 5)


def test_ensure_can_access_user_allows_admin() -> None:
    ensure_can_access_user(Principal(user_id=5, roles=frozenset({"admin"})), 9)


def test_ensure_can_access_user_rejects_other_users() -> None:
    with pytest.raises(HTTPException) as error:
        ensure_can_access_user(Principal(user_id=5), 9)

    assert error.value.status_code == 403


def test_configured_algorithm_is_used() -> None:
    assert settings.jwt_algorithm in {"HS256", "HS384", "HS512"}


def test_admin_roles_are_configurable() -> None:
    assert "admin" in settings.admin_role_set


def test_token_without_audience_is_accepted_by_default() -> None:
    assert settings.jwt_audience_or_none is None
    assert settings.jwt_issuer_or_none is None
    assert decode_token(create_token(1))["sub"] == "1"
