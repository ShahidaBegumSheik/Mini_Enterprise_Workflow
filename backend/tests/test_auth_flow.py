import pytest

from app.core.email_validation import is_personal_email, is_business_email
from helpers import (
    DEFAULT_OTP,
    INDIVIDUAL_PERSONAL_EMAIL,
    NEW_PASSWORD,
    PASSWORD,
    individual_payload,
    verify_payload,
)


def _register_and_verify(client):
    client.post("/auth/register", json=individual_payload())
    resp = client.post(
        "/auth/verify-otp",
        json=verify_payload(email=INDIVIDUAL_PERSONAL_EMAIL),
    )
    assert resp.status_code == 200


def test_login_success_sets_http_only_cookies(client):
    _register_and_verify(client)

    resp = client.post(
        "/auth/login",
        json={"email": INDIVIDUAL_PERSONAL_EMAIL, "password": PASSWORD},
    )
    assert resp.status_code == 200
    set_cookie = resp.headers.get("set-cookie", "")
    assert "access_token=" in set_cookie
    assert "refresh_token=" in set_cookie
    assert "HttpOnly" in set_cookie


def test_login_wrong_password(client):
    _register_and_verify(client)
    resp = client.post(
        "/auth/login",
        json={"email": INDIVIDUAL_PERSONAL_EMAIL, "password": "WrongPass1!"},
    )
    assert resp.status_code == 401


def test_login_unknown_email(client):
    resp = client.post(
        "/auth/login",
        json={"email": "nobody@gmail.com", "password": PASSWORD},
    )
    assert resp.status_code == 401


def test_logout_revokes_refresh_token(client):
    _register_and_verify(client)
    client.post(
        "/auth/login",
        json={"email": INDIVIDUAL_PERSONAL_EMAIL, "password": PASSWORD},
    )

    refresh_cookie = client.cookies.get("refresh_token")
    assert refresh_cookie

    resp = client.post("/auth/logout")
    assert resp.status_code == 200
    assert "access_token" not in client.cookies
    assert "refresh_token" not in client.cookies

    refresh_response = client.post("/auth/refresh-token")
    assert refresh_response.status_code == 401


def test_refresh_token_flow(client):
    _register_and_verify(client)

    old_refresh = client.cookies.get("refresh_token")
    assert old_refresh

    resp = client.post("/auth/refresh-token")
    assert resp.status_code == 200
    assert "access_token" in resp.json()
    new_refresh = client.cookies.get("refresh_token")
    assert new_refresh
    assert new_refresh != old_refresh


def test_refresh_token_missing(client):
    resp = client.post("/auth/refresh-token")
    assert resp.status_code == 401


def test_revoked_refresh_token_rejected(client):
    _register_and_verify(client)
    refresh_token = client.cookies.get("refresh_token")
    assert refresh_token

    resp = client.post("/auth/logout")
    assert resp.status_code == 200


def test_forgot_password_and_reset(client):
    _register_and_verify(client)

    forgot = client.post(
        "/auth/forgot-password",
        json={"email": INDIVIDUAL_PERSONAL_EMAIL},
    )
    assert forgot.status_code == 200
    assert "otp_token" in client.cookies

    verify = client.post(
        "/auth/verify-forgot-otp",
        json={"otp": DEFAULT_OTP},
    )
    assert verify.status_code == 200

    reset = client.post(
        "/auth/reset-password",
        json={"password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD},
    )
    assert reset.status_code == 200

    old_login = client.post(
        "/auth/login",
        json={"email": INDIVIDUAL_PERSONAL_EMAIL, "password": PASSWORD},
    )
    assert old_login.status_code == 401

    new_login = client.post(
        "/auth/login",
        json={"email": INDIVIDUAL_PERSONAL_EMAIL, "password": NEW_PASSWORD},
    )
    assert new_login.status_code == 200


def test_forgot_password_unknown_email(client):
    resp = client.post(
        "/auth/forgot-password",
        json={"email": "ghost@gmail.com"},
    )
    assert resp.status_code == 404


def test_reset_password_without_otp_verification(client):
    _register_and_verify(client)

    client.post(
        "/auth/forgot-password",
        json={"email": INDIVIDUAL_PERSONAL_EMAIL},
    )

    reset = client.post(
        "/auth/reset-password",
        json={"password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD},
    )
    assert reset.status_code == 400


def test_reset_password_wrong_otp(client):
    _register_and_verify(client)

    client.post(
        "/auth/forgot-password",
        json={"email": INDIVIDUAL_PERSONAL_EMAIL},
    )

    verify = client.post(
        "/auth/verify-forgot-otp",
        json={"otp": "999999"},
    )
    assert verify.status_code == 400


def test_reset_password_policy_enforced(client):
    _register_and_verify(client)

    client.post(
        "/auth/forgot-password",
        json={"email": INDIVIDUAL_PERSONAL_EMAIL},
    )
    client.post("/auth/verify-forgot-otp", json={"otp": DEFAULT_OTP})

    resp = client.post(
        "/auth/reset-password",
        json={"password": "short", "confirm_password": "short"},
    )
    assert resp.status_code == 422


def test_cookie_attributes(client):
    _register_and_verify(client)
    login = client.post(
        "/auth/login",
        json={"email": INDIVIDUAL_PERSONAL_EMAIL, "password": PASSWORD},
    )
    set_cookie = login.headers.get("set-cookie", "")
    assert "access_token=" in set_cookie
    assert "refresh_token=" in set_cookie
    assert "HttpOnly" in set_cookie


def test_individual_email_validation_helpers():
    assert is_personal_email("a@gmail.com")
    assert not is_personal_email("a@mycorp.io")
    assert is_business_email("help@mycorp.io")
    assert not is_business_email("help@gmail.com")