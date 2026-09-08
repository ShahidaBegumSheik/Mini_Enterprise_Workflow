from app.core.email_validation import is_business_email, is_personal_email
from helpers import (
    DEFAULT_OTP,
    INDIVIDUAL_BUSINESS_EMAIL,
    INDIVIDUAL_PERSONAL_EMAIL,
    PASSWORD,
    individual_payload,
    verify_payload,
)


def test_email_classification():
    assert is_personal_email("x@gmail.com")
    assert is_personal_email("x@yahoo.com")
    assert is_personal_email("x@outlook.com")
    assert not is_personal_email("x@company.com")
    assert is_business_email("x@company.com")
    assert not is_business_email("x@gmail.com")


def test_personal_email_accepted_at_register(client):
    resp = client.post("/auth/register", json=individual_payload())
    assert resp.status_code == 200
    data = resp.json()
    assert data["account_type"] == "individual"
    assert data["email"] == INDIVIDUAL_PERSONAL_EMAIL
    assert "otp_token" in client.cookies


def test_business_email_rejected_for_individual(client):
    payload = individual_payload(email=INDIVIDUAL_BUSINESS_EMAIL)
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 422


def test_register_account_type_required(client):
    payload = individual_payload()
    del payload["account_type"]
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 422


def test_register_email_required(client):
    payload = individual_payload()
    del payload["email"]
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 422


def test_register_invalid_email_format(client):
    payload = individual_payload(email="not-an-email")
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 422


def test_password_mismatch_rejected(client):
    payload = individual_payload()
    payload["confirm_password"] = "Different!Pass1"
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 422


def test_password_policy_rejected(client):
    for weak in ["short1!", "alllower1!", "ALLUPPER1!", "NoSpecial1", "nodespecial!"]:
        payload = individual_payload(password=weak)
        payload["confirm_password"] = weak
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 422, weak


def test_duplicate_email_rejected(client):
    first = client.post("/auth/register", json=individual_payload())
    assert first.status_code == 200

    client.post(
        "/auth/verify-otp",
        json=verify_payload(email=INDIVIDUAL_PERSONAL_EMAIL),
    )

    second = client.post("/auth/register", json=individual_payload())
    assert second.status_code == 409


def test_duplicate_pending_registration_rejected(client):
    first = client.post("/auth/register", json=individual_payload())
    assert first.status_code == 200
    second = client.post("/auth/register", json=individual_payload())
    assert second.status_code == 409


def test_individual_registration_and_login_flow(client):
    register = client.post("/auth/register", json=individual_payload())
    assert register.status_code == 200
    assert "otp_token" in client.cookies

    verify = client.post(
        "/auth/verify-otp",
        json=verify_payload(email=INDIVIDUAL_PERSONAL_EMAIL),
    )
    assert verify.status_code == 200
    data = verify.json()
    assert data["user"]["account_type"] == "individual"
    assert data["user"]["role"] == "individual"
    assert data["user"]["is_active"] is True
    assert data["tenant_id"] is None
    assert "access_token" in client.cookies
    assert "refresh_token" in client.cookies

    login = client.post(
        "/auth/login",
        json={"email": INDIVIDUAL_PERSONAL_EMAIL, "password": PASSWORD},
    )
    assert login.status_code == 200
    assert login.json()["user"]["email"] == INDIVIDUAL_PERSONAL_EMAIL


def test_user_not_created_before_otp_verification(client, db_session):
    from app.models.user import User

    client.post("/auth/register", json=individual_payload())
    count = db_session.query(User).count()
    assert count == 0


def test_verify_otp_without_token_unauthorized(client):
    resp = client.post(
        "/auth/verify-otp",
        json=verify_payload(email=INDIVIDUAL_PERSONAL_EMAIL),
    )
    assert resp.status_code == 401


def test_registration_otp_http_only_cookie(client, monkeypatch):
    monkeypatch.setattr("app.core.config.settings.COOKIE_HTTP_ONLY", True)
    resp = client.post("/auth/register", json=individual_payload())
    assert resp.status_code == 200
    set_cookie = resp.headers.get("set-cookie", "")
    assert "otp_token=" in set_cookie
    assert "HttpOnly" in set_cookie


def test_invalid_otp_rejected(client):
    client.post("/auth/register", json=individual_payload())
    resp = client.post(
        "/auth/verify-otp",
        json=verify_payload(email=INDIVIDUAL_PERSONAL_EMAIL, otp="999999"),
    )
    assert resp.status_code == 400


def test_expired_otp_rejected(client, db_session):
    from datetime import datetime, timedelta

    from app.models.otp_verification import OTPVerification

    client.post("/auth/register", json=individual_payload())
    record = (
        db_session.query(OTPVerification)
        .filter(OTPVerification.email == INDIVIDUAL_PERSONAL_EMAIL)
        .first()
    )
    record.expires_at = datetime.utcnow() - timedelta(minutes=6)
    db_session.commit()

    resp = client.post(
        "/auth/verify-otp",
        json=verify_payload(email=INDIVIDUAL_PERSONAL_EMAIL),
    )
    assert resp.status_code == 400


def test_otp_retry_limit_enforced(client):
    from app.core.config import settings

    client.post("/auth/register", json=individual_payload())

    for _ in range(settings.OTP_MAX_ATTEMPTS):
        resp = client.post(
            "/auth/verify-otp",
            json=verify_payload(email=INDIVIDUAL_PERSONAL_EMAIL, otp="000000"),
        )
        assert resp.status_code == 400

    resp = client.post(
        "/auth/verify-otp",
        json=verify_payload(email=INDIVIDUAL_PERSONAL_EMAIL),
    )
    assert resp.status_code == 429


def test_resend_otp_and_old_otp_invalid(client, otp_codes):
    otp_codes[:] = ["111111", "222222"]

    resp = client.post("/auth/register", json=individual_payload())
    assert resp.status_code == 200

    resp = client.post("/auth/resend-otp")
    assert resp.status_code == 200

    old_otp = client.post(
        "/auth/verify-otp",
        json=verify_payload(email=INDIVIDUAL_PERSONAL_EMAIL, otp="111111"),
    )
    assert old_otp.status_code == 400

    new_otp = client.post(
        "/auth/verify-otp",
        json=verify_payload(email=INDIVIDUAL_PERSONAL_EMAIL, otp="222222"),
    )
    assert new_otp.status_code == 200