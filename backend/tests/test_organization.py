from app.models.tenant import Tenant
from app.models.user import User
from helpers import (
    DEFAULT_OTP,
    ORG_BUSINESS_EMAIL,
    ORG_PERSONAL_EMAIL,
    PASSWORD,
    organization_payload,
    verify_payload,
)


def test_business_email_accepted_for_org(client):
    resp = client.post("/auth/register", json=organization_payload())
    assert resp.status_code == 200


def test_personal_email_rejected_for_org(client):
    payload = organization_payload(email=ORG_PERSONAL_EMAIL)
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 422


def test_organization_name_required(client):
    payload = organization_payload()
    del payload["organization_name"]
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 422


def test_duplicate_org_email_rejected(client):
    first = client.post("/auth/register", json=organization_payload())
    assert first.status_code == 200
    client.post(
        "/auth/verify-otp",
        json=verify_payload(
            email=ORG_BUSINESS_EMAIL,
            account_type="organization",
            organization_name="Acme Corp",
        ),
    )
    second = client.post("/auth/register", json=organization_payload())
    assert second.status_code == 409


def test_duplicate_organization_name_rejected(client):
    first = client.post("/auth/register", json=organization_payload())
    assert first.status_code == 200
    client.post(
        "/auth/verify-otp",
        json=verify_payload(
            email=ORG_BUSINESS_EMAIL,
            account_type="organization",
            organization_name="Acme Corp",
        ),
    )

    payload = organization_payload(
        email="hr@officetech.co",
        full_name="HR Admin",
    )
    client.post("/auth/register", json=payload)
    resp = client.post(
        "/auth/verify-otp",
        json=verify_payload(
            email="hr@officetech.co",
            account_type="organization",
            organization_name="Acme Corp",
        ),
    )
    assert resp.status_code == 409


def test_organization_registration_creates_tenant_and_admin(client, db_session):
    register = client.post("/auth/register", json=organization_payload())
    assert register.status_code == 200

    verify = client.post(
        "/auth/verify-otp",
        json=verify_payload(
            email=ORG_BUSINESS_EMAIL,
            account_type="organization",
            organization_name="Acme Corp",
        ),
    )
    assert verify.status_code == 200
    data = verify.json()
    assert data["tenant_id"] is not None
    assert data["user"]["role"] == "tenant_admin"
    assert data["user"]["account_type"] == "organization"
    assert data["user"]["tenant_id"] == data["tenant_id"]

    tenant = db_session.get(Tenant, data["tenant_id"])
    assert tenant is not None
    assert tenant.name == "Acme Corp"
    assert tenant.is_active is True

    user = db_session.get(User, data["user"]["id"])
    assert user.tenant_id == tenant.id


def test_org_tenant_admin_login(client):
    client.post("/auth/register", json=organization_payload())
    client.post(
        "/auth/verify-otp",
        json=verify_payload(
            email=ORG_BUSINESS_EMAIL,
            account_type="organization",
            organization_name="Acme Corp",
        ),
    )

    login = client.post(
        "/auth/login",
        json={"email": ORG_BUSINESS_EMAIL, "password": PASSWORD},
    )
    assert login.status_code == 200
    user = login.json()["user"]
    assert user["role"] == "tenant_admin"
    assert user["account_type"] == "organization"


def test_org_invalid_otp_rejected(client):
    client.post("/auth/register", json=organization_payload())
    resp = client.post(
        "/auth/verify-otp",
        json=verify_payload(
            email=ORG_BUSINESS_EMAIL,
            otp="999999",
            account_type="organization",
            organization_name="Acme Corp",
        ),
    )
    assert resp.status_code == 400


def test_org_expired_otp_rejected(client, db_session):
    from datetime import datetime, timedelta

    from app.models.otp_verification import OTPVerification

    client.post("/auth/register", json=organization_payload())
    record = (
        db_session.query(OTPVerification)
        .filter(OTPVerification.email == ORG_BUSINESS_EMAIL)
        .first()
    )
    record.expires_at = datetime.utcnow() - timedelta(minutes=6)
    db_session.commit()

    resp = client.post(
        "/auth/verify-otp",
        json=verify_payload(
            email=ORG_BUSINESS_EMAIL,
            account_type="organization",
            organization_name="Acme Corp",
        ),
    )
    assert resp.status_code == 400


def test_org_account_type_mismatch_rejected(client):
    client.post("/auth/register", json=organization_payload())
    resp = client.post(
        "/auth/verify-otp",
        json=verify_payload(
            email=ORG_BUSINESS_EMAIL,
            account_type="individual",
        ),
    )
    assert resp.status_code in (400, 422)