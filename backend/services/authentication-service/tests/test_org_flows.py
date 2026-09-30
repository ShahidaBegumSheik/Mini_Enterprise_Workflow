"""End-to-end organization-account flows through the public API.

Complements the (mostly individual-focused) API suites by exercising every
required public endpoint for an ``organization`` credential: registration with
business-email validation, OTP verification with mocked Tenant Admin / User
service creation, login, me, refresh, logout, forgot-password, verification
and reset-password — then re-login with the new password.
"""

from tests.conftest import (
    VALID_ORGANIZATION,
    login_payload,
    otp_from_cookie,
    seed_credential,
)

ORG_EMAIL = "bob.ops@acmecorp.io"
ORG_PASSWORD = "Str0ngPassw#ord"
NEW_ORG_PASSWORD = "New3Str#ongPass"


def _reset_otp(client) -> str:
    from app.core.security import open_otp_flow

    token = client.cookies.get("reset_otp_token")
    assert token, "expected a reset_otp_token cookie"
    return open_otp_flow(token)["otp"]


class TestOrganizationRegistration:
    async def test_register_to_verify_creates_tenant_and_user(self, client, fakes):
        resp = await client.post("/api/v1/auth/register", json=VALID_ORGANIZATION)
        assert resp.status_code == 200
        assert client.cookies.get("otp_token")

        verify = await client.post(
            "/api/v1/auth/verify-otp", json={"otp": otp_from_cookie(client)}
        )
        assert verify.status_code == 200
        body = verify.json()
        assert body["account_type"] == "organization"
        assert body["user_id"]
        assert body["organization"] is not None

        # Tenant Admin + User creation were performed via the mocked contracts.
        assert len(fakes[1].created) == 1  # tenant-admin-service.create_organization
        assert fakes[1].created[0]["name"] == VALID_ORGANIZATION["organization_name"]
        assert len(fakes[0].created) == 1  # user-service.create_user
        assert fakes[0].created[0]["account_type"] == "organization"
        assert fakes[0].created[0].get("organization_id") == 5001


class TestOrganizationLoginSession:
    async def test_login_me_refresh_logout(self, client, session_factory):
        seed_credential(session_factory, email=ORG_EMAIL, account_type="organization")

        login = await client.post(
            "/api/v1/auth/login", json=login_payload(ORG_EMAIL, ORG_PASSWORD)
        )
        assert login.status_code == 200
        assert login.json()["account_type"] == "organization"
        assert client.cookies.get("access_token")
        assert client.cookies.get("refresh_token")

        me = await client.get("/api/v1/auth/me")
        assert me.status_code == 200
        assert me.json()["user_id"]

        refresh = await client.post("/api/v1/auth/refresh-token")
        assert refresh.status_code == 200
        assert refresh.json()["session_id"]

        logout = await client.post("/api/v1/auth/logout")
        assert logout.status_code == 200
        assert not client.cookies.get("access_token")
        assert not client.cookies.get("refresh_token")


class TestOrganizationPasswordReset:
    async def test_forgot_verify_reset_then_relogin(self, client, session_factory):
        seed_credential(
            session_factory, email=ORG_EMAIL, account_type="organization"
        )

        forgot = await client.post(
            "/api/v1/auth/forgot-password", json={"email": ORG_EMAIL}
        )
        assert forgot.status_code == 200

        verify = await client.post(
            "/api/v1/auth/verify-forgot-otp", json={"otp": _reset_otp(client)}
        )
        assert verify.status_code == 200
        assert client.cookies.get("reset_flow_token")

        reset = await client.post(
            "/api/v1/auth/reset-password",
            json={"new_password": NEW_ORG_PASSWORD, "confirm_password": NEW_ORG_PASSWORD},
        )
        assert reset.status_code == 200
        assert reset.json()["message"]

        # Old password rejected; the new password logs in.
        old_login = await client.post(
            "/api/v1/auth/login", json=login_payload(ORG_EMAIL, ORG_PASSWORD)
        )
        assert old_login.status_code == 401

        new_login = await client.post(
            "/api/v1/auth/login", json=login_payload(ORG_EMAIL, NEW_ORG_PASSWORD)
        )
        assert new_login.status_code == 200
        assert new_login.json()["account_type"] == "organization"

        # Session invalidation: reset bumps token_version in the database, so every
        # access token issued before the reset is now dead.
        from app.repositories import AuthRepository

        fresh = AuthRepository(session_factory()).credential_by_email(ORG_EMAIL)
        assert fresh.token_version == 1