from tests.conftest import VALID_INDIVIDUAL, VALID_ORGANIZATION, otp_from_cookie, register


class TestRegister:
    async def test_registers_individual_and_sets_otp_cookie(self, client, fakes):
        response = await register(client, VALID_INDIVIDUAL)
        assert response.status_code == 200
        body = response.json()
        assert "OTP sent" in body["message"]
        assert body["expires_in"] == 300

        set_cookie = response.headers["set-cookie"]
        assert "otp_token=" in set_cookie
        assert "HttpOnly" in set_cookie
        assert "SameSite=lax" in set_cookie
        assert "Max-Age=300" in set_cookie
        assert client.cookies.get("otp_token")
        assert not fakes[0].created

    async def test_registers_organization(self, client):
        response = await register(client, VALID_ORGANIZATION)
        assert response.status_code == 200
        assert client.cookies.get("otp_token")

    async def test_individual_business_email_rejected(self, client):
        data = {**VALID_INDIVIDUAL, "email": "alice@acmecorp.io"}
        response = await register(client, data)
        assert response.status_code == 422
        assert client.cookies.get("otp_token") is None

    async def test_organization_personal_email_rejected(self, client):
        data = {**VALID_ORGANIZATION, "email": "bob@gmail.com"}
        response = await register(client, data)
        assert response.status_code == 422

    async def test_organization_missing_name_rejected(self, client):
        data = {**VALID_ORGANIZATION, "organization_name": None}
        response = await register(client, data)
        assert response.status_code == 422

    async def test_password_mismatch_rejected(self, client):
        data = {**VALID_INDIVIDUAL, "confirm_password": "Str0ngPassw#orx"}
        response = await register(client, data)
        assert response.status_code == 422

    async def test_weak_password_rejected(self, client):
        data = {**VALID_INDIVIDUAL, "password": "weakpass", "confirm_password": "weakpass"}
        response = await register(client, data)
        assert response.status_code == 422


class TestVerifyOtp:
    async def test_verify_success_clears_cookie(self, client, fakes):
        await register(client, VALID_INDIVIDUAL)
        response = await client.post(
            "/api/v1/auth/verify-otp",
            json={"otp": otp_from_cookie(client)},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["verified"] is True
        assert body["user_id"] == 1001
        assert body["account_type"] == "individual"
        assert client.cookies.get("otp_token") is None
        assert fakes[0].created[0]["email"] == "alice.personal@gmail.com"

    async def test_verify_organization_full_flow(self, client, fakes):
        await register(client, VALID_ORGANIZATION)
        response = await client.post(
            "/api/v1/auth/verify-otp",
            json={"otp": otp_from_cookie(client)},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["organization"]["organization_id"] == 5001
        created_user = fakes[0].created[0]
        assert created_user["organization_id"] == 5001
        assert created_user["role_code"] == "tenant_admin"
        assert fakes[1].created[0]["name"] == "AcmeCorp"

    async def test_verify_wrong_otp_returns_remaining_attempts(self, client):
        await register(client, VALID_INDIVIDUAL)
        wrong = "000000"
        response = await client.post(
            "/api/v1/auth/verify-otp",
            json={"otp": wrong},
        )
        assert response.status_code == 400
        assert response.headers["x-remaining-attempts"] == "4"
        assert client.cookies.get("otp_token")

    async def test_verify_exhausted_attempts(self, client):
        await register(client, VALID_INDIVIDUAL)
        for _ in range(5):
            response = await client.post("/api/v1/auth/verify-otp", json={"otp": "000000"})
            assert response.status_code == 400
        response = await client.post(
            "/api/v1/auth/verify-otp",
            json={"otp": otp_from_cookie(client)},
        )
        assert response.status_code == 429
        assert client.cookies.get("otp_token") is None

    async def test_verify_without_cookie_rejected(self, client):
        response = await client.post(
            "/api/v1/auth/verify-otp", json={"otp": "123456"}
        )
        assert response.status_code == 400
        assert client.cookies.get("otp_token") is None


class TestResendOtp:
    async def test_resend_returns_new_cookie(self, client):
        await register(client, VALID_INDIVIDUAL)
        response = await client.post("/api/v1/auth/resend-otp")
        assert response.status_code == 200
        assert response.json()["resend_count"] == 1
        assert client.cookies.get("otp_token")

    async def test_resend_limit_enforced(self, client):
        await register(client, VALID_INDIVIDUAL)
        for _ in range(3):
            response = await client.post("/api/v1/auth/resend-otp")
            assert response.status_code == 200
        response = await client.post("/api/v1/auth/resend-otp")
        assert response.status_code == 429

    async def test_resend_without_cookie_rejected(self, client):
        response = await client.post("/api/v1/auth/resend-otp")
        assert response.status_code == 400


class TestDuplicateEmail:
    async def test_duplicate_across_registrations(self, client):
        await register(client, VALID_INDIVIDUAL)
        await client.post(
            "/api/v1/auth/verify-otp",
            json={"otp": otp_from_cookie(client)},
        )
        response = await register(client, VALID_INDIVIDUAL)
        assert response.status_code == 409