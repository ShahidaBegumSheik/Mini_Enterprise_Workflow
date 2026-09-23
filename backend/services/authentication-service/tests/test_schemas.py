import pytest
from pydantic import ValidationError

from app.schemas import OTPVerifyRequest, RegisterRequest
from tests.conftest import VALID_INDIVIDUAL, VALID_ORGANIZATION


class TestRegisterRequestEmailRules:
    def test_individual_personal_email_ok(self):
        data = {**VALID_INDIVIDUAL, "email": "alice@gmail.com"}
        model = RegisterRequest(**data)
        assert model.email == "alice@gmail.com"

    def test_individual_personal_email_normalized(self):
        data = {**VALID_INDIVIDUAL, "email": "  Alice.Personal@gmail.com "}
        model = RegisterRequest(**data)
        assert model.email == "alice.personal@gmail.com"

    def test_individual_business_email_rejected(self):
        data = {**VALID_INDIVIDUAL, "email": "alice@acmecorp.io"}
        with pytest.raises(ValidationError) as exc:
            RegisterRequest(**data)
        assert "personal email" in str(exc.value)

    def test_organization_personal_email_rejected(self):
        data = {
            **VALID_ORGANIZATION,
            "email": "bob@gmail.com",
        }
        with pytest.raises(ValidationError) as exc:
            RegisterRequest(**data)
        assert "business email" in str(exc.value)

    def test_organization_without_name_rejected(self):
        data = {**VALID_ORGANIZATION, "organization_name": None}
        with pytest.raises(ValidationError) as exc:
            RegisterRequest(**data)
        assert "Organization name is required" in str(exc.value)


class TestRegisterRequestPasswords:
    def test_password_mismatch_rejected(self):
        data = {**VALID_INDIVIDUAL, "confirm_password": "Str0ngPassw#orx"}
        with pytest.raises(ValidationError) as exc:
            RegisterRequest(**data)
        assert "must match" in str(exc.value)

    def test_weak_password_rejected(self):
        data = {**VALID_INDIVIDUAL, "password": "weakpass", "confirm_password": "weakpass"}
        with pytest.raises(ValidationError) as exc:
            RegisterRequest(**data)
        assert "Password" in str(exc.value)

    @pytest.mark.parametrize(
        "password",
        [
            "ALLUPPER123@",  # no lowercase
            "alllower123@",  # no uppercase
            "NoDigitsHere!@",  # no digit
            "NoSpecial123",  # no special
            "$pecial1A",  # starts with special (not underscore)
            "Aa1" * 30,  # too long (>72)
        ],
    )
    def test_weak_password_variants_rejected(self, password):
        data = {
            **VALID_INDIVIDUAL,
            "password": password,
            "confirm_password": password,
        }
        with pytest.raises(ValidationError):
            RegisterRequest(**data)

    def test_underscore_start_is_allowed(self):
        data = {**VALID_INDIVIDUAL, "password": "_Str0ngPassw#ord", "confirm_password": "_Str0ngPassw#ord"}
        RegisterRequest(**data)


class TestOtpVerifyRequest:
    def test_valid_otp(self):
        OTPVerifyRequest(otp="123456")

    def test_non_digit_rejected(self):
        with pytest.raises(ValidationError):
            OTPVerifyRequest(otp="12345a")

    def test_wrong_length_rejected(self):
        with pytest.raises(ValidationError):
            OTPVerifyRequest(otp="12345")