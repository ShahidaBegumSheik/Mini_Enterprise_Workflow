DEFAULT_OTP = "123456"

INDIVIDUAL_PERSONAL_EMAIL = "john.doe@gmail.com"
INDIVIDUAL_BUSINESS_EMAIL = "john.doe@company.com"

ORG_BUSINESS_EMAIL = "admin@company.com"
ORG_PERSONAL_EMAIL = "admin@gmail.com"

PASSWORD = "Strong!Pass1"
NEW_PASSWORD = "New!Strong9"


def individual_payload(
    email=INDIVIDUAL_PERSONAL_EMAIL,
    password=PASSWORD,
    full_name="John Doe",
    account_type="individual",
):
    return {
        "full_name": full_name,
        "email": email,
        "password": password,
        "confirm_password": password,
        "account_type": account_type,
    }


def organization_payload(
    email=ORG_BUSINESS_EMAIL,
    password=PASSWORD,
    full_name="Jane Admin",
    organization_name="Acme Corp",
    account_type="organization",
):
    return {
        "full_name": full_name,
        "email": email,
        "password": password,
        "confirm_password": password,
        "organization_name": organization_name,
        "account_type": account_type,
    }


def verify_payload(
    email,
    otp=DEFAULT_OTP,
    password=PASSWORD,
    full_name="John Doe",
    account_type="individual",
    organization_name=None,
):
    return {
        "otp": otp,
        "full_name": full_name,
        "email": email,
        "password": password,
        "confirm_password": password,
        "account_type": account_type,
        "organization_name": organization_name,
    }