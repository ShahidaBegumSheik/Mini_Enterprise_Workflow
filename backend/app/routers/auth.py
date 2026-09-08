from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.cookies import (
    clear_auth_cookies,
    clear_otp_token_cookie,
)
from app.db.session import get_db
from app.services.auth_service import (
    AuthenticationService,
    _validate_otp_token_cookie,
)
from app.schemas.auth import (
    ForgotPasswordRequest,
    IndividualRegisterRequest,
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    MessageResponse,
    OTPVerifyResponse,
    OrganizationRegisterRequest,
    RefreshTokenResponse,
    RegisterResponse,
    ResendOTPResponse,
    ResetPasswordRequest,
    VerifyAccountRequest,
    VerifyForgotOTPRequest,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _auth(db: Session = Depends(get_db)) -> AuthenticationService:
    return AuthenticationService(db)


def _require_otp_context(
    otp_token: str | None = Cookie(default=None),
) -> dict:
    return _validate_otp_token_cookie(otp_token)


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_200_OK,
    summary="Register an individual or organization account",
    description=(
        "Validates the registration details, generates an OTP, stores a "
        "signed OTP token in the `otp_token` HTTP-only cookie and sends the "
        "OTP to the provided email. The account is NOT created until the OTP "
        "is verified via `/auth/verify-otp`."
    ),
    responses={
        409: {"description": "Email already registered"},
        422: {"description": "Validation error"},
    },
)
def register(
    payload: IndividualRegisterRequest | OrganizationRegisterRequest,
    response: Response,
    auth: AuthenticationService = Depends(_auth),
):
    context = auth.initiate_registration(payload)
    auth.generate_registration_otp(context, response)
    return RegisterResponse(
        message="OTP sent to your email. Please verify to complete registration.",
        email=str(payload.email).lower(),
        account_type=payload.account_type,
        otp_expires_in_minutes=settings.OTP_EXPIRE_MINUTES,
    )


@router.post(
    "/verify-otp",
    response_model=OTPVerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify OTP and complete registration",
    description=(
        "Verifies the OTP sent during registration. On success the user is "
        "created and activated and access/refresh tokens are stored in "
        "HTTP-only cookies. Requires the `otp_token` cookie from "
        "`/auth/register`."
    ),
    responses={
        400: {"description": "Invalid/expired OTP or mismatched details"},
        401: {"description": "Missing/invalid OTP token"},
    },
)
def verify_otp(
    payload: VerifyAccountRequest,
    response: Response,
    context: dict = Depends(_require_otp_context),
    auth: AuthenticationService = Depends(_auth),
):
    result = auth.complete_registration(context, payload, response)
    clear_otp_token_cookie(response)
    return OTPVerifyResponse(
        message=result["message"],
        user=result["user"],
        tenant_id=result["tenant_id"],
    )


@router.post(
    "/resend-otp",
    response_model=ResendOTPResponse,
    status_code=status.HTTP_200_OK,
    summary="Resend registration OTP",
    description=(
        "Sends a new OTP for an in-progress registration. The previous OTP is "
        "invalidated. Requires the `otp_token` cookie. Enforces a resend "
        "cooldown."
    ),
    responses={
        401: {"description": "Missing/invalid OTP token"},
        429: {"description": "Resend cooldown not elapsed"},
    },
)
def resend_otp(
    response: Response,
    context: dict = Depends(_require_otp_context),
    auth: AuthenticationService = Depends(_auth),
):
    result = auth.resend_registration_otp(context, response)
    return ResendOTPResponse(
        message="A new OTP has been sent to your email.",
        email=result["email"],
        otp_expires_in_minutes=settings.OTP_EXPIRE_MINUTES,
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Log in an existing account",
    description=(
        "Authenticates using email and password for individual, tenant admin "
        "and tenant users. On success, access and refresh tokens are stored "
        "in HTTP-only cookies."
    ),
    responses={
        401: {"description": "Invalid credentials"},
        403: {"description": "Account is not active"},
    },
)
def login(
    payload: LoginRequest,
    response: Response,
    auth: AuthenticationService = Depends(_auth),
):
    result = auth.login(payload, response)
    return LoginResponse(message="Login successful", user=result["user"])


@router.post(
    "/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Log out the current session",
    description=(
        "Revokes the server-side refresh token and clears the access and "
        "refresh token HTTP-only cookies."
    ),
)
def logout(
    response: Response,
    refresh_token: str | None = Cookie(
        default=None, alias=settings.REFRESH_TOKEN_COOKIE
    ),
    auth: AuthenticationService = Depends(_auth),
):
    auth.logout(refresh_token)
    clear_auth_cookies(response)
    return LogoutResponse(message="Logged out successfully")


@router.post(
    "/refresh-token",
    response_model=RefreshTokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token",
    description=(
        "Validates the refresh token in the `refresh_token` HTTP-only cookie "
        "and issues a new access token (and rotates the refresh token)."
    ),
    responses={
        401: {"description": "Missing/invalid/expired/revoked refresh token"},
    },
)
def refresh_token(
    response: Response,
    refresh_token: str | None = Cookie(
        default=None, alias=settings.REFRESH_TOKEN_COOKIE
    ),
    auth: AuthenticationService = Depends(_auth),
):
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing",
        )
    new_access = auth.rotate_refresh(refresh_token, response)
    return RefreshTokenResponse(access_token=new_access)


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Request a password reset OTP",
    description=(
        "Sends an OTP to the given registered email and stores an OTP token "
        "in the `otp_token` HTTP-only cookie. The email must exist."
    ),
    responses={
        404: {"description": "No account found with this email"},
    },
)
def forgot_password(
    payload: ForgotPasswordRequest,
    response: Response,
    auth: AuthenticationService = Depends(_auth),
):
    auth.initiate_forgot_password(str(payload.email), response)
    return MessageResponse(
        message="If the email is registered, an OTP has been sent."
    )


@router.post(
    "/verify-forgot-otp",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify the password reset OTP",
    description=(
        "Verifies the OTP for a password reset. Requires the `otp_token` "
        "cookie from `/auth/forgot-password`. After verification, call "
        "`/auth/reset-password`."
    ),
    responses={
        400: {"description": "Invalid/expired OTP"},
        401: {"description": "Missing/invalid OTP token"},
    },
)
def verify_forgot_otp(
    payload: VerifyForgotOTPRequest,
    context: dict = Depends(_require_otp_context),
    auth: AuthenticationService = Depends(_auth),
):
    auth.verify_forgot_password_otp(context, payload.otp)
    return MessageResponse(
        message="OTP verified. You may now reset your password."
    )


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Reset the account password",
    description=(
        "Sets a new password after a verified reset OTP. Requires the "
        "`otp_token` cookie and a previously verified OTP. The old password "
        "stops working immediately."
    ),
    responses={
        400: {"description": "OTP not verified or validation failed"},
        401: {"description": "Missing/invalid OTP token"},
    },
)
def reset_password(
    payload: ResetPasswordRequest,
    context: dict = Depends(_require_otp_context),
    auth: AuthenticationService = Depends(_auth),
):
    auth.reset_password(context, payload.password)
    return MessageResponse(message="Password reset successfully")
