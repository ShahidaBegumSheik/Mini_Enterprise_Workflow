from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from app.core.cookies import (
    clear_auth_cookies,
    clear_otp_token_cookie,
    clear_reset_flow_token_cookie,
    clear_reset_otp_token_cookie,
    set_access_token_cookie,
    set_otp_token_cookie,
    set_refresh_token_cookie,
    set_reset_flow_token_cookie,
    set_reset_otp_token_cookie,
)
from app.core.config import settings
from app.routers.dependencies import get_current_user, get_service
from app.schemas import (
    ErrorResponse,
    ForgotPasswordRequest,
    LoginRequest,
    LoginResponse,
    MeResponse,
    MessageResponse,
    OTPVerifyRequest,
    RefreshResponse,
    RegisterRequest,
    RegistrationVerifiedResponse,
    ResetPasswordRequest,
)
from app.services import (
    AuthService,
    InvalidOTPError,
    OTPAttemptsExhaustedError,
    OTPResendLimitExceededError,
)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

MISSING_OTP_TOKEN = "OTP flow token is missing or expired. Please register again."
MISSING_RESET_OTP_TOKEN = (
    "Password reset OTP token is missing or expired. Please request a new one."
)
MISSING_RESET_FLOW_TOKEN = (
    "Password reset token is missing or expired. Please request a new one."
)
FORGOT_PASSWORD_GENERIC_MESSAGE = "If the account exists, an OTP has been sent."


def _error_responses(error_map: dict[int, str]) -> dict:
    """Build OpenAPI ``responses`` entries for the service's business errors.

    All business errors share the ``{"detail": str}`` shape; FastAPI still
    auto-documents its own 422 `HTTPValidationError` for request bodies.
    """
    return {
        status_code: {"model": ErrorResponse, "description": description}
        for status_code, description in error_map.items()
    }


_COOKIE_AUTH_NOTE = (
    "Tokens never leave the browser: they are set and read exclusively as "
    "HttpOnly cookies by the service. Nothing sensitive is returned in bodies."
)


def _cookie_name() -> str:
    return settings.otp_token_cookie_name


def _otp_cookie(request: Request) -> str | None:
    return request.cookies.get(_cookie_name())


def _error_response(status_code: int, detail: str, headers: dict | None = None):
    """Error response so we can still manipulate the OTP cookie on it.

    Raising an HTTPException would make FastAPI build a fresh error response
    and would discard any cookies already set on this response object.
    """
    return JSONResponse(
        content={"detail": detail},
        status_code=status_code,
        headers=headers,
    )


@router.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Register an account (email OTP)",
    description=(
        "Validates the registration (individual or organization), generates a numeric OTP "
        "and stores the encrypted, short-lived OTP flow inside the `otp_token` HttpOnly "
        "cookie. The OTP email is delivered through the Notification Service. "
        "Nothing about the account is persisted until the OTP is verified. "
        + _COOKIE_AUTH_NOTE
    ),
    responses=_error_responses(
        {
            409: "An account with this email already exists",
            502: "Notification Service rejected the OTP request",
            503: "Notification Service is unreachable",
        }
    ),
)
async def register(
    data: RegisterRequest,
    response: Response,
    service: AuthService = Depends(get_service),
):
    result = await service.register(data)
    set_otp_token_cookie(response, result["token"])
    return MessageResponse(
        message="OTP sent successfully. Please verify within "
        f"{settings.otp_expire_minutes} minutes.",
        expires_in=result["expires_in"],
    )


@router.post(
    "/verify-otp",
    response_model=RegistrationVerifiedResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify the registration OTP",
    description=(
        "Verifies the OTP from the `otp_token` cookie. On success the user (and, for "
        "organization accounts, the organization) is created through the User Service "
        "and Tenant Admin Service contracts, the credential is stored, and the flow "
        "cookie is cleared. Wrong OTPs consume attempts (see `x-remaining-attempts`). "
        + _COOKIE_AUTH_NOTE
    ),
    responses=_error_responses(
        {
            400: "Missing or invalid OTP / expired flow token",
            409: "Email is already registered",
            429: "Too many incorrect OTP attempts",
            502: "User/Tenant Admin Service dependency failed",
            503: "A required service dependency is unreachable",
        }
    ),
)
async def verify_otp(
    data: OTPVerifyRequest,
    response: Response,
    request: Request,
    otp_cookie: str | None = Cookie(None, alias=_cookie_name()),
    service: AuthService = Depends(get_service),
):
    token = otp_cookie or _otp_cookie(request)
    if not token:
        error = _error_response(status.HTTP_400_BAD_REQUEST, MISSING_OTP_TOKEN)
        clear_otp_token_cookie(error)
        return error

    try:
        result = await service.verify_otp(token, data.otp)
    except InvalidOTPError as exc:
        error = _error_response(
            status.HTTP_400_BAD_REQUEST,
            "Invalid OTP",
            headers={"x-remaining-attempts": str(exc.remaining_attempts)},
        )
        set_otp_token_cookie(error, exc.new_token)
        return error
    except OTPAttemptsExhaustedError as exc:
        error = _error_response(status.HTTP_429_TOO_MANY_REQUESTS, exc.detail)
        clear_otp_token_cookie(error)
        return error
    except HTTPException as exc:
        error = _error_response(exc.status_code, exc.detail, dict(exc.headers or {}))
        clear_otp_token_cookie(error)
        return error

    clear_otp_token_cookie(response)
    return RegistrationVerifiedResponse(**result)


@router.post(
    "/resend-otp",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Resend the registration OTP",
    description=(
        "Rotates the OTP inside the `otp_token` cookie and re-delivers it via the "
        "Notification Service. Resends are bounded by `OTP_MAX_RESENDS`. "
        + _COOKIE_AUTH_NOTE
    ),
    responses=_error_responses(
        {
            400: "Missing or expired OTP flow token cookie",
            429: "OTP resend limit exceeded",
        }
    ),
)
async def resend_otp(
    response: Response,
    request: Request,
    otp_cookie: str | None = Cookie(None, alias=_cookie_name()),
    service: AuthService = Depends(get_service),
):
    token = otp_cookie or _otp_cookie(request)
    if not token:
        error = _error_response(status.HTTP_400_BAD_REQUEST, MISSING_OTP_TOKEN)
        clear_otp_token_cookie(error)
        return error

    try:
        result = await service.resend_otp(token)
    except OTPResendLimitExceededError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=exc.detail) from exc
    except HTTPException as exc:
        raise exc from exc

    set_otp_token_cookie(response, result["token"])
    return MessageResponse(
        message="OTP re-sent successfully.",
        resend_count=result["resend_count"],
        expires_in=result["expires_in"],
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Log in and start a session",
    description=(
        "Validates credentials and starts a refresh-token session. The access and refresh "
        "JWTs are delivered only as HttpOnly cookies; the response carries safe session "
        "metadata (`session_id`, expiries) and never the tokens. "
        + _COOKIE_AUTH_NOTE
    ),
    responses=_error_responses(
        {
            401: "Incorrect email or password",
            403: "Account is inactive or not verified",
        }
    ),
)
async def login(
    data: LoginRequest,
    response: Response,
    request: Request,
    service: AuthService = Depends(get_service),
):
    result = await service.login(
        str(data.email).lower(),
        data.password,
        device_info=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
    # Tokens are delivered strictly via HttpOnly cookies, never in the body.
    set_access_token_cookie(response, result["access_token"])
    set_refresh_token_cookie(response, result["refresh_token"])
    return LoginResponse(
        message="Login successful",
        user_id=result["user_id"],
        email=result["email"],
        account_type=result["account_type"],
        session_id=result["session_id"],
        access_token_expires_in=result["access_token_expires_in"],
        refresh_token_expires_in=result["refresh_token_expires_in"],
    )


@router.get(
    "/me",
    response_model=MeResponse,
    status_code=status.HTTP_200_OK,
    summary="Current authenticated principal",
    description=(
        "Returns the current user. Authenticates using only the HttpOnly `access_token` "
        "cookie set by POST /login; the profile is resolved through the User Service "
        "contract (`GET /api/v1/internal/users/{id}`), never from another database. "
        + _COOKIE_AUTH_NOTE
    ),
    responses=_error_responses(
        {
            401: "Missing, invalid, expired or revoked access token",
        }
    ),
)
async def me(current_user: dict = Depends(get_current_user)):
    return {
        "user_id": current_user["user_id"],
        "email": current_user.get("email"),
        "account_type": current_user.get("account_type"),
    }


@router.post(
    "/refresh-token",
    response_model=RefreshResponse,
    status_code=status.HTTP_200_OK,
    summary="Rotate the refresh token",
    description=(
        "Rotates the refresh session using the HttpOnly `refresh_token` cookie. The old "
        "refresh token is revoked and recorded as replaced by the new session; the fresh "
        "access and refresh JWTs are set as HttpOnly cookies. Reusing an already-rotated "
        "token revokes the whole token family. "
        + _COOKIE_AUTH_NOTE
    ),
    responses=_error_responses(
        {
            401: "Missing, invalid, expired or revoked refresh token",
        }
    ),
)
async def refresh_token(
    response: Response,
    request: Request,
    refresh_cookie: str | None = Cookie(None, alias=settings.refresh_cookie_name),
    service: AuthService = Depends(get_service),
):
    token = refresh_cookie or request.cookies.get(settings.refresh_cookie_name)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is missing",
        )

    result = await service.refresh(
        token,
        device_info=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
    # Rotated tokens are delivered strictly via HttpOnly cookies, never in the body.
    set_access_token_cookie(response, result["access_token"])
    set_refresh_token_cookie(response, result["refresh_token"])
    return RefreshResponse(
        message="Tokens refreshed successfully",
        user_id=result["user_id"],
        session_id=result["session_id"],
        access_token_expires_in=result["access_token_expires_in"],
        refresh_token_expires_in=result["refresh_token_expires_in"],
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Log out and revoke the session",
    description=(
        "Revokes the current refresh session (if the `refresh_token` cookie is present) "
        "and clears every authentication/flow cookie using their original attributes. "
        "Idempotent: logging out without cookies is safe. "
        + _COOKIE_AUTH_NOTE
    ),
)
async def logout(
    response: Response,
    request: Request,
    refresh_cookie: str | None = Cookie(None, alias=settings.refresh_cookie_name),
    service: AuthService = Depends(get_service),
):
    token = refresh_cookie or request.cookies.get(settings.refresh_cookie_name)
    await service.logout(token)
    # Cookie deletion uses the same path/domain/max-age attributes as creation.
    clear_auth_cookies(response)
    clear_otp_token_cookie(response)
    return MessageResponse(message="Logged out successfully")


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Request a password-reset OTP",
    description=(
        "Starts the password-reset flow and returns a fixed, generic message to avoid "
        "account enumeration. If the account exists, the reset OTP token is set in the "
        "`reset_otp_token` HttpOnly cookie and emailed, otherwise the cookie is cleared. "
        "Resend is bounded by `OTP_MAX_RESENDS`. "
        + _COOKIE_AUTH_NOTE
    ),
)
async def forgot_password(
    data: ForgotPasswordRequest,
    response: Response,
    request: Request,
    reset_cookie: str | None = Cookie(None, alias=settings.reset_otp_token_cookie_name),
    service: AuthService = Depends(get_service),
):
    existing = reset_cookie or request.cookies.get(settings.reset_otp_token_cookie_name)
    token = await service.forgot_password(str(data.email), existing_token=existing)
    if token:
        set_reset_otp_token_cookie(response, token)
    else:
        clear_reset_otp_token_cookie(response)
    # Generic response regardless of whether the account exists (no enumeration).
    return MessageResponse(message=FORGOT_PASSWORD_GENERIC_MESSAGE)


@router.post(
    "/verify-forgot-otp",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify the password-reset OTP",
    description=(
        "Verifies the OTP from the `reset_otp_token` cookie. On success a short-lived "
        "`reset_flow_token` (single-use) is issued so the caller may proceed to "
        "reset-password. Wrong OTPs consume attempts (see `x-remaining-attempts`). "
        + _COOKIE_AUTH_NOTE
    ),
    responses=_error_responses(
        {
            400: "Missing or invalid OTP / expired reset token",
            429: "Too many incorrect OTP attempts",
        }
    ),
)
async def verify_forgot_otp(
    data: OTPVerifyRequest,
    response: Response,
    request: Request,
    reset_cookie: str | None = Cookie(None, alias=settings.reset_otp_token_cookie_name),
    service: AuthService = Depends(get_service),
):
    token = reset_cookie or request.cookies.get(settings.reset_otp_token_cookie_name)
    if not token:
        error = _error_response(status.HTTP_400_BAD_REQUEST, MISSING_RESET_OTP_TOKEN)
        clear_reset_otp_token_cookie(error)
        return error

    try:
        result = await service.verify_forgot_otp(token, data.otp)
    except InvalidOTPError as exc:
        error = _error_response(
            status.HTTP_400_BAD_REQUEST,
            "Invalid OTP",
            headers={"x-remaining-attempts": str(exc.remaining_attempts)},
        )
        set_reset_otp_token_cookie(error, exc.new_token)
        return error
    except OTPAttemptsExhaustedError as exc:
        error = _error_response(status.HTTP_429_TOO_MANY_REQUESTS, exc.detail)
        clear_reset_otp_token_cookie(error)
        return error
    except HTTPException as exc:
        error = _error_response(exc.status_code, exc.detail, dict(exc.headers or {}))
        clear_reset_otp_token_cookie(error)
        return error

    clear_reset_otp_token_cookie(response)
    set_reset_flow_token_cookie(response, result["token"])
    return MessageResponse(message="OTP verified successfully.")


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Reset the password",
    description=(
        "Applies a new password using the single-use `reset_flow_token` cookie issued by "
        "verify-forgot-otp. On success the password hash is rotated, the credential's "
        "`token_version` is bumped (invalidating every previously issued JWT) and all "
        "refresh sessions are revoked. All flow/auth cookies are cleared. "
        + _COOKIE_AUTH_NOTE
    ),
    responses=_error_responses(
        {
            400: "Missing, invalid, expired or already-consumed reset token",
        }
    ),
)
async def reset_password(
    data: ResetPasswordRequest,
    response: Response,
    request: Request,
    flow_cookie: str | None = Cookie(None, alias=settings.reset_flow_token_cookie_name),
    service: AuthService = Depends(get_service),
):
    token = flow_cookie or request.cookies.get(settings.reset_flow_token_cookie_name)
    if not token:
        error = _error_response(status.HTTP_400_BAD_REQUEST, MISSING_RESET_FLOW_TOKEN)
        clear_reset_flow_token_cookie(error)
        return error

    try:
        result = await service.reset_password(token, data.new_password)
    except HTTPException as exc:
        error = _error_response(exc.status_code, exc.detail, dict(exc.headers or {}))
        clear_reset_flow_token_cookie(error)
        return error

    clear_reset_flow_token_cookie(response)
    clear_reset_otp_token_cookie(response)
    clear_auth_cookies(response)
    return MessageResponse(message=result["message"])