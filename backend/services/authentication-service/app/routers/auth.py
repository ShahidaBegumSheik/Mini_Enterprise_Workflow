from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from app.core.cookies import (
    clear_auth_cookies,
    clear_otp_token_cookie,
    set_access_token_cookie,
    set_otp_token_cookie,
    set_refresh_token_cookie,
)
from app.core.config import settings
from app.routers.dependencies import get_current_user, get_service
from app.schemas import (
    LoginRequest,
    LoginResponse,
    MessageResponse,
    OTPVerifyRequest,
    RefreshResponse,
    RegisterRequest,
    RegistrationVerifiedResponse,
)
from app.services import (
    AuthService,
    InvalidOTPError,
    OTPAttemptsExhaustedError,
    OTPResendLimitExceededError,
)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

MISSING_OTP_TOKEN = "OTP flow token is missing or expired. Please register again."


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


@router.get("/me", status_code=status.HTTP_200_OK)
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