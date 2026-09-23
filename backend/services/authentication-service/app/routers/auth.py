from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from app.core.cookies import (
    clear_otp_token_cookie,
    set_otp_token_cookie,
)
from app.core.config import settings
from app.routers.dependencies import get_service
from app.schemas import (
    MessageResponse,
    OTPVerifyRequest,
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