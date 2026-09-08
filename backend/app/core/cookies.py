from fastapi import Response

from app.core.config import settings


def _cookie_attributes(path: str | None = None) -> dict:
    return {
        "httponly": settings.COOKIE_HTTP_ONLY,
        "secure": settings.COOKIE_SECURE,
        "samesite": settings.COOKIE_SAME_SITE,
        "path": path or settings.COOKIE_PATH,
    }


def set_otp_token_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.OTP_TOKEN_COOKIE,
        value=token,
        max_age=settings.OTP_EXPIRE_MINUTES * 60,
        **_cookie_attributes(),
    )


def set_access_token_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.ACCESS_TOKEN_COOKIE,
        value=token,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        **_cookie_attributes(),
    )


def set_refresh_token_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.REFRESH_TOKEN_COOKIE,
        value=token,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        **_cookie_attributes(),
    )


def clear_otp_token_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.OTP_TOKEN_COOKIE,
        **_cookie_attributes(),
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(
        key=settings.ACCESS_TOKEN_COOKIE,
        **_cookie_attributes(),
    )
    response.delete_cookie(
        key=settings.REFRESH_TOKEN_COOKIE,
        **_cookie_attributes(),
    )
