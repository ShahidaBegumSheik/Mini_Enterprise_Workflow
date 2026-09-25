from fastapi import Response

from app.core.config import settings


def _options(max_age: int) -> dict:
    return {
        "httponly": True,
        "secure": settings.cookie_secure,
        "samesite": settings.cookie_samesite,
        "domain": settings.cookie_domain or None,
        "path": settings.cookie_path,
        "max_age": max_age,
    }


def set_otp_token_cookie(response: Response, value: str) -> None:
    """Set the short-lived OTP flow token as an HTTP-only cookie.

    The cookie attributes (HttpOnly, Secure, SameSite, Path, Max-Age) are all
    configurable via the service settings. Max-Age mirrors the OTP expiry.
    """
    response.set_cookie(
        settings.otp_token_cookie_name,
        value,
        **_options(settings.otp_expire_minutes * 60),
    )


def clear_otp_token_cookie(response: Response) -> None:
    response.delete_cookie(
        settings.otp_token_cookie_name,
        **{k: v for k, v in _options(0).items() if k != "max_age"},
    )


def set_access_token_cookie(response: Response, value: str) -> None:
    """Set the HttpOnly access token cookie. Token is never sent in the body."""
    response.set_cookie(
        settings.access_cookie_name,
        value,
        **_options(settings.access_token_expire_minutes * 60),
    )


def set_refresh_token_cookie(response: Response, value: str) -> None:
    """Set the HttpOnly refresh token cookie. Token is never sent in the body."""
    response.set_cookie(
        settings.refresh_cookie_name,
        value,
        **_options(settings.refresh_token_expire_days * 24 * 60 * 60),
    )


def clear_auth_cookies(response: Response) -> None:
    for name in (settings.access_cookie_name, settings.refresh_cookie_name):
        response.delete_cookie(name, **{k: v for k, v in _options(0).items() if k != "max_age"})