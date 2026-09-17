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


def set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    response.set_cookie(
        settings.access_cookie_name,
        access_token,
        **_options(settings.access_token_expire_minutes * 60),
    )
    response.set_cookie(
        settings.refresh_cookie_name,
        refresh_token,
        **_options(settings.refresh_token_expire_days * 86400),
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(
        settings.access_cookie_name,
        domain=settings.cookie_domain or None,
        path=settings.cookie_path,
    )
    response.delete_cookie(
        settings.refresh_cookie_name,
        domain=settings.cookie_domain or None,
        path=settings.cookie_path,
    )


def set_flow_cookie(response: Response, name: str, value: str) -> None:
    response.set_cookie(name, value, **_options(settings.otp_expire_minutes * 60))


def clear_flow_cookie(response: Response, name: str) -> None:
    response.delete_cookie(name, domain=settings.cookie_domain or None, path=settings.cookie_path)