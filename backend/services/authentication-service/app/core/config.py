from functools import lru_cache

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "MECWF Authentication Service"
    app_env: str = "development"
    debug: bool = False
    log_level: str = "INFO"

    # Port the HTTP server listens on (published 1:1 by Docker Compose)
    authentication_service_port: int = 8001

    database_url: str
    internal_api_key: str

    enable_external_services: bool = True
    http_timeout_seconds: float = 15.0
    http_connect_timeout_seconds: float = 5.0

    # JWT (used for the signed OTP flow token)
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "mecwf-authentication-service"
    jwt_audience: str = "mecwf-services"

    # OTP
    otp_length: int = 6
    otp_expire_minutes: int = 5
    otp_max_attempts: int = 5
    # Resend cap per flow; accepted from either OTP_RESEND_LIMIT (canonical)
    # or the legacy OTP_MAX_RESENDS env var.
    otp_max_resends: int = Field(
        default=3,
        validation_alias=AliasChoices(
            "OTP_RESEND_LIMIT", "otp_max_resends", "OTP_MAX_RESENDS"
        ),
    )

    # Base64-urlsafe 32-byte Fernet key used to encrypt the OTP (and the rest
    # of the sensitive flow payload) inside the short-lived OTP flow token.
    # When empty it is derived from JWT_SECRET_KEY so development works out
    # of the box; production deployments should set an explicit key.
    otp_encryption_key: str = ""

    # OTP flow token cookie
    otp_token_cookie_name: str = "otp_token"

    # Password reset flow cookies (reuse the OTP security settings)
    reset_otp_token_cookie_name: str = "reset_otp_token"
    reset_flow_token_cookie_name: str = "reset_flow_token"
    reset_verified_expire_minutes: int = 10

    # Access / refresh session tokens
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # Session cookies (set on login, read back by get_current_user)
    access_cookie_name: str = "access_token"
    refresh_cookie_name: str = "refresh_token"

    # Cookie security attributes. ``cookie_secure`` defaults to ``None``: when
    # unset it is resolved from the environment (``True`` for ``production`` so
    # tokens only ever travel over HTTPS, ``False`` otherwise). An explicit
    # ``COOKIE_SECURE`` value always wins. SameSite and Path stay configurable.
    cookie_secure: bool | None = None
    cookie_samesite: str = "lax"
    cookie_domain: str | None = None
    cookie_path: str = "/"

    cors_origins: str = (
        "http://localhost:8001,"
        "http://localhost:8002,"
        "http://localhost:8003"
    )

    # Microservice base URLs (called through the shared HTTPX client)
    user_service_url: str = "http://user-service:8002"
    tenant_admin_service_url: str = "http://tenant-admin-service:8003"
    notification_service_url: str = "http://notification-service:8004"
    notification_timeout_seconds: float = 30.0

    # SMTP email delivery
    smtp_enabled: bool = False
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    smtp_from_email: str = ""
    email_from_name: str = "MECWF"
    developer_redirect_email: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )

    @model_validator(mode="after")
    def _resolve_cookie_security(self) -> "Settings":
        if self.cookie_secure is None:
            self.cookie_secure = self.app_env == "production"
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [
            item.strip()
            for item in self.cors_origins.split(",")
            if item.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()