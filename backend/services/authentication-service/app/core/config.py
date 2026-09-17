from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "MECWF Authentication Service"
    app_env: str = "development"
    debug: bool = False
    log_level: str = "INFO"

    database_url: str
    internal_api_key: str

    enable_external_services: bool = True
    http_timeout_seconds: float = 15.0
    http_connect_timeout_seconds: float = 5.0

    # JWT
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "mecwf-authentication-service"
    jwt_audience: str = "mecwf-services"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # OTP
    otp_length: int = 6
    otp_expire_minutes: int = 5
    otp_max_attempts: int = 5
    otp_max_resends: int = 3

    # HTTP-only cookies
    registration_otp_cookie_name: str = "registration_otp_token"
    password_reset_otp_cookie_name: str = "password_reset_otp_token"
    password_reset_verified_cookie_name: str = "password_reset_verified_token"
    access_cookie_name: str = "access_token"
    refresh_cookie_name: str = "refresh_token"

    cookie_secure: bool = False
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