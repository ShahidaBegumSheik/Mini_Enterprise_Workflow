from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "ECWF Tool"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Database
    DATABASE_URL: str

    # JWT
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"

    # Access Token
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 10

    # Refresh Token
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Password hashing
    BCRYPT_ROUNDS: int = 12

    # OTP
    OTP_EXPIRE_MINUTES: int = 5
    OTP_MAX_ATTEMPTS: int = 5
    OTP_RESEND_COOLDOWN_SECONDS: int = 60

    # Cookies
    ACCESS_TOKEN_COOKIE: str = "access_token"
    REFRESH_TOKEN_COOKIE: str = "refresh_token"
    OTP_TOKEN_COOKIE: str = "otp_token"

    COOKIE_HTTP_ONLY: bool = True
    COOKIE_SECURE: bool = False
    COOKIE_SAME_SITE: str = "lax"
    COOKIE_PATH: str = "/"

    # Notification Service
    NOTIFICATION_SERVICE_URL: str = "http://notification-service:8000"
    INTERNAL_API_KEY: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()