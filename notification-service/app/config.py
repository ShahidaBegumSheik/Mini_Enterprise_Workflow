from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "ECWF Notification Service"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Internal API key shared with the backend service
    INTERNAL_API_KEY: str = ""

    # SMTP delivery (optional). When SMTP_ENABLED is false or SMTP_HOST is
    # empty, the service reports a delivery configuration problem instead of
    # attempting to send.
    SMTP_ENABLED: bool = False
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""
    SMTP_USE_TLS: bool = True

    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parents[1] / ".env"),
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()