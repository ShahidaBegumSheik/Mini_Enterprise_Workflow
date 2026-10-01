from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "MECWF Tenant Admin Service"
    app_env: str = "development"
    debug: bool = False
    log_level: str = "INFO"

    database_url: str
    internal_api_key: str

    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "mecwf-authentication-service"
    jwt_audience: str = "mecwf-services"

    access_token_expire_minutes: int = 30

    cors_origins: str = "http://localhost:8000,http://localhost:8001,http://localhost:8003"

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