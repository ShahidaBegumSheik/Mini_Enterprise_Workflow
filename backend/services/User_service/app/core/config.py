import os
import re
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


SERVICE_ROOT = Path(__file__).resolve().parents[2]

_PLACEHOLDER_PATTERN = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}",
)


def expand_env_placeholders(value: str) -> str:
    """Expand ``${VAR}`` / ``${VAR:-default}`` references from the environment.

    The same ``.env`` file has to work for local development (``localhost``)
    and for the Docker network (``db``). Keeping the host and the credentials
    in environment variables means neither the host name nor any password is
    hardcoded in the image or in a committed file.
    """

    def _replace(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        return os.environ.get(name, default if default is not None else "")

    return _PLACEHOLDER_PATTERN.sub(_replace, value)


class Settings(BaseSettings):
    app_name: str = "User Service"
    app_env: str = "development"
    app_version: str = "1.0.0"
    debug: bool = False

    # MySQL connection string owned exclusively by this service's database.
    database_url: str

    # JWT verification only. This service never issues tokens.
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    # Optional hardening. Left empty the claims are not enforced, so tokens
    # issued by the Authentication Service keep working as they do today.
    jwt_audience: str = ""
    jwt_issuer: str = ""

    # Shared service-to-service credential used by the internal router that
    # the Authentication Service calls. When empty the internal router is
    # disabled entirely and returns 503.
    internal_api_key: str = ""

    # Listing defaults / guard rails.
    default_page_size: int = 20
    max_page_size: int = 100

    # Roles (from the JWT claims) allowed to act on any user, not just
    # their own record.
    admin_roles: str = "admin,superadmin,super_admin,platform_admin"

    model_config = SettingsConfigDict(
        env_file=SERVICE_ROOT / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("database_url", mode="after")
    @classmethod
    def _expand_database_url(cls, value: str) -> str:
        return expand_env_placeholders(value)

    @property
    def internal_api_enabled(self) -> bool:
        return bool(self.internal_api_key.strip())

    @property
    def jwt_audience_or_none(self) -> str | None:
        return self.jwt_audience.strip() or None

    @property
    def jwt_issuer_or_none(self) -> str | None:
        return self.jwt_issuer.strip() or None

    @property
    def admin_role_set(self) -> frozenset[str]:
        return frozenset(
            role.strip().lower()
            for role in self.admin_roles.split(",")
            if role.strip()
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
