"""Configuration behaviour tests (no business logic).

Verifies the service's cookie-security defaults: the Secure flag must be
enabled automatically for production deployments (tokens over HTTPS only),
disabled by default for development, and always overridable.
"""

import pytest

from app.core.config import Settings

# Drains the globally-set test env so "unset" behaviour can be exercised.
pytestmark = pytest.mark.usefixtures("_unset_cookie_env")

_BASE = {
    "database_url": "sqlite:///./cfg.db",
    "internal_api_key": "k",
    "jwt_secret_key": "secret",
}


@pytest.fixture
def _unset_cookie_env(monkeypatch):
    monkeypatch.delenv("COOKIE_SECURE", raising=False)


def _settings(**overrides) -> Settings:
    base = dict(_BASE)
    base.update(overrides)
    return Settings(**base)


class TestCookieSecurity:
    def test_cookie_secure_is_false_in_development_by_default(self):
        assert _settings(app_env="development").cookie_secure is False

    def test_cookie_secure_is_enabled_in_production_by_default(self):
        assert _settings(app_env="production").cookie_secure is True

    def test_explicit_setting_wins_over_environment(self):
        assert _settings(app_env="production", cookie_secure=False).cookie_secure is False
        assert _settings(app_env="development", cookie_secure=True).cookie_secure is True

    def test_samesite_and_path_remain_configurable(self):
        st = _settings(
            app_env="production",
            cookie_samesite="strict",
            cookie_path="/auth",
            cookie_domain="example.com",
        )
        assert st.cookie_samesite == "strict"
        assert st.cookie_path == "/auth"
        assert st.cookie_domain == "example.com"


class TestHttpTimeouts:
    def test_external_service_timeouts_are_set(self):
        st = _settings(http_timeout_seconds=7, notification_timeout_seconds=45)
        assert st.http_timeout_seconds == 7
        assert st.notification_timeout_seconds == 45