"""Import, app lifecycle and OpenAPI-contract checks (no business logic).

Verifies:
- every application module imports (compile-level sanity).
- the FastAPI app starts (lifespan) and the health endpoint responds.
- ``/openapi.json`` documents all required public endpoints, their response
  models, the business error statuses (400/401/403/409/429/502/503), the
  input validation schemas, and the cookie-based auth parameters used by the
  OTP/reset flows. Also asserts the login responses expose no raw tokens.
"""

import importlib

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app

APP_MODULES = [
    "app.main",
    "app.schemas",
    "app.models",
    "app.repositories",
    "app.services",
    "app.core.config",
    "app.core.cookies",
    "app.core.security",
    "app.core.utils",
    "app.database.base",
    "app.database.session",
    "app.clients.contracts",
    "app.clients.user_service",
    "app.clients.tenant_admin_service",
    "app.clients.notification_service",
    "app.routers.auth",
    "app.routers.dependencies",
]

AUTH_PATHS = [
    "/api/v1/auth/register",
    "/api/v1/auth/verify-otp",
    "/api/v1/auth/resend-otp",
    "/api/v1/auth/login",
    "/api/v1/auth/logout",
    "/api/v1/auth/refresh-token",
    "/api/v1/auth/forgot-password",
    "/api/v1/auth/verify-forgot-otp",
    "/api/v1/auth/reset-password",
]


class TestImports:
    def test_all_application_modules_import(self):
        for module in APP_MODULES:
            importlib.import_module(module)


class TestStartup:
    def test_healthcheck(self):
        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            assert resp.json()["service"] == "authentication-service"

    def test_openapi_endpoint(self):
        with TestClient(app) as client:
            resp = client.get("/openapi.json")
            assert resp.status_code == 200
            assert resp.json()["paths"]


class TestOpenAPI:
    def _openapi(self):
        return app.openapi()

    def test_all_public_auth_endpoints_documented(self):
        paths = self._openapi()["paths"]
        for path in AUTH_PATHS:
            assert path in paths, f"missing {path} in OpenAPI"
            if "/me" in path:
                assert paths[path]["get"]
            else:
                assert paths[path]["post"]

    def test_request_and_response_models_documented(self):
        openapi = self._openapi()
        schemas = openapi.get("components", {}).get("schemas", {})
        for schema in (
            "RegisterRequest",
            "OTPVerifyRequest",
            "LoginRequest",
            "ForgotPasswordRequest",
            "ResetPasswordRequest",
            "MessageResponse",
            "LoginResponse",
            "RefreshResponse",
            "RegistrationVerifiedResponse",
            "ErrorResponse",
        ):
            assert schema in schemas, f"missing schema {schema}"

    def test_login_response_exposes_no_raw_tokens(self):
        schemas = self._openapi()["components"]["schemas"]
        props = schemas["LoginResponse"]["properties"]
        assert "access_token" not in props
        assert "refresh_token" not in props
        assert "token" not in props

    def test_business_error_statuses_documented(self):
        paths = self._openapi()["paths"]
        expected = {
            "login": {"401", "403"},
            "refresh-token": {"401"},
            "me": {"401"},
            "register": {"409", "502", "503"},
            "verify-otp": {"400", "409", "429", "502", "503"},
            "resend-otp": {"400", "429"},
            "verify-forgot-otp": {"400", "429"},
            "reset-password": {"400"},
        }
        for suffix, codes in expected.items():
            endpoint = next(p for p in paths if p.endswith(suffix))
            op = paths[endpoint]["get" if suffix == "me" else "post"]
            responses = op["responses"]
            for code in codes:
                assert code in responses, f"{endpoint} does not document {code}"

    def test_otp_flow_endpoints_document_cookie_parameters(self):
        paths = self._openapi()["paths"]
        otp_cookie = next(p for p in paths if p.endswith("verify-otp"))
        params = paths[otp_cookie]["post"]["parameters"]
        cookie_param = next(
            (p for p in params if p.get("in") == "cookie" and p.get("name") == settings.otp_token_cookie_name),
            None,
        )
        assert cookie_param, "verify-otp must document the otp_token cookie parameter"

    def test_endpoints_have_summary_or_description(self):
        paths = self._openapi()["paths"]
        for path in AUTH_PATHS:
            op = paths[path]["get" if path.endswith("/me") else "post"]
            assert op.get("summary") or op.get("description"), f"{path} lacks documentation"