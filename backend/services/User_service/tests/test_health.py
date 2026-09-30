from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app


EXPECTED_OPERATIONS = {
    "/": {"get"},
    "/users": {"get"},
    "/users/profile": {"get", "put"},
    "/users/{user_id}": {"get", "put"},
    "/users/{user_id}/status": {"patch"},
}


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {"service": settings.app_name, "status": "running"}


def test_health_alias(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "running"


def test_swagger_ui_is_served(client: TestClient) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        response = client.get(path)
        assert response.status_code == 200, path


def test_openapi_exposes_every_endpoint(client: TestClient) -> None:
    response = client.get("/openapi.json")
    paths = response.json()["paths"]

    for path, operations in EXPECTED_OPERATIONS.items():
        assert path in paths, path
        assert operations.issubset(set(paths[path])), path


def test_openapi_documents_bearer_security(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()

    schemes = spec["components"]["securitySchemes"]
    assert schemes["BearerAuth"]["scheme"] == "bearer"
    assert schemes["BearerAuth"]["type"] == "http"

    for path in ("/users", "/users/profile", "/users/{user_id}"):
        for operation in spec["paths"][path].values():
            assert operation.get("security"), path


def test_openapi_documents_request_and_response_schemas(
    client: TestClient,
) -> None:
    spec = client.get("/openapi.json").json()
    schemas = spec["components"]["schemas"]

    for name in (
        "UserResponse",
        "UserProfileUpdate",
        "UserUpdate",
        "UserStatusUpdate",
        "UserListResponse",
    ):
        assert name in schemas, name

    put_profile = spec["paths"]["/users/profile"]["put"]
    body = put_profile["requestBody"]["content"]["application/json"]["schema"]
    assert body["$ref"] == "#/components/schemas/UserProfileUpdate"

    patch_status = spec["paths"]["/users/{user_id}/status"]["patch"]
    assert patch_status["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/UserStatusUpdate"
    }
    assert patch_status["responses"]["200"]["content"]["application/json"][
        "schema"
    ] == {"$ref": "#/components/schemas/UserResponse"}


def test_openapi_documents_error_status_codes(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()

    profile_get = spec["paths"]["/users/profile"]["get"]
    assert {"401", "403", "422"} <= set(profile_get["responses"])

    user_get = spec["paths"]["/users/{user_id}"]["get"]
    assert {"401", "403", "404", "422"} <= set(user_get["responses"])

    status_patch = spec["paths"]["/users/{user_id}/status"]["patch"]
    assert {"401", "403", "404", "422"} <= set(status_patch["responses"])


def test_title_and_description_are_configured() -> None:
    assert app.title == settings.app_name
    assert app.description
