from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.exceptions import AuthenticationError, ServiceError
from app.routers.internal import router as internal_router
from app.routers.users import router as users_router
from app.schemas.health import HealthResponse


DESCRIPTION = (
    "Owns individual user profiles: the current authenticated user, user "
    "details, profile updates, user listing and user status management.\n\n"
    "This service never issues tokens. It only verifies the JWT issued by the "
    "Authentication Service and reads the `users` table it owns."
)

TAGS_METADATA = [
    {"name": "Health", "description": "Liveness probe."},
    {"name": "Users", "description": "Individual user profile and management."},
    {
        "name": "Internal",
        "description": (
            "Service-to-service contract consumed by the Authentication "
            "Service. Requires the internal API key."
        ),
    },
]

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=DESCRIPTION,
    openapi_tags=TAGS_METADATA,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.include_router(users_router)
app.include_router(internal_router)


# ---------------------------------------------------------------------------
# Error handling: domain errors are mapped to stable HTTP codes and no
# exception detail, stack trace or secret ever reaches the client.
# ---------------------------------------------------------------------------


def _json_error(status_code: int, detail: str, headers: dict[str, str] | None = None):
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail},
        headers=headers,
    )


@app.exception_handler(ServiceError)
async def handle_service_error(
    _request: Request,
    exc: ServiceError,
) -> JSONResponse:
    """Maps every domain error to a stable HTTP code.

    Starlette resolves handlers through the exception MRO, so this single
    handler covers 401 / 403 / 404 / 409 / 503. The response body only ever
    contains the curated ``detail`` string.
    """

    headers = {"WWW-Authenticate": "Bearer"} if isinstance(
        exc,
        AuthenticationError,
    ) else None

    return _json_error(exc.status_code, exc.detail, headers)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get(
    "/",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Health check",
    description="Liveness probe for the User Service.",
)
def health_check() -> HealthResponse:
    return HealthResponse(
        service=settings.app_name,
        status="running",
    )


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Health check (alias)",
    include_in_schema=False,
)
def health_check_alias() -> HealthResponse:
    return health_check()
