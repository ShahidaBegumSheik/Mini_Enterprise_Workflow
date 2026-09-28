from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.exceptions import DatabaseOperationError
from app.routers.users import router as users_router
from app.schemas.health import HealthResponse


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
)


app.include_router(users_router)


@app.exception_handler(DatabaseOperationError)
async def handle_database_operation_error(
    _request: Request,
    _exc: DatabaseOperationError,
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": "Database operation failed"},
    )


@app.get("/", response_model=HealthResponse, summary="Health check")
def health_check() -> HealthResponse:
    return HealthResponse(
        service=settings.app_name,
        status="running",
    )
