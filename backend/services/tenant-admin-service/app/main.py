from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.routers.dashboard import router as dashboard_router
from app.routers.organizations import (
    internal_router as organization_internal_router,
)
from app.routers.organizations import router as organization_router


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="MECWF Tenant Admin Service",
    debug=settings.debug,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(organization_internal_router)
app.include_router(organization_router)
app.include_router(dashboard_router)


@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
        "service": "tenant-admin-service",
    }


@app.get("/", tags=["Root"])
def root() -> dict[str, str]:
    return {
        "service": settings.app_name,
        "status": "running",
    }