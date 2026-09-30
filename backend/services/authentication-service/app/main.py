from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.routers.auth import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    timeout = httpx.Timeout(
        settings.http_timeout_seconds, connect=settings.http_connect_timeout_seconds
    )
    app.state.http = httpx.AsyncClient(timeout=timeout)
    try:
        yield
    finally:
        await app.state.http.aclose()


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description=(
        "MECWF Authentication Service - registration with email OTP. "
        "Owns authentication credentials only; user records are created "
        "through the User Service and organization records through the "
        "Tenant Admin Service."
    ),
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)


@app.get("/health", tags=["System"])
def health():
    return {"status": "healthy", "service": "authentication-service", "database": "auth_db"}