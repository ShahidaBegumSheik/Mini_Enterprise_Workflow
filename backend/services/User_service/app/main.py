from fastapi import FastAPI

from app.core.config import settings
from app.routers.users import router as users_router


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
)


app.include_router(users_router)


@app.get("/")
def health_check():
    return {
        "service": settings.app_name,
        "status": "running",
    }