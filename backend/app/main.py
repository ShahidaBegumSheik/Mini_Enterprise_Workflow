from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import text

from app.core.config import settings
from app.db.base import Base
from app.db.session import engine
from app.routers.auth import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Enterprise Collaboration and Workflow Tool API",
    lifespan=lifespan,
)

app.include_router(auth_router)


@app.get("/")
def root():
    return {"message": "ECWF API is running"}


@app.get("/health")
def health_check():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {
            "status": "success",
            "database": "connected",
        }
    except Exception as e:
        return {
            "status": "failed",
            "database": "disconnected",
            "error": str(e),
        }
