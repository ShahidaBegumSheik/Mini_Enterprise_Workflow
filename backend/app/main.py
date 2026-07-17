from fastapi import FastAPI
from sqlalchemy import text

from app.db.session import engine

app = FastAPI(
    title="ECWF Tool",
    version="1.0.0",
    description="Enterprise Collaboration and Workflow Tool API",
)

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
            "database": "connected"
        }
    except Exception as e:
        return {
            "status": "failed",
            "database": "disconnected",
            "error": str(e)
        }