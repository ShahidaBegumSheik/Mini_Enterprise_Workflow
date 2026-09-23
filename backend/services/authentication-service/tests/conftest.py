import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

os.environ["INTERNAL_API_KEY"] = "test-internal-key"
os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-key-0123456789abcdef0123456789abcdef"
os.environ["JWT_ALGORITHM"] = "HS256"
os.environ["JWT_ISSUER"] = "test-issuer"
os.environ["JWT_AUDIENCE"] = "test-audience"
os.environ["OTP_ENCRYPTION_KEY"] = ""
os.environ["OTP_TOKEN_COOKIE_NAME"] = "otp_token"
os.environ["OTP_LENGTH"] = "6"
os.environ["OTP_EXPIRE_MINUTES"] = "5"
os.environ["OTP_MAX_ATTEMPTS"] = "5"
os.environ["OTP_MAX_RESENDS"] = "3"
os.environ["COOKIE_SECURE"] = "false"
os.environ["COOKIE_SAMESITE"] = "lax"
os.environ["COOKIE_PATH"] = "/"
os.environ["SMTP_ENABLED"] = "false"
os.environ["DATABASE_URL"] = "sqlite:///:memory:?cache=shared"

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.main import app
from app.repositories import AuthRepository
from app.routers.dependencies import get_service
from app.services import AuthService

from tests.fakes import FakeTenantClient, FakeUserClient

ENGINE_PATH = Path(tempfile.mkdtemp()) / "test_auth.db"

VALID_INDIVIDUAL = {
    "full_name": "Alice Personal",
    "email": "alice.personal@gmail.com",
    "password": "Str0ngPassw#ord",
    "confirm_password": "Str0ngPassw#ord",
    "account_type": "individual",
}

VALID_ORGANIZATION = {
    "full_name": "Bob Enterprise",
    "email": "bob.ops@acmecorp.io",
    "password": "Str0ngPassw#ord",
    "confirm_password": "Str0ngPassw#ord",
    "account_type": "organization",
    "organization_name": "AcmeCorp",
    "organization_type": "enterprise",
    "industry": "software",
}


@pytest.fixture(scope="session")
def engine():
    engine = create_engine(
        f"sqlite:///{ENGINE_PATH}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    yield engine


@pytest.fixture
def session_factory(engine):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture
def fakes():
    return FakeUserClient(), FakeTenantClient()


def _dependency(fakes, session_factory):
    def _get_service():
        db = session_factory()
        try:
            yield AuthService(AuthRepository(db), fakes[0], fakes[1])
        finally:
            db.close()

    return _get_service


@asynccontextmanager
async def _lifespan_client():
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            yield client


@pytest.fixture
async def client(session_factory, fakes):
    app.dependency_overrides[get_service] = _dependency(fakes, session_factory)
    try:
        async with _lifespan_client() as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_service, None)


@pytest.fixture
async def service(fakes, session_factory):
    service = AuthService(AuthRepository(session_factory()), fakes[0], fakes[1])
    yield service


def otp_from_cookie(client) -> str:
    from app.core.security import open_otp_flow

    token = client.cookies.get("otp_token")
    assert token, "expected an otp_token cookie"
    return open_otp_flow(token)["otp"]


def register(client, payload):
    return client.post("/api/v1/auth/register", json=payload)