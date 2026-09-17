import os

os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("INTERNAL_API_KEY", "test-internal-key")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-0123456789")
os.environ.setdefault("JWT_ISSUER", "mecwf-authentication-service")
os.environ.setdefault("JWT_AUDIENCE", "mecwf-services")
os.environ.setdefault("OTP_LENGTH", "6")
os.environ.setdefault("OTP_EXPIRE_MINUTES", "5")
os.environ.setdefault("OTP_MAX_ATTEMPTS", "5")
os.environ.setdefault("OTP_MAX_RESENDS", "3")
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
os.environ.setdefault("REFRESH_TOKEN_EXPIRE_DAYS", "7")
os.environ.setdefault("SMTP_ENABLED", "false")
os.environ.setdefault("ENABLE_EXTERNAL_SERVICES", "true")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401  registers models on Base.metadata
from app.database.base import Base
from app.database.session import get_db
from app.main import app
from app.repositories.auth_repository import AuthRepository
from app.routers.auth import service as auth_service_dependency
from app.services.auth import AuthService

from tests.fakes import FakeTenantClient, FakeUserClient


@pytest.fixture
def db_session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    yield Session
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def session(db_session_factory):
    db = db_session_factory()
    yield db
    db.close()


@pytest.fixture
def repo(session):
    return AuthRepository(session)


@pytest.fixture
def user_client():
    return FakeUserClient()


@pytest.fixture
def tenant_client():
    return FakeTenantClient()


@pytest.fixture
def fakes(user_client, tenant_client):
    return user_client, tenant_client


@pytest.fixture
def auth_service(repo, fakes):
    return AuthService(repo, fakes[0], fakes[1])


@pytest.fixture
def otp_fixture(monkeypatch):
    """Force deterministic OTP codes; resends cycle to the next value."""
    import app.services.auth as auth_module

    state = {"index": 0, "values": ["123456", "654321"]}

    def fake_generate_otp():
        value = state["values"][state["index"] % len(state["values"])]
        state["index"] += 1
        return value

    monkeypatch.setattr(auth_module, "generate_otp", fake_generate_otp)
    return state


@pytest.fixture
def api(db_session_factory):
    Session = db_session_factory
    fakes = {"user": FakeUserClient(), "tenant": FakeTenantClient()}
    app.state.test_fakes = fakes

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    async def override_service():
        db = Session()
        try:
            yield AuthService(
                AuthRepository(db), fakes["user"], fakes["tenant"]
            )
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[auth_service_dependency] = override_service

    with TestClient(app) as test_client:
        yield test_client, fakes

    app.dependency_overrides.clear()
    app.state.test_fakes = None