import os
import sys
import tempfile
from pathlib import Path

TEST_DB = os.path.join(tempfile.gettempdir(), "ecwf_test.db")
if os.path.exists(TEST_DB):
    os.remove(TEST_DB)

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["OTP_RESEND_COOLDOWN_SECONDS"] = "0"
os.environ["COOKIE_SECURE"] = "False"
os.environ["BCRYPT_ROUNDS"] = "4"

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402

DEFAULT_OTP = "123456"

# Module-level OTP queue shared by registered tests. Tests may replace this
# list to control which OTP values are generated.
OTP_CODES: list[str] = []


def _fake_generate_otp() -> str:
    if not OTP_CODES:
        OTP_CODES.append(DEFAULT_OTP)
    return OTP_CODES.pop(0)


engine = create_engine(f"sqlite:///{TEST_DB}", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


@pytest.fixture()
def db_session():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(monkeypatch):
    from app.services import otp_service

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    monkeypatch.setattr(otp_service, "generate_otp", _fake_generate_otp)

    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def otp_codes():
    backup = list(OTP_CODES)
    OTP_CODES[:] = []
    yield OTP_CODES
    OTP_CODES[:] = []
    OTP_CODES.extend(backup)