import os
import sys
from pathlib import Path

os.environ["INTERNAL_API_KEY"] = "test-internal-key-123"
os.environ["SMTP_ENABLED"] = "false"
os.environ["SMTP_HOST"] = ""

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def auth_header():
    return {"Authorization": f"Bearer {settings.INTERNAL_API_KEY}"}