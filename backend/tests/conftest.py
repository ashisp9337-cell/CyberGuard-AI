import os
import sys
import tempfile

_tmpdir = tempfile.mkdtemp(prefix="cyberguard_test_")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmpdir}/test.db"
os.environ["JWT_SECRET"] = "test-secret"
os.environ["ENVIRONMENT"] = "development"
os.environ["UPLOAD_DIR"] = f"{_tmpdir}/uploads"
os.environ["REPORTS_DIR"] = f"{_tmpdir}/reports"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"

import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def auth_client(client):
    import uuid
    email = f"user_{uuid.uuid4().hex[:8]}@example.com"
    r = client.post("/api/auth/register", json={"name": "Test User", "email": email, "password": "TestPass123"})
    assert r.status_code == 201
    client._test_email = email
    return client
