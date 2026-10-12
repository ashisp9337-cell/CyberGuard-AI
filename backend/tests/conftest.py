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
os.environ["RATE_LIMIT_ENABLED"] = "false"   # tests sign up many users from one "IP"
os.environ["AUTOMATION_ENABLED"] = "false"   # never start the real Gmail/Windows/Downloads watchers in tests
os.environ["AUTOMATION_STATE_FILE"] = f"{_tmpdir}/automation_state.json"
# Never send real Telegram / email / WhatsApp alerts while testing, whatever is in .env.
for _k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD", "ALERT_EMAIL_TO",
           "WHATSAPP_TO", "CALLMEBOT_APIKEY", "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_WHATSAPP_FROM"):
    os.environ[_k] = ""

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
    from helpers import register_user
    r = register_user(client, {"name": "Test User", "email": email, "password": "TestPass123"})
    assert r.status_code == 201
    client._test_email = email
    return client
