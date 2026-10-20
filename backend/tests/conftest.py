import os
import tempfile

import pytest

_tmpdir = tempfile.mkdtemp(prefix="cyberguard_test_")


def _test_database_url() -> str:
    """The tests run on PostgreSQL (CyberGuard's only database), in a SEPARATE database whose name ends in
    '_test' -- never the real one. TEST_DATABASE_URL wins; otherwise it is DATABASE_URL (environment or
    backend/.env) with '_test' added to the database name: cyberguard -> cyberguard_test."""
    from sqlalchemy.engine import make_url
    url = os.environ.get("TEST_DATABASE_URL", "").strip()
    if not url:
        base = os.environ.get("DATABASE_URL", "").strip()
        if not base:
            from dotenv import dotenv_values
            env = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
            base = (dotenv_values(env).get("DATABASE_URL") or "").strip() if os.path.exists(env) else ""
        if not base.startswith("postgresql"):
            pytest.exit("Tests need PostgreSQL: set DATABASE_URL in backend/.env (or TEST_DATABASE_URL).", returncode=2)
        u = make_url(base)
        if not (u.database or "").endswith("_test"):
            u = u.set(database=f"{u.database}_test")
        url = u.render_as_string(hide_password=False)
    u = make_url(url)
    if not url.startswith("postgresql") or not (u.database or "").endswith("_test"):
        pytest.exit(f"Refusing to run tests on database '{u.database}': the test database name must end in "
                    f"'_test' (tests wipe it).", returncode=2)
    return url


def _fresh_test_database(url: str) -> None:
    """Create the _test database if needed, wipe it, and build the schema with the REAL Alembic migrations
    (so every test run also proves the migrations work)."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url
    u = make_url(url)
    admin = create_engine(u.set(database="postgres"), isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as c:
            if not c.execute(text("select 1 from pg_database where datname = :n"), {"n": u.database}).scalar():
                c.execute(text(f'CREATE DATABASE "{u.database}"'))
    except Exception as exc:
        msg = str(exc).splitlines()[0][:200]
        if "refused" in msg.lower() or "could not connect" in msg.lower() or "timeout" in msg.lower():
            pytest.exit(f"PostgreSQL is not reachable at {u.host}:{u.port or 5432} ({msg}). Start PostgreSQL, "
                        f"then run the tests again.", returncode=2)
        pytest.exit(f"Could not create the test database '{u.database}' ({type(exc).__name__}: {msg}). "
                    f"Create it once in pgAdmin (owner = the user in DATABASE_URL), then run the tests again.",
                    returncode=2)
    finally:
        admin.dispose()
    eng = create_engine(url, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    eng.dispose()
    from alembic import command
    from alembic.config import Config
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg = Config(os.path.join(here, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(here, "alembic"))
    command.upgrade(cfg, "head")


os.environ["DATABASE_URL"] = _test_database_url()
os.environ["JWT_SECRET"] = "test-secret-" + "x" * 40          # long enough to pass the startup check
os.environ["ENVIRONMENT"] = "development"
os.environ["UPLOAD_DIR"] = f"{_tmpdir}/uploads"
os.environ["REPORTS_DIR"] = f"{_tmpdir}/reports"
os.environ["QUARANTINE_DIR"] = f"{_tmpdir}/quarantine"     # never the real quarantine folder
os.environ["CORS_ORIGINS"] = "http://localhost:5173"
os.environ["RATE_LIMIT_ENABLED"] = "false"   # tests sign up many users from one "IP"
os.environ["EXPOSE_DEV_CODES"] = "true"      # tests read the OTP / reset code from the response; NEVER set this in .env
os.environ["ADMIN_EMAILS"] = ""
os.environ["TURNSTILE_SECRET_KEY"] = ""
os.environ["WARM_UP_MODELS"] = "false"       # tests load models themselves; no background thread
os.environ["AUTOMATION_ENABLED"] = "false"   # never start the real Gmail/Windows/Downloads watchers in tests
os.environ["AUTOMATION_STATE_FILE"] = f"{_tmpdir}/automation_state.json"
# Never send real Telegram / email / WhatsApp alerts while testing, whatever is in .env.
for _k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM",
           "IMAP_USER", "IMAP_PASSWORD", "AUTOMATION_USER_EMAIL", "ALERT_EMAIL_TO",
           "WHATSAPP_TO", "CALLMEBOT_APIKEY", "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_WHATSAPP_FROM"):
    os.environ[_k] = ""

_fresh_test_database(os.environ["DATABASE_URL"])

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402


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


@pytest.fixture()
def admin_client(auth_client):
    """auth_client promoted to administrator (automation and alert-channel routes are admin-only)."""
    from app.db.database import SessionLocal
    from app.db.models import User
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.email == auth_client._test_email).first()
        u.role = "admin"
        db.commit()
    finally:
        db.close()
    return auth_client
