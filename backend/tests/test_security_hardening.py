"""Security hardening: every fix from the security audit has a test here, so it can't silently come back."""
import uuid

import pytest

from app.core.config import get_settings
from helpers import login_user, register_user


def _email(prefix="sec"):
    return f"{prefix}_{uuid.uuid4().hex[:8]}@example.com"


# ---- 1. password reset token is never handed to the requester -----------------------------------
def test_forgot_password_never_returns_token_outside_tests(client, monkeypatch):
    register_user(client, {"name": "V", "email": (e := _email("victim")), "password": "TestPass123"})
    client.post("/api/auth/logout")
    monkeypatch.setattr(get_settings(), "EXPOSE_DEV_CODES", False)      # a real setup
    r = client.post("/api/auth/forgot-password", json={"email": e})
    assert r.status_code == 200
    assert "devResetToken" not in r.json() and "token" not in str(r.json()).lower().replace("reset link", "")


def test_unknown_and_known_email_get_identical_reset_answer(client, monkeypatch):
    register_user(client, {"name": "K", "email": (e := _email()), "password": "TestPass123"})
    client.post("/api/auth/logout")
    monkeypatch.setattr(get_settings(), "EXPOSE_DEV_CODES", False)
    a = client.post("/api/auth/forgot-password", json={"email": e}).json()
    b = client.post("/api/auth/forgot-password", json={"email": _email("nobody")}).json()
    assert a == b


# ---- 2. one-time sign-in codes are never handed to the requester --------------------------------
def test_login_code_not_returned_when_email_fails(client, monkeypatch):
    register_user(client, {"name": "O", "email": (e := _email()), "password": "TestPass123"})
    client.post("/api/auth/logout")
    monkeypatch.setattr(get_settings(), "EXPOSE_DEV_CODES", False)
    r = client.post("/api/auth/login", json={"email": e, "password": "TestPass123"})
    assert r.status_code == 200 and r.json()["otpRequired"] is True
    assert "devOtp" not in r.json()
    r = client.post("/api/auth/signup/start", json={"name": "X", "email": _email("someone_else")})
    assert r.status_code == 200 and "devOtp" not in r.json()


def test_dev_codes_can_never_be_exposed_in_production(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "EXPOSE_DEV_CODES", True)
    monkeypatch.setattr(s, "ENVIRONMENT", "production")
    assert s.dev_codes_allowed is False


# ---- 3. admin-only system controls ---------------------------------------------------------------
@pytest.mark.parametrize("method,path", [
    ("get", "/api/automation/status"), ("post", "/api/automation/downloads/toggle"),
    ("post", "/api/automation/email/run"), ("get", "/api/alerts/status"), ("post", "/api/alerts/test"),
])
def test_normal_user_cannot_use_admin_routes(auth_client, method, path, monkeypatch):
    monkeypatch.setattr(get_settings(), "ADMIN_EMAILS", "the-real-admin@example.com")
    kwargs = {"json": {"enabled": False}} if path.endswith("toggle") else {}
    r = getattr(auth_client, method)(path, **kwargs)
    assert r.status_code == 403 and r.json()["error"]["code"] == "ADMIN_ONLY"


def test_admin_can_use_admin_routes_and_me_says_so(admin_client):
    assert admin_client.get("/api/automation/status").status_code == 200
    assert admin_client.get("/api/auth/me").json()["isAdmin"] is True


def test_me_reports_normal_user_as_not_admin(auth_client, monkeypatch):
    monkeypatch.setattr(get_settings(), "ADMIN_EMAILS", "the-real-admin@example.com")
    assert auth_client.get("/api/auth/me").json()["isAdmin"] is False


def test_admin_emails_setting_decides_admins(auth_client, monkeypatch):
    monkeypatch.setattr(get_settings(), "ADMIN_EMAILS", auth_client._test_email.upper())   # case-insensitive
    assert auth_client.get("/api/automation/status").status_code == 200


# ---- 4. CAPTCHA can't be skipped by leaving the token out -------------------------------------
def test_captcha_required_when_configured(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "TURNSTILE_SECRET_KEY", "configured-secret")
    r = client.post("/api/auth/signup/start", json={"name": "Bot", "email": _email("bot")})
    assert r.status_code == 400 and r.json()["error"]["code"] == "CAPTCHA_FAILED"
    r = client.post("/api/auth/login", json={"email": _email("bot"), "password": "whatever1A"})
    assert r.status_code == 400 and r.json()["error"]["code"] == "CAPTCHA_FAILED"


# ---- 6. logout and password reset really end sessions -------------------------------------------
def test_logout_kills_a_stolen_copy_of_the_session(client):
    register_user(client, {"name": "S", "email": _email(), "password": "TestPass123"})
    stolen = client.cookies.get("cyberguard_session")
    assert client.get("/api/auth/me").status_code == 200
    client.post("/api/auth/logout")
    client.cookies.set("cyberguard_session", stolen)          # attacker replays the old cookie
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_password_reset_ends_sessions_and_old_reset_links(client):
    register_user(client, {"name": "R", "email": (e := _email()), "password": "TestPass123"})
    session = client.cookies.get("cyberguard_session")
    t1 = client.post("/api/auth/forgot-password", json={"email": e}).json()["devResetToken"]
    t2 = client.post("/api/auth/forgot-password", json={"email": e}).json()["devResetToken"]
    assert client.post("/api/auth/reset-password", json={"token": t2, "newPassword": "NewPass456"}).status_code == 200
    client.cookies.set("cyberguard_session", session)
    assert client.get("/api/auth/me").status_code == 401                       # old session is dead
    assert client.post("/api/auth/reset-password", json={"token": t1, "newPassword": "Other789X"}).status_code == 400
    assert login_user(client, e, "NewPass456").status_code == 200


def test_tampered_or_unsigned_tokens_rejected(client):
    import jwt as pyjwt
    register_user(client, {"name": "T", "email": _email(), "password": "TestPass123"})
    me = client.get("/api/auth/me").json()
    forged = pyjwt.encode({"sub": me["id"], "sv": 0, "exp": 9999999999}, "wrong-secret-" + "y" * 40, algorithm="HS256")
    client.cookies.set("cyberguard_session", forged)
    assert client.get("/api/auth/me").status_code == 401
    none_alg = pyjwt.encode({"sub": me["id"], "sv": 0, "exp": 9999999999}, None, algorithm="none")
    client.cookies.set("cyberguard_session", none_alg)
    assert client.get("/api/auth/me").status_code == 401


# ---- 7. input limits -----------------------------------------------------------------------------
def test_oversized_scan_text_rejected(auth_client, monkeypatch):
    monkeypatch.setattr(get_settings(), "MAX_TEXT_CHARS", 1000)
    r = auth_client.post("/api/analysis/scan", data={"moduleId": "phishing", "subtopicId": "sms-analysis",
                                                     "subtopicTitle": "SMS", "textInput": "a" * 1001})
    assert r.status_code == 413


def test_bad_extra_fields_do_not_crash(auth_client):
    r = auth_client.post("/api/analysis/scan", data={"moduleId": "cyber-threat", "subtopicId": "log-analysis",
                                                     "subtopicTitle": "Logs", "textInput": "normal log line",
                                                     "extraFieldValues": "[1, 2, 3]"})
    assert r.status_code == 200


def test_chat_message_length_limited(auth_client):
    r = auth_client.post("/api/chat", json={"message": "x" * (get_settings().MAX_CHAT_CHARS + 1)})
    assert r.status_code == 422


def test_password_longer_than_bcrypt_limit_refused(client):
    r = register_user(client, {"name": "L", "email": _email(), "password": "Aa1" + "x" * 80})
    assert r.status_code == 422 and r.json()["error"]["code"] == "WEAK_PASSWORD"


def test_validation_errors_do_not_echo_submitted_values(client):
    r = client.post("/api/auth/login", json={"email": "not-an-email", "password": "SuperSecret123"})
    assert r.status_code == 422 and "SuperSecret123" not in r.text


def test_threat_intel_lookup_only_accepts_web_links(auth_client):
    assert auth_client.get("/api/threat-intelligence/lookup?url=file:///etc/passwd").status_code == 422


# ---- 8/9. docs off, headers on, CORS exact ------------------------------------------------------
def test_api_docs_are_not_public(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_security_headers_present(auth_client):
    r = auth_client.get("/api/scans")
    h = r.headers
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
    assert "default-src 'none'" in h["content-security-policy"] and h["cache-control"] == "no-store"
    assert "camera=()" in h["permissions-policy"]


def test_cors_allows_only_the_configured_origin(client):
    ok = client.options("/api/auth/me", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})
    bad = client.options("/api/auth/me", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-origin" not in bad.headers


def test_unhandled_errors_hide_internal_details(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app

    @app.get("/api/_boom_for_test")
    def _boom():
        raise RuntimeError("secret internal path C:/Users/x")

    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/api/_boom_for_test")
    assert r.status_code == 500 and "secret internal" not in r.text


def test_startup_check_flags_unsafe_settings():
    from app.core.config import Settings, security_problems
    bad = Settings(JWT_SECRET="dev-secret-change-me-in-production", CORS_ORIGINS="*", ENVIRONMENT="production",
                   COOKIE_SECURE=False, EXPOSE_DEV_CODES=True, DEBUG=True)
    probs = " ".join(security_problems(bad))
    for word in ("JWT_SECRET", "CORS_ORIGINS", "COOKIE_SECURE", "EXPOSE_DEV_CODES", "DEBUG"):
        assert word in probs
    good = Settings(JWT_SECRET="x" * 64, CORS_ORIGINS="https://cyberguard.example", ENVIRONMENT="production",
                    COOKIE_SECURE=True, EXPOSE_DEV_CODES=False, DEBUG=False)
    assert security_problems(good) == []
