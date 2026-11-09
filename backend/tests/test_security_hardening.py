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
    client.cookies.clear()                    # only the old cookie is sent (httpx2's jar keeps both otherwise)
    client.cookies.set("cyberguard_session", session)
    assert client.get("/api/auth/me").status_code == 401                       # old session is dead
    assert client.post("/api/auth/reset-password", json={"token": t1, "newPassword": "Other789X"}).status_code == 400
    assert login_user(client, e, "NewPass456").status_code == 200


def test_tampered_or_unsigned_tokens_rejected(client):
    import jwt as pyjwt
    register_user(client, {"name": "T", "email": _email(), "password": "TestPass123"})
    me = client.get("/api/auth/me").json()
    forged = pyjwt.encode({"sub": me["id"], "sv": 0, "exp": 9999999999}, "wrong-secret-" + "y" * 40, algorithm="HS256")
    client.cookies.clear()                    # only the forged cookie is sent (httpx2's jar keeps both otherwise)
    client.cookies.set("cyberguard_session", forged)
    assert client.get("/api/auth/me").status_code == 401
    none_alg = pyjwt.encode({"sub": me["id"], "sv": 0, "exp": 9999999999}, None, algorithm="none")
    client.cookies.clear()
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


# ---- 19 Oct audit fixes -------------------------------------------------------------------------
def test_link_check_connects_only_to_the_address_it_checked(monkeypatch):
    """DNS rebinding: the domain is resolved ONCE, checked, and the connection goes to exactly that address."""
    import socket

    from app.services import safe_fetch
    lookups, connects = [], []
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, *a, **k: lookups.append(host) or [(socket.AF_INET, 1, 6, "", ("93.184.216.34", 0))])

    def fake_get(url, ip):
        connects.append((url, ip))
        return 200, None, "text/html", b"<html><title>ok</title></html>"
    monkeypatch.setattr(safe_fetch, "_get_pinned", fake_get)
    r = safe_fetch.fetch("https://rebind.example.test/login")
    assert r["status"] == "ok" and connects == [("https://rebind.example.test/login", "93.184.216.34")]
    assert lookups == ["rebind.example.test"]                         # one lookup, no second chance to lie


def test_link_check_refuses_a_domain_that_points_anywhere_private(monkeypatch):
    import socket

    from app.services import safe_fetch
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [
        (socket.AF_INET, 1, 6, "", ("93.184.216.34", 0)), (socket.AF_INET, 1, 6, "", ("10.0.0.5", 0))])
    monkeypatch.setattr(safe_fetch, "_get_pinned", lambda url, ip: pytest.fail("must not connect"))
    r = safe_fetch.fetch("http://mixed.example.test/")
    assert r["status"] == "refused" and "10.0.0.5" in r["reason"]


def test_no_hidden_bidirectional_characters_in_source():
    """Trojan-source: right-to-left / invisible control characters must be written as escapes, never raw."""
    import pathlib
    bad = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩"}
    root = pathlib.Path(__file__).resolve().parents[1] / "app"
    hits = [str(p) for p in root.rglob("*.py") if bad & set(p.read_text(encoding="utf-8"))]
    assert hits == []


def test_windows_event_xml_with_entities_is_refused():
    from app.automation import windows_logons
    bomb = ('<!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">&b;</Event>')
    with pytest.raises(ValueError):
        windows_logons.parse_events(bomb)


def test_database_must_be_postgresql():
    from app.core.config import database_problem
    assert database_problem("postgresql+psycopg2://u:p@localhost:5432/cyberguard") == ""
    assert "PostgreSQL" in database_problem("sqlite:///./cyberguard.db")
    assert "not set" in database_problem("")
    assert "PostgreSQL" in database_problem("mysql+pymysql://u:p@localhost/db")


# ---- (6 Nov) pentest: the per-IP login limit could be dodged with a faked X-Forwarded-For --------------------------
def test_wrong_passwords_lock_the_account_whatever_address_they_come_from(client):
    email = f"lock_{uuid.uuid4().hex[:6]}@example.com"
    assert register_user(client, {"name": "L", "email": email, "password": "RightPass123!"}).status_code == 201
    client.post("/api/auth/logout")
    limit = get_settings().LOGIN_MAX_FAILED_PER_ACCOUNT
    for i in range(limit):
        r = client.post("/api/auth/login", json={"email": email, "password": f"wrong{i}"},
                        headers={"X-Forwarded-For": f"203.0.113.{i}"})
        assert r.status_code == 401
    r = client.post("/api/auth/login", json={"email": email, "password": "RightPass123!"},
                    headers={"X-Forwarded-For": "198.51.100.77"})
    assert r.status_code == 429 and r.json()["error"]["code"] == "ACCOUNT_LOCKED"   # even the right password waits
    other = f"other_{uuid.uuid4().hex[:6]}@example.com"
    register_user(client, {"name": "O", "email": other, "password": "RightPass123!"})
    client.post("/api/auth/logout")
    assert login_user(client, other, "RightPass123!").status_code == 200              # other accounts unaffected


def test_unknown_accounts_lock_the_same_way(client):
    """Same answer for an address with no account: the lock never tells which emails exist."""
    ghost = f"ghost_{uuid.uuid4().hex[:6]}@example.com"
    codes = [client.post("/api/auth/login", json={"email": ghost, "password": f"x{i}"}).status_code
             for i in range(get_settings().LOGIN_MAX_FAILED_PER_ACCOUNT + 1)]
    assert codes[-1] == 429 and set(codes[:-1]) == {401}


def test_account_lock_can_be_switched_off(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "LOGIN_MAX_FAILED_PER_ACCOUNT", 0)
    ghost = f"off_{uuid.uuid4().hex[:6]}@example.com"
    assert {client.post("/api/auth/login", json={"email": ghost, "password": "x"}).status_code for _ in range(12)} == {401}


# ---- (6 Nov) full security audit ---------------------------------------------------------------------------------
@pytest.fixture()
def limits_on():
    from app.core.rate_limit import limiter
    old = limiter.enabled
    limiter.enabled = True
    limiter.reset()
    yield limiter
    limiter.enabled = old
    limiter.reset()


def test_default_limit_covers_routes_without_their_own(client, limits_on):
    codes = [client.get("/api/health").status_code for _ in range(605)]
    assert codes[:600] == [200] * 600 and 429 in codes[600:]


def test_own_route_limits_are_not_counted_twice(client, limits_on):
    codes = [client.post("/api/auth/login", json={"email": f"x{i}@example.com", "password": "Wrong1234"}).status_code
             for i in range(12)]
    assert codes[:10] == [401] * 10 and codes[10] == 429          # exactly 10 a minute, as the route says


@pytest.mark.parametrize("title", ["<b>unclosed tag", '<a href="javascript:alert(1)">Click to verify</a>',
                                   "Q3 report & <findings>"])
def test_report_titles_are_text_not_markup(auth_client, title):
    from app.services.report_service import generate_pdf_report
    pdf = generate_pdf_report([], title)                          # used to crash / plant a clickable link
    assert pdf.startswith(b"%PDF") and b"/URI" not in pdf and b"/Link" not in pdf   # no clickable link planted
    assert auth_client.post("/api/reports", json={"title": title, "format": "PDF"}).status_code == 201


def _cap():
    from app.core.config import get_settings
    return (2 * get_settings().MAX_UPLOAD_MB + 2) * 1024 * 1024


def test_one_huge_request_is_refused_before_it_is_read(auth_client):
    big = b'{"displayName": "' + b"A" * (_cap() + 10) + b'"}'
    r = auth_client.post("/api/contacts", content=big, headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.json()["error"]["code"] == "REQUEST_TOO_LARGE"


def test_a_huge_request_without_a_declared_size_is_stopped_too(auth_client):
    def chunks():
        for _ in range(_cap() // (1024 * 1024) + 3):
            yield b"A" * (1024 * 1024)
    r = auth_client.post("/api/contacts", content=chunks(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_normal_uploads_still_reach_their_own_checks(auth_client):
    from app.core.config import get_settings
    over_file_limit = b"x" * ((get_settings().MAX_UPLOAD_MB + 5) * 1024 * 1024)      # below the request cap
    r = auth_client.post("/api/analysis/scan", files={"file": ("big.txt", over_file_limit, "text/plain")},
                         data={"moduleId": "cyber-threat", "subtopicId": "log-analysis", "subtopicTitle": "Logs"})
    assert r.status_code == 413 and r.json()["error"]["code"] == "FILE_TOO_LARGE"   # the route's own answer
    ok = auth_client.post("/api/contacts", json={"displayName": "Mom", "authorizedEmail": "mom@example.com"})
    assert ok.status_code in (200, 201)


# ---- (9 Nov) no upload is kept once read (public website: strangers upload files too) -------------------------------
def _uploads():
    import os
    from app.core.config import get_settings
    folder = get_settings().UPLOAD_DIR
    return [n for n in (os.listdir(folder) if os.path.isdir(folder) else []) if not n.startswith(".")]


def _png() -> bytes:
    import io
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (32, 32), (40, 90, 160)).save(buf, "PNG")
    return buf.getvalue()


def test_every_upload_is_deleted_after_its_scan(auth_client):
    before = set(_uploads())
    eml = (b"From: SBI Alerts <alerts@sbi-kyc-update.top>\r\nTo: you@example.com\r\nSubject: KYC pending\r\n\r\n"
           b"Your account will be blocked today. Update KYC at http://sbi-kyc-update.top/login\r\n")
    for module, sub, name, data in [("deepfake", "image-analysis", "photo.png", _png()),
                                    ("phishing", "auto", "mail.eml", eml)]:
        r = auth_client.post("/api/analysis/scan", data={"moduleId": module, "subtopicId": sub, "subtopicTitle": "t"},
                             files={"file": (name, data, "application/octet-stream")})
        assert r.status_code == 200, r.text
    assert set(_uploads()) == before                                  # photo and e-mail are gone too (before: kept)


def test_upload_is_deleted_even_when_the_scan_fails(auth_client, monkeypatch):
    from app.api.routes import analysis
    before = set(_uploads())

    def boom(**kw):
        raise RuntimeError("detector crashed")
    monkeypatch.setattr(analysis, "run_scan", boom)
    with pytest.raises(RuntimeError):
        auth_client.post("/api/analysis/scan", data={"moduleId": "deepfake", "subtopicId": "image-analysis",
                                                     "subtopicTitle": "t"}, files={"file": ("p.png", _png(), "image/png")})
    assert set(_uploads()) == before
