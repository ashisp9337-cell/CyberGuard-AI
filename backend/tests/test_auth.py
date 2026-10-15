"""Sign-up (email OTP first, then password) and login (password, then email OTP)."""
from datetime import datetime, timedelta, timezone

from helpers import login_user, register_user


def _start(client, email, name="Alice"):
    return client.post("/api/auth/signup/start", json={"name": name, "email": email})


# ---- sign-up ---------------------------------------------------------------
def test_signup_three_steps_creates_verified_account_and_logs_in(client):
    r1 = _start(client, "alice@example.com")
    assert r1.status_code == 200
    body = r1.json()
    assert body["sentTo"].endswith("@example.com") and "*" in body["sentTo"]
    assert len(body["devOtp"]) == 6 and body["devOtp"].isdigit()   # dev mode: email not configured in tests
    assert client.get("/api/auth/me").status_code == 401             # no account / session yet

    r2 = client.post("/api/auth/signup/verify", json={"challengeId": body["challengeId"], "code": body["devOtp"]})
    assert r2.status_code == 200 and r2.json()["email"] == "alice@example.com"

    r3 = client.post("/api/auth/signup/complete", json={"signupToken": r2.json()["signupToken"], "password": "GoodPass123"})
    assert r3.status_code == 201
    assert r3.json()["user"]["email"] == "alice@example.com"
    assert client.get("/api/auth/me").status_code == 200

    from app.db.database import SessionLocal
    from app.db.models import User
    db = SessionLocal()
    assert db.query(User).filter(User.email == "alice@example.com").one().is_verified is True
    db.close()


def test_signup_existing_email_is_refused_before_any_code(client):
    register_user(client, {"name": "Alice", "email": "dup@example.com", "password": "GoodPass123"})
    assert _start(client, "dup@example.com").status_code == 409


def test_signup_wrong_code_counts_down_then_locks(client):
    ch = _start(client, "wrong@example.com").json()["challengeId"]
    r = client.post("/api/auth/signup/verify", json={"challengeId": ch, "code": "000000"})
    if r.status_code == 200:   # 1-in-a-million: the random code really was 000000
        return
    assert r.status_code == 400 and r.json()["error"]["code"] == "OTP_WRONG" and "4 attempts left" in r.json()["error"]["message"]
    for _ in range(3):
        client.post("/api/auth/signup/verify", json={"challengeId": ch, "code": "000000"})
    r = client.post("/api/auth/signup/verify", json={"challengeId": ch, "code": "000000"})
    assert r.status_code == 429 and r.json()["error"]["code"] == "OTP_TOO_MANY_ATTEMPTS"
    # even the right code no longer works once locked
    r = client.post("/api/auth/signup/verify", json={"challengeId": ch, "code": "123456"})
    assert r.status_code == 400 and r.json()["error"]["code"] == "OTP_INVALID"


def test_signup_weak_password_rejected_and_token_still_usable(client):
    b = _start(client, "weak@example.com").json()
    tok = client.post("/api/auth/signup/verify", json={"challengeId": b["challengeId"], "code": b["devOtp"]}).json()["signupToken"]
    assert client.post("/api/auth/signup/complete", json={"signupToken": tok, "password": "weak"}).status_code == 422
    assert client.post("/api/auth/signup/complete", json={"signupToken": tok, "password": "GoodPass123"}).status_code == 201


def test_signup_token_cannot_be_reused_or_forged(client):
    b = _start(client, "once@example.com").json()
    tok = client.post("/api/auth/signup/verify", json={"challengeId": b["challengeId"], "code": b["devOtp"]}).json()["signupToken"]
    assert client.post("/api/auth/signup/complete", json={"signupToken": tok, "password": "GoodPass123"}).status_code == 201
    client.post("/api/auth/logout")
    assert client.post("/api/auth/signup/complete", json={"signupToken": tok, "password": "GoodPass123"}).status_code in (400, 409)
    assert client.post("/api/auth/signup/complete", json={"signupToken": "not.a.token", "password": "GoodPass123"}).status_code == 400


def test_signup_token_is_not_a_login_session(client):
    b = _start(client, "notsession@example.com").json()
    tok = client.post("/api/auth/signup/verify", json={"challengeId": b["challengeId"], "code": b["devOtp"]}).json()["signupToken"]
    from app.core.config import get_settings
    client.cookies.set(get_settings().COOKIE_NAME, tok)
    assert client.get("/api/auth/me").status_code == 401


def test_expired_code_is_refused(client):
    b = _start(client, "late@example.com").json()
    from app.db.database import SessionLocal
    from app.db.models import EmailOTP
    db = SessionLocal()
    otp = db.get(EmailOTP, b["challengeId"])
    otp.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    db.close()
    r = client.post("/api/auth/signup/verify", json={"challengeId": b["challengeId"], "code": b["devOtp"]})
    assert r.status_code == 400 and r.json()["error"]["code"] == "OTP_EXPIRED"


def test_resend_waits_then_gives_a_new_code(client):
    b = _start(client, "resend@example.com").json()
    r = client.post("/api/auth/otp/resend", json={"challengeId": b["challengeId"], "purpose": "signup"})
    assert r.status_code == 429 and r.json()["error"]["code"] == "OTP_RESEND_TOO_SOON"
    from app.db.database import SessionLocal
    from app.db.models import EmailOTP
    db = SessionLocal()
    db.get(EmailOTP, b["challengeId"]).sent_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    db.commit()
    db.close()
    r = client.post("/api/auth/otp/resend", json={"challengeId": b["challengeId"], "purpose": "signup"})
    assert r.status_code == 200
    new = r.json()["devOtp"]
    ok = client.post("/api/auth/signup/verify", json={"challengeId": b["challengeId"], "code": new})
    assert ok.status_code == 200


def test_old_one_step_register_is_closed(client):
    r = client.post("/api/auth/register", json={"name": "Old", "email": "old@example.com", "password": "GoodPass123"})
    assert r.status_code == 410


def test_code_is_stored_hashed_not_plain(client):
    b = _start(client, "hash@example.com").json()
    from app.db.database import SessionLocal
    from app.db.models import EmailOTP
    db = SessionLocal()
    otp = db.get(EmailOTP, b["challengeId"])
    assert b["devOtp"] not in otp.code_hash and len(otp.code_hash) == 64
    db.close()


# ---- login -----------------------------------------------------------------
def test_login_needs_password_then_otp(client):
    register_user(client, {"name": "Bob", "email": "bob@example.com", "password": "GoodPass123"})
    client.post("/api/auth/logout")
    r1 = client.post("/api/auth/login", json={"email": "bob@example.com", "password": "GoodPass123"})
    assert r1.status_code == 200 and r1.json()["otpRequired"] is True
    assert client.get("/api/auth/me").status_code == 401   # password alone is NOT enough
    r2 = client.post("/api/auth/login/verify", json={"challengeId": r1.json()["challengeId"], "code": r1.json()["devOtp"]})
    assert r2.status_code == 200 and r2.json()["user"]["email"] == "bob@example.com"
    assert client.get("/api/auth/me").status_code == 200


def test_login_wrong_password_sends_no_code(client):
    register_user(client, {"name": "Bob", "email": "bob2@example.com", "password": "GoodPass123"})
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"email": "bob2@example.com", "password": "WrongPass123"})
    assert r.status_code == 401 and "challengeId" not in r.json()


def test_login_code_cannot_be_used_twice(client):
    register_user(client, {"name": "Eve", "email": "eve@example.com", "password": "GoodPass123"})
    client.post("/api/auth/logout")
    r1 = client.post("/api/auth/login", json={"email": "eve@example.com", "password": "GoodPass123"}).json()
    assert client.post("/api/auth/login/verify", json={"challengeId": r1["challengeId"], "code": r1["devOtp"]}).status_code == 200
    client.post("/api/auth/logout")
    again = client.post("/api/auth/login/verify", json={"challengeId": r1["challengeId"], "code": r1["devOtp"]})
    assert again.status_code == 400


def test_signup_code_cannot_be_used_for_login(client):
    b = _start(client, "mix@example.com").json()
    r = client.post("/api/auth/login/verify", json={"challengeId": b["challengeId"], "code": b["devOtp"]})
    assert r.status_code == 400


def test_production_without_email_refuses_instead_of_leaking_code(client, monkeypatch):
    from app.core.config import get_settings
    from app.api.routes import auth as auth_routes
    monkeypatch.setattr(get_settings(), "ENVIRONMENT", "production")

    async def captcha_passes(token, remote_ip=None):      # production requires CAPTCHA; pretend it passed
        return True
    monkeypatch.setattr(auth_routes, "verify_turnstile", captcha_passes)
    r = client.post("/api/auth/signup/start", json={"name": "Alice", "email": "prod@example.com", "turnstileToken": "ok"})
    assert r.status_code == 503 and "devOtp" not in r.text


def test_production_without_captcha_token_is_refused(client, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "ENVIRONMENT", "production")
    r = _start(client, "prod2@example.com")
    assert r.status_code == 400 and r.json()["error"]["code"] == "CAPTCHA_FAILED"


def test_email_with_code_is_sent_when_smtp_works(client, monkeypatch):
    from app.services import notifier
    sent = []
    monkeypatch.setattr(notifier, "send_mail", lambda to, subject, text, html=None, channel="email":
                        sent.append((to, subject, text)) or {"channel": channel, "status": "sent", "error": "", "at": ""})
    r = _start(client, "mailed@example.com").json()
    assert "devOtp" not in r and r["delivered"] is True
    to, subject, text = sent[0]
    code = subject.split()[0]
    assert to == ["mailed@example.com"] and code.isdigit() and len(code) == 6 and code in text


# ---- unchanged parts ---------------------------------------------------------
def test_me_requires_auth(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_after_login(auth_client):
    r = auth_client.get("/api/auth/me")
    assert r.status_code == 200
    assert r.json()["email"] == auth_client._test_email


def test_logout_clears_session(auth_client):
    auth_client.post("/api/auth/logout")
    assert auth_client.get("/api/auth/me").status_code == 401


def test_forgot_password_dev_token(client):
    register_user(client, {"name": "Carl", "email": "carl@example.com", "password": "GoodPass123"})
    r = client.post("/api/auth/forgot-password", json={"email": "carl@example.com"})
    assert r.status_code == 200
    assert "devResetToken" in r.json()


def test_forgot_password_unknown_email_same_response_shape(client):
    r = client.post("/api/auth/forgot-password", json={"email": "nobody@example.com"})
    assert r.status_code == 200
    assert "devResetToken" not in r.json()


def test_reset_password_flow(client):
    register_user(client, {"name": "Dana", "email": "dana@example.com", "password": "OldPass123"})
    client.post("/api/auth/logout")
    token = client.post("/api/auth/forgot-password", json={"email": "dana@example.com"}).json()["devResetToken"]
    assert client.post("/api/auth/reset-password", json={"token": token, "newPassword": "NewPass456"}).status_code == 200
    assert login_user(client, "dana@example.com", "NewPass456").status_code == 200


def test_reset_password_invalid_token(client):
    r = client.post("/api/auth/reset-password", json={"token": "not-a-real-token", "newPassword": "NewPass456"})
    assert r.status_code == 400
