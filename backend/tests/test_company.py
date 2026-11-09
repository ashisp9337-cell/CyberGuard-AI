"""(9 Nov) Company mode: who may join (company domain or invite), Google sign-in with the same rule, the Employees
page and the administrator's controls (role, disable, sign out everywhere), last activity."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app
from helpers import login_user, register_user

PW = "TestPass123"


@pytest.fixture()
def company(monkeypatch):
    from app.core.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "COMPANY_EMAIL_DOMAINS", "threatora.example")
    monkeypatch.setattr(s, "COMPANY_NAME", "THREATORA Test Ltd")
    return s


def _mail(domain="threatora.example"):
    return f"emp_{uuid.uuid4().hex[:8]}@{domain}"


def _new_client():
    return TestClient(app)


def _make_admin(email):
    from app.db.database import SessionLocal
    from app.db.models import User
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.email == email).first()
        u.role = "admin"
        db.commit()
        return u.id
    finally:
        db.close()


@pytest.fixture()
def admin(company):
    c = _new_client()
    email = _mail()
    assert register_user(c, {"name": "Boss", "email": email, "password": PW}).status_code == 201
    c._uid = _make_admin(email)
    c._email = email
    return c


def test_public_info_tells_the_sign_up_page_the_rule(client, company):
    r = client.get("/api/company/public").json()
    assert r == {"name": "THREATORA Test Ltd", "domains": ["threatora.example"], "restricted": True}


def test_without_company_domains_anyone_may_sign_up_as_before(client):
    assert register_user(client, {"name": "A", "email": _mail("gmail.example"), "password": PW}).status_code == 201


def test_company_domain_may_join_but_others_need_an_invite(client, company):
    assert register_user(_new_client(), {"name": "E", "email": _mail(), "password": PW}).status_code == 201
    r = _new_client().post("/api/auth/signup/start", json={"name": "J", "email": _mail("gmail.example")})
    assert r.status_code == 403 and r.json()["error"]["code"] == "NOT_INVITED"
    assert "THREATORA Test Ltd" in r.json()["error"]["message"] and "@threatora.example" in r.json()["error"]["message"]


def test_invited_judge_can_join_once_and_gets_the_invited_role(admin):
    judge = _mail("gmail.example")
    r = admin.post("/api/company/invites", json={"email": judge, "role": "employee"})
    assert r.status_code == 201 and r.json()["status"] == "open" and r.json()["link"].endswith(f"/signup?email={judge}")
    c = _new_client()
    assert register_user(c, {"name": "Judge", "email": judge, "password": PW}).status_code == 201
    assert c.get("/api/auth/me").json()["isAdmin"] is False
    inv = admin.get("/api/company/invites").json()["invites"]
    assert next(i for i in inv if i["email"] == judge)["status"] == "used"
    # an admin invite makes an administrator
    boss2 = _mail("gmail.example")
    admin.post("/api/company/invites", json={"email": boss2, "role": "admin"})
    c2 = _new_client()
    assert register_user(c2, {"name": "Boss 2", "email": boss2, "password": PW}).status_code == 201
    assert c2.get("/api/auth/me").json()["isAdmin"] is True


def test_revoked_or_expired_invites_do_not_work(admin):
    a, b = _mail("gmail.example"), _mail("gmail.example")
    iid = admin.post("/api/company/invites", json={"email": a}).json()["id"]
    assert admin.delete(f"/api/company/invites/{iid}").json()["status"] == "revoked"
    assert _new_client().post("/api/auth/signup/start", json={"name": "A", "email": a}).status_code == 403
    admin.post("/api/company/invites", json={"email": b})
    from app.db.database import SessionLocal
    from app.db.models import Invite
    db = SessionLocal()
    try:
        db.query(Invite).filter(Invite.email == b).update({"expires_at": datetime.now(timezone.utc) - timedelta(hours=1)})
        db.commit()
    finally:
        db.close()
    assert _new_client().post("/api/auth/signup/start", json={"name": "B", "email": b}).status_code == 403
    assert next(i for i in admin.get("/api/company/invites").json()["invites"] if i["email"] == b)["status"] == "expired"


def test_an_invite_revoked_after_the_code_was_sent_still_blocks_the_account(admin):
    who = _mail("gmail.example")
    iid = admin.post("/api/company/invites", json={"email": who}).json()["id"]
    c = _new_client()
    r1 = c.post("/api/auth/signup/start", json={"name": "X", "email": who})
    r2 = c.post("/api/auth/signup/verify", json={"challengeId": r1.json()["challengeId"], "code": r1.json()["devOtp"]})
    admin.delete(f"/api/company/invites/{iid}")
    r3 = c.post("/api/auth/signup/complete", json={"signupToken": r2.json()["signupToken"], "password": PW})
    assert r3.status_code == 403 and r3.json()["error"]["code"] == "NOT_INVITED"


def _google(monkeypatch, email):
    from app.api.routes import auth as A
    monkeypatch.setattr(A, "verify_google_credential", lambda cred: {
        "email": email, "email_verified": True, "sub": "g-" + email, "name": "G User", "iss": "accounts.google.com"})


def test_google_sign_in_follows_the_same_company_rule(admin, monkeypatch):
    outsider = _mail("gmail.example")
    _google(monkeypatch, outsider)
    r = _new_client().post("/api/auth/google", json={"credential": "x"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "NOT_INVITED"
    admin.post("/api/company/invites", json={"email": outsider})
    c = _new_client()
    assert c.post("/api/auth/google", json={"credential": "x"}).status_code == 200
    assert c.get("/api/auth/me").json()["email"] == outsider
    staff = _mail()
    _google(monkeypatch, staff)
    assert _new_client().post("/api/auth/google", json={"credential": "x"}).status_code == 200
    rows = {r["email"]: r for r in admin.get("/api/company/employees").json()["employees"]}
    assert rows[outsider]["signIn"] == "Google" and rows[staff]["signIn"] == "Google"


def test_employees_page_is_for_administrators_only(admin, company):
    c = _new_client()
    email = _mail()
    register_user(c, {"name": "Emp", "email": email, "password": PW})
    assert c.get("/api/company/employees").status_code == 403
    assert c.post("/api/company/invites", json={"email": _mail("gmail.example")}).status_code == 403
    assert _new_client().get("/api/company/employees").status_code == 401
    data = admin.get("/api/company/employees").json()
    row = next(r for r in data["employees"] if r["email"] == email)
    assert row["role"] == "employee" and row["active"] is True and row["online"] is True and row["lastBrowser"] != None
    assert data["summary"]["total"] >= 2 and data["summary"]["admins"] >= 1


def test_scans_threats_and_detail_of_an_employee(admin, company):
    c = _new_client()
    email = _mail()
    register_user(c, {"name": "Emp", "email": email, "password": PW})
    r = c.post("/api/analysis/scan", data={"moduleId": "phishing", "subtopicId": "sms-analysis", "subtopicTitle": "SMS",
                                           "textInput": "URGENT your SBI account is blocked, update KYC now at "
                                                        "http://sbi-kyc.example/login or pay fine"})
    assert r.status_code == 200
    row = next(r for r in admin.get("/api/company/employees").json()["employees"] if r["email"] == email)
    assert row["scans"] == 1 and row["lastScan"]
    d = admin.get(f"/api/company/employees/{row['id']}").json()
    assert d["scans"][0]["module"] == "phishing" and d["signIns"][0]["action"].startswith("auth.")


def test_disable_ends_every_session_and_blocks_sign_in_until_enabled(admin, company):
    c = _new_client()
    email = _mail()
    register_user(c, {"name": "Emp", "email": email, "password": PW})
    uid = next(r for r in admin.get("/api/company/employees").json()["employees"] if r["email"] == email)["id"]
    assert admin.post(f"/api/company/employees/{uid}/active", json={"active": False}).json()["active"] is False
    assert c.get("/api/auth/me").status_code == 401
    r = _new_client().post("/api/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 403 and r.json()["error"]["code"] == "ACCOUNT_DISABLED"
    admin.post(f"/api/company/employees/{uid}/active", json={"active": True})
    assert login_user(_new_client(), email, PW).status_code == 200


def test_role_change_and_sign_out_everywhere(admin, company):
    c = _new_client()
    email = _mail()
    register_user(c, {"name": "Emp", "email": email, "password": PW})
    uid = next(r for r in admin.get("/api/company/employees").json()["employees"] if r["email"] == email)["id"]
    admin.post(f"/api/company/employees/{uid}/role", json={"role": "admin"})
    assert c.get("/api/auth/me").json()["isAdmin"] is True
    admin.post(f"/api/company/employees/{uid}/role", json={"role": "employee"})
    assert c.get("/api/auth/me").json()["isAdmin"] is False
    assert admin.post(f"/api/company/employees/{uid}/sign-out").json()["signedOut"] is True
    assert c.get("/api/auth/me").status_code == 401
    assert admin.post(f"/api/company/employees/{uid}/role", json={"role": "boss"}).status_code == 422


def test_an_administrator_cannot_lock_out_themselves_or_the_owner(admin, company, monkeypatch):
    assert admin.post(f"/api/company/employees/{admin._uid}/active", json={"active": False}).status_code == 409
    assert admin.post(f"/api/company/employees/{admin._uid}/role", json={"role": "employee"}).status_code == 409
    owner = _new_client()
    oemail = _mail()
    register_user(owner, {"name": "Owner", "email": oemail, "password": PW})
    monkeypatch.setattr(company, "ADMIN_EMAILS", f"{oemail},{admin._email}")
    oid = next(r for r in admin.get("/api/company/employees").json()["employees"] if r["email"] == oemail)
    assert oid["owner"] is True and oid["role"] == "admin"
    assert admin.post(f"/api/company/employees/{oid['id']}/active", json={"active": False}).status_code == 409


def test_company_actions_are_in_the_audit_log(admin, company):
    who = _mail("gmail.example")
    admin.post("/api/company/invites", json={"email": who})
    from app.db.database import SessionLocal
    from app.db.models import AuditLog
    db = SessionLocal()
    try:
        assert db.query(AuditLog).filter(AuditLog.action == "company.invite", AuditLog.target == who).count() == 1
    finally:
        db.close()


def test_inviting_an_existing_account_is_refused(admin):
    assert admin.post("/api/company/invites", json={"email": admin._email}).status_code == 409
    assert admin.post("/api/company/invites", json={"email": "not-an-email"}).status_code == 422
