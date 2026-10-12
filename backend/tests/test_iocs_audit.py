"""IOC memory ("seen before"), allowlisting, blocklist export, and the audit (activity) log."""
import uuid

from helpers import login_user, register_user


def _user_id(client):
    return client.get("/api/auth/me").json()["id"]


def _result(score, explanation="test"):
    from app.services.risk_scoring import classify_risk, severity_from_classification
    c = classify_risk(score)
    return {"riskScore": score, "classification": c, "severity": severity_from_classification(c),
            "confidenceScore": 80, "threatType": "Malicious URL", "analysisEngine": "test",
            "explanation": explanation, "indicators": [], "recommendations": []}


def _save(uid, target, result, module="url-security"):
    from app.db.database import SessionLocal
    from app.services import scan_store
    db = SessionLocal()
    try:
        scan = scan_store.save_result(db, user_id=uid, module_id=module, subtopic_id="general",
                                      subtopic_title="t", result=result, target=target, target_type="url")
        db.commit()
        return scan.id, result
    finally:
        db.close()


def test_risky_url_is_remembered_and_flagged_when_seen_again(auth_client):
    uid = _user_id(auth_client)
    dom = f"sbi-kyc-{uuid.uuid4().hex[:6]}.top"
    _save(uid, f"https://{dom}/login", _result(82))
    iocs = auth_client.get("/api/iocs").json()
    values = {(i["type"], i["value"]) for i in iocs}
    assert ("domain", dom) in values and ("url", f"https://{dom}/login") in values

    _, again = _save(uid, f"https://{dom}/verify-account", _result(30))          # new link, same domain
    labels = [i["label"] for i in again["indicators"]]
    assert "Seen before in an earlier threat" in labels
    assert again["riskScore"] >= 60 and again["classification"] in ("suspicious", "high_risk", "critical")
    assert any(i["type"] == "domain" for i in again["iocHits"])


def test_safe_scans_and_official_sites_are_not_recorded(auth_client):
    uid = _user_id(auth_client)
    _save(uid, "https://accounts.google.com/signin", _result(85))                 # trusted official site
    _save(uid, "https://harmless-blog-example.org/post", _result(10))             # safe -> not an IOC
    values = {i["value"] for i in auth_client.get("/api/iocs").json()}
    assert "google.com" not in values and "harmless-blog-example.org" not in values


def test_allowlisted_indicator_stops_raising_scores(auth_client):
    uid = _user_id(auth_client)
    dom = f"fp-{uuid.uuid4().hex[:6]}.xyz"
    _save(uid, f"https://{dom}/", _result(75))
    row = next(i for i in auth_client.get("/api/iocs").json() if i["value"] == dom)
    r = auth_client.patch(f"/api/iocs/{row['id']}", json={"status": "allowlisted", "note": "our test site"})
    assert r.status_code == 200 and r.json()["status"] == "allowlisted"
    _, again = _save(uid, f"https://{dom}/page", _result(20))
    assert "Seen before in an earlier threat" not in [i["label"] for i in again["indicators"]]
    assert again["riskScore"] == 20


def test_email_observables_skip_freemail_domains():
    from app.services import ioc
    result = {"email": {"from_address": "Scammer@Gmail.com", "originating_ip": "185.220.101.4",
                        "links": [{"url": "http://sbi-kyc-update.top/login"}],
                        "attachments": [{"sha256": "A" * 64, "is_inline": False}]}}
    c = ioc.candidates(result, "subject", "phishing")
    assert ("email", "scammer@gmail.com") in c and ("domain", "gmail.com") not in c
    assert ("ip", "185.220.101.4") in c and ("sha256", "a" * 64) in c and ("domain", "sbi-kyc-update.top") in c
    assert not any(t == "ip" and v.startswith("192.168.") for t, v in ioc.candidates({}, "from 192.168.1.5", "credential"))


def test_iocs_are_private_per_user_and_export_is_csv(client):
    a = f"a_{uuid.uuid4().hex[:6]}@example.com"
    b = f"b_{uuid.uuid4().hex[:6]}@example.com"
    register_user(client, {"name": "A", "email": a, "password": "TestPass123"})
    uid_a = _user_id(client)
    dom = f"only-a-{uuid.uuid4().hex[:6]}.top"
    _save(uid_a, f"https://{dom}/", _result(90))
    csv_text = client.get("/api/iocs/export.csv").text
    assert csv_text.startswith("type,value") and dom in csv_text
    summary = client.get("/api/iocs/summary").json()
    assert summary["total"] >= 1 and summary["byType"]["domain"] >= 1
    client.post("/api/auth/logout")
    register_user(client, {"name": "B", "email": b, "password": "TestPass123"})
    assert dom not in {i["value"] for i in client.get("/api/iocs").json()}
    row_id = None
    from app.db.database import SessionLocal
    from app.db.models import IOC
    db = SessionLocal()
    try:
        row_id = db.query(IOC).filter(IOC.value == dom).first().id
    finally:
        db.close()
    assert client.patch(f"/api/iocs/{row_id}", json={"status": "allowlisted"}).status_code == 404


def test_incident_shows_seen_before(auth_client):
    uid = _user_id(auth_client)
    dom = f"repeat-{uuid.uuid4().hex[:6]}.top"
    _save(uid, f"https://{dom}/a", _result(88))
    _save(uid, f"https://{dom}/b", _result(88))
    rows = auth_client.get("/api/incidents?status=all&limit=100").json()
    mine = [r for r in rows if dom in r["target"]]
    assert {r["seenBefore"] for r in mine} == {False, True}


# ---- audit log -----------------------------------------------------------------------------------
def test_audit_log_records_sign_ins_failures_and_settings(client):
    email = f"aud_{uuid.uuid4().hex[:6]}@example.com"
    register_user(client, {"name": "Aud", "email": email, "password": "TestPass123"})
    client.post("/api/auth/logout")
    assert client.post("/api/auth/login", json={"email": email, "password": "WrongPass999"}).status_code == 401
    assert login_user(client, email, "TestPass123").status_code == 200
    assert client.put("/api/settings", json={"sensitivity": "high"}).status_code == 200
    rows = client.get("/api/audit").json()
    actions = [r["action"] for r in rows]
    assert {"auth.signup", "auth.login_failed", "auth.login", "settings.update"} <= set(actions)
    failed = next(r for r in rows if r["action"] == "auth.login_failed")
    assert failed["success"] is False and failed["label"] == "Failed sign-in"
    assert "TestPass123" not in str(rows) and "WrongPass999" not in str(rows)        # never stores passwords


def test_audit_log_is_private(client):
    a = f"pa_{uuid.uuid4().hex[:6]}@example.com"
    register_user(client, {"name": "PA", "email": a, "password": "TestPass123"})
    client.put("/api/settings", json={"sensitivity": "low"})
    client.post("/api/auth/logout")
    register_user(client, {"name": "PB", "email": f"pb_{uuid.uuid4().hex[:6]}@example.com", "password": "TestPass123"})
    assert all(r["actor"] != a for r in client.get("/api/audit").json())
