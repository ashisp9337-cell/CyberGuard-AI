from helpers import register_user


def test_scans_requires_auth(client):
    r = client.get("/api/scans")
    assert r.status_code == 401


def test_dashboard_requires_auth(client):
    r = client.get("/api/dashboard/overview")
    assert r.status_code == 401


def test_invalid_token_rejected(client):
    client.cookies.set("cyberguard_session", "not-a-real-jwt")
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_user_isolation(client):
    import uuid
    email_a = f"a_{uuid.uuid4().hex[:8]}@example.com"
    email_b = f"b_{uuid.uuid4().hex[:8]}@example.com"

    register_user(client, {"name": "A", "email": email_a, "password": "PassA1234"})
    client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "sms-analysis", "subtopicTitle": "SMS",
        "textInput": "You won a free prize, claim your gift card now!",
    })
    r = client.get("/api/scans")
    scans_a = r.json()["items"]
    assert len(scans_a) >= 1
    scan_id = scans_a[0]["scanId"]

    client.post("/api/auth/logout")
    register_user(client, {"name": "B", "email": email_b, "password": "PassB1234"})
    r = client.get(f"/api/scans/{scan_id}")
    assert r.status_code == 404
