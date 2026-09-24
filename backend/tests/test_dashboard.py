def test_dashboard_empty(auth_client):
    r = auth_client.get("/api/dashboard/overview")
    assert r.status_code == 200
    body = r.json()
    assert body["totalScans"] == 0
    assert body["securityScore"] == 100


def test_dashboard_reflects_scans(auth_client):
    auth_client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "sms-analysis", "subtopicTitle": "SMS",
        "textInput": "URGENT click http://scam.tk now and enter your password to claim your prize!",
    })
    r = auth_client.get("/api/dashboard/overview")
    body = r.json()
    assert body["totalScans"] == 1
