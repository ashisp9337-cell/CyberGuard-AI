def test_phishing_scan_flags_suspicious_email(auth_client):
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "email-analysis", "subtopicTitle": "Email Analysis",
        "textInput": "URGENT: verify your password immediately or your account will be suspended. Click http://totally-legit-bank.tk/login now.",
        "extraFieldValues": '{"sender":"noreply@random-domain.ru"}',
    })
    assert r.status_code == 200
    body = r.json()
    assert body["riskScore"] > 40
    assert body["classification"] in ("suspicious", "high_risk", "critical")
    assert len(body["indicators"]) > 0
    assert any(i["triggered"] for i in body["indicators"])


def test_phishing_scan_safe_text(auth_client):
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "sms-analysis", "subtopicTitle": "SMS",
        "textInput": "Hey, are we still meeting for lunch at noon tomorrow?",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["riskScore"] < 50


def test_malicious_url_scan(auth_client):
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "url-security", "subtopicId": "lookalike-domain", "subtopicTitle": "Lookalike Domain",
        "urlInput": "http://192.168.1.1@secure-paypal-login.tk/verify?user=1&pass=2",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["riskScore"] > 0
    assert body["targetType"] == "url"


def test_malformed_scan_missing_fields(auth_client):
    r = auth_client.post("/api/analysis/scan", data={})
    assert r.status_code == 422


def test_credential_event_scan(auth_client):
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "credential", "subtopicId": "failed-logins", "subtopicTitle": "Failed Logins",
        "extraFieldValues": '{"failedAttempts": "20", "impossibleTravel": "true", "newDevice": "true"}',
    })
    assert r.status_code == 200
    body = r.json()
    assert body["classification"] in ("high_risk", "critical")


def test_unsupported_file_type_rejected(auth_client):
    r = auth_client.post(
        "/api/analysis/scan",
        data={"moduleId": "deepfake", "subtopicId": "image-analysis", "subtopicTitle": "Image Analysis"},
        files={"file": ("malware.exe", b"MZfakecontent", "application/octet-stream")},
    )
    assert r.status_code == 400
