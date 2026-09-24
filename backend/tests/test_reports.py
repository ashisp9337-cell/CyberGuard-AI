def test_generate_json_report(auth_client):
    auth_client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "sms-analysis", "subtopicTitle": "SMS",
        "textInput": "Hello, just checking in.",
    })
    r = auth_client.post("/api/reports", json={"title": "My Report", "format": "JSON"})
    assert r.status_code == 201
    assert r.json()["format"] == "JSON"


def test_generate_csv_report(auth_client):
    r = auth_client.post("/api/reports", json={"title": "CSV Report", "format": "CSV"})
    assert r.status_code == 201
    assert r.json()["format"] == "CSV"


def test_generate_pdf_report(auth_client):
    r = auth_client.post("/api/reports", json={"title": "PDF Report", "format": "PDF"})
    assert r.status_code == 201
    assert r.json()["format"] == "PDF"


def test_download_report(auth_client):
    r = auth_client.post("/api/reports", json={"title": "Download Me", "format": "JSON"})
    report_id = r.json()["id"]
    dl = auth_client.get(f"/api/reports/{report_id}/download")
    assert dl.status_code == 200
