"""Auto-quarantine: dangerous emails are held automatically; analysts can release / delete them."""
from helpers import register_user
import os
import uuid

from app.core.config import get_settings

SAMPLES = os.path.join(os.path.dirname(__file__), "email_samples")


def _read(name):
    with open(os.path.join(SAMPLES, name), "rb") as f:
        return f.read()


def _analyze(client, name):
    return client.post("/api/email/analyze", files={"file": (name, _read(name), "message/rfc822")}).json()


def test_dangerous_email_is_quarantined_automatically(auth_client):
    body = _analyze(auth_client, "attack_sbi_kyc_spoof.eml")
    assert body["riskScore"] >= get_settings().QUARANTINE_MIN_SCORE
    assert body["quarantine"]["status"] == "quarantined" and body["quarantine"]["auto"] is True
    assert any(a["title"] == "Email quarantined automatically" for a in body["responseActions"])

    q = auth_client.get("/api/email/quarantine").json()
    assert q["counts"]["quarantined"] == 1
    item = q["items"][0]
    assert item["id"] == body["emailRecordId"] and item["status"] == "quarantined"
    assert item["history"][0]["by"] == "CYBERGUARD (automatic)"


def test_genuine_email_is_delivered(auth_client):
    body = _analyze(auth_client, "genuine_hdfc_statement.eml")
    assert body["quarantine"]["status"] == "delivered"
    assert auth_client.get("/api/email/quarantine").json()["items"] == []


def test_release_and_delete_keep_an_audit_trail(auth_client):
    rid = _analyze(auth_client, "attack_ceo_giftcard_bec.eml")["emailRecordId"]

    r = auth_client.post(f"/api/email/records/{rid}/action", json={"action": "release", "note": "Checked with CEO"})
    assert r.status_code == 200 and r.json()["status"] == "released"
    r = auth_client.post(f"/api/email/records/{rid}/action", json={"action": "delete", "note": "Actually a scam"})
    hist = r.json()["history"]
    assert [h["action"] for h in hist] == ["quarantined", "released", "deleted"]
    assert hist[1]["by"] == auth_client._test_email and hist[1]["note"] == "Checked with CEO"

    q = auth_client.get("/api/email/quarantine").json()
    assert q["items"] == [] and q["counts"] == {"quarantined": 0, "released": 0, "deleted": 1}


def test_invalid_action_and_other_users_record(client):
    register_user(client, {"name": "A", "email": f"a_{uuid.uuid4().hex[:8]}@example.com",
                                            "password": "PassA1234"})
    rid = _analyze(client, "attack_sbi_kyc_spoof.eml")["emailRecordId"]
    assert client.post(f"/api/email/records/{rid}/action", json={"action": "explode"}).status_code == 422

    client.cookies.clear()
    register_user(client, {"name": "B", "email": f"b_{uuid.uuid4().hex[:8]}@example.com",
                                            "password": "PassB1234"})
    assert client.post(f"/api/email/records/{rid}/action", json={"action": "release"}).status_code == 404
    assert client.get("/api/email/quarantine").json()["items"] == []


def test_email_scanned_from_analysis_page_is_quarantined_too(auth_client):
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "email-analysis", "subtopicTitle": "Email Analysis",
        "textInput": _read("attack_fake_microsoft_alert.eml").decode()})
    body = r.json()
    assert body["quarantine"]["status"] == "quarantined"
    assert auth_client.get("/api/email/quarantine").json()["counts"]["quarantined"] == 1


def test_auto_quarantine_can_be_switched_off(auth_client, monkeypatch):
    monkeypatch.setattr(get_settings(), "AUTO_QUARANTINE", False)
    body = _analyze(auth_client, "attack_sbi_kyc_spoof.eml")
    assert body["quarantine"]["status"] == "delivered"
    assert any(a["title"] == "Quarantine this email" for a in body["responseActions"])
