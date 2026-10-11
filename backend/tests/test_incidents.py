"""Incident workflow: open -> investigating -> resolved / false positive."""
from helpers import register_user
import uuid

BRUTE_FORCE_LOG = "\n".join(
    ["Oct  7 03:12:0%d srv sshd[1]: Failed password for root from 185.220.101.4 port 44%d ssh2" % (i, i) for i in range(6)]
    + ["Oct  7 03:12:09 srv sshd[1]: Accepted password for root from 185.220.101.4"])


def _critical_scan(client):
    return client.post("/api/analysis/scan", data={
        "moduleId": "credential", "subtopicId": "failed-logins", "subtopicTitle": "Failed Logins",
        "textInput": BRUTE_FORCE_LOG, "extraFieldValues": '{"failedAttempts": "7", "newDevice": "true"}',
    }).json()


def test_high_risk_scan_becomes_open_incident(auth_client):
    scan = _critical_scan(auth_client)
    items = auth_client.get("/api/incidents").json()
    assert len(items) == 1
    i = items[0]
    assert i["status"] == "open" and i["scanId"] == scan["scanId"] and i["severity"] in ("high", "critical")
    s = auth_client.get("/api/incidents/summary").json()
    assert s["counts"]["open"] == 1 and s["active"] == 1 and s["mttrMinutes"] is None


def test_safe_scan_is_not_an_incident(auth_client):
    auth_client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "sms-analysis", "subtopicTitle": "SMS",
        "textInput": "Hi, are we still meeting for lunch at 1 tomorrow?"})
    assert auth_client.get("/api/incidents?status=all").json() == []


def test_full_workflow_with_history_and_mttr(auth_client):
    _critical_scan(auth_client)
    iid = auth_client.get("/api/incidents").json()[0]["id"]

    r = auth_client.patch(f"/api/incidents/{iid}", json={"status": "investigating", "note": "Checking SSH logs"})
    assert r.status_code == 200 and r.json()["status"] == "investigating"

    r = auth_client.patch(f"/api/incidents/{iid}", json={"status": "resolved", "note": "IP blocked, password reset"})
    body = r.json()
    assert body["status"] == "resolved" and body["resolvedAt"]
    assert [h["status"] for h in body["history"]] == ["investigating", "resolved"]
    assert body["history"][1]["note"] == "IP blocked, password reset"
    assert body["history"][0]["by"] == auth_client._test_email

    assert auth_client.get("/api/incidents").json() == []            # no longer active
    assert len(auth_client.get("/api/incidents?status=resolved").json()) == 1
    s = auth_client.get("/api/incidents/summary").json()
    assert s["counts"]["resolved"] == 1 and s["active"] == 0 and s["mttrMinutes"] is not None


def test_invalid_status_rejected(auth_client):
    _critical_scan(auth_client)
    iid = auth_client.get("/api/incidents").json()[0]["id"]
    assert auth_client.patch(f"/api/incidents/{iid}", json={"status": "deleted"}).status_code == 422


def test_cannot_touch_another_users_incident(client):
    register_user(client, {"name": "A", "email": f"a_{uuid.uuid4().hex[:8]}@example.com",
                                            "password": "PassA1234"})
    _critical_scan(client)
    iid = client.get("/api/incidents").json()[0]["id"]

    client.cookies.clear()
    register_user(client, {"name": "B", "email": f"b_{uuid.uuid4().hex[:8]}@example.com",
                                            "password": "PassB1234"})
    assert client.get("/api/incidents?status=all").json() == []
    assert client.patch(f"/api/incidents/{iid}", json={"status": "resolved"}).status_code == 404


def test_bell_read_state_is_separate(auth_client):
    _critical_scan(auth_client)
    iid = auth_client.get("/api/incidents").json()[0]["id"]
    auth_client.post("/api/events/mark-all-read")
    # Reading the notification must NOT close the incident.
    assert auth_client.get("/api/incidents").json()[0]["id"] == iid


def test_bulk_resolve_selected_and_select_all(auth_client):
    for i in range(3):   # 3 different incidents (different targets so none are merged)
        auth_client.post("/api/analysis/scan", data={
            "moduleId": "credential", "subtopicId": "failed-logins", "subtopicTitle": "Failed Logins",
            "textInput": BRUTE_FORCE_LOG.replace("185.220.101.4", f"185.220.101.{i + 10}"),
            "extraFieldValues": '{"failedAttempts": "7", "newDevice": "true"}'})
    ids = [i["id"] for i in auth_client.get("/api/incidents").json()]
    assert len(ids) == 3

    # tick two of them -> investigating
    r = auth_client.post("/api/incidents/bulk", json={"ids": ids[:2], "status": "investigating"}).json()
    assert r["changed"] == 2 and r["summary"]["counts"]["investigating"] == 2 and r["summary"]["counts"]["open"] == 1

    # select all active -> resolved
    r = auth_client.post("/api/incidents/bulk", json={"scope": "active", "status": "resolved", "note": "Cleared"}).json()
    assert r["changed"] == 3 and r["summary"]["counts"]["resolved"] == 3 and r["summary"]["active"] == 0
    assert auth_client.get("/api/incidents").json() == []

    # back to open (bulk works in every direction) and bad status is refused
    r = auth_client.post("/api/incidents/bulk", json={"ids": ids, "status": "open"}).json()
    assert r["changed"] == 3
    assert auth_client.post("/api/incidents/bulk", json={"ids": ids, "status": "gone"}).status_code == 422


def test_bulk_cannot_touch_other_users(client):
    register_user(client, {"name": "A", "email": f"a_{uuid.uuid4().hex[:8]}@example.com",
                                            "password": "PassA1234"})
    _critical_scan(client)
    iid = client.get("/api/incidents").json()[0]["id"]
    client.cookies.clear()
    register_user(client, {"name": "B", "email": f"b_{uuid.uuid4().hex[:8]}@example.com",
                                            "password": "PassB1234"})
    r = client.post("/api/incidents/bulk", json={"ids": [iid], "status": "resolved"}).json()
    assert r["matched"] == 0 and r["changed"] == 0


def test_escalate_safe_scan_creates_open_incident_and_alerts(auth_client, monkeypatch):
    from app.services import notifier
    sent = []
    monkeypatch.setattr(notifier, "send_all", lambda msg: sent.append(msg) or [
        {"channel": "telegram", "status": "sent", "error": "", "at": "now"}])
    scan = auth_client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "sms-analysis", "subtopicTitle": "SMS",
        "textInput": "Hi, are we still meeting for lunch at 1 tomorrow?"}).json()
    assert scan["classification"] in ("safe", "low_risk")
    assert auth_client.get("/api/incidents").json() == []

    r = auth_client.post("/api/incidents/escalate", json={"scanId": scan["scanId"], "note": "Looks odd to me"})
    assert r.status_code == 200
    inc_ = r.json()["incident"]
    assert inc_["status"] == "open" and inc_["severity"] == "high"
    assert inc_["history"][-1]["note"].startswith("Escalated to team")
    assert [i["id"] for i in auth_client.get("/api/incidents").json()] == [inc_["id"]]
    assert len(sent) == 1 and "ESCALATED" in sent[0]["subject"]        # alert sent despite the low score
    assert "telegram" in auth_client.get("/api/incidents").json()[0]["alertedVia"]


def test_escalate_reopens_resolved_incident_and_blocks_other_users(client, monkeypatch):
    from app.services import notifier
    monkeypatch.setattr(notifier, "send_all", lambda msg: [])
    register_user(client, {"name": "A", "email": f"a_{uuid.uuid4().hex[:8]}@example.com",
                                            "password": "PassA1234"})
    scan = _critical_scan(client)
    iid = client.get("/api/incidents").json()[0]["id"]
    client.patch(f"/api/incidents/{iid}", json={"status": "resolved"})
    r = client.post("/api/incidents/escalate", json={"scanId": scan["scanId"]}).json()
    assert r["incident"]["id"] == iid and r["incident"]["status"] == "open"

    client.cookies.clear()
    register_user(client, {"name": "B", "email": f"b_{uuid.uuid4().hex[:8]}@example.com",
                                            "password": "PassB1234"})
    assert client.post("/api/incidents/escalate", json={"scanId": scan["scanId"]}).status_code == 404

