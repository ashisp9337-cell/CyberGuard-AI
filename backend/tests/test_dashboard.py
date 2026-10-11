"""Dashboard activity chart: right category, today included, safe scans not counted."""
from datetime import datetime, timezone


def _today_point(auth_client, days=7):
    r = auth_client.get(f"/api/dashboard/activity?days={days}")
    assert r.status_code == 200
    points = r.json()
    assert len(points) == days
    today = datetime.now(timezone.utc).strftime("%b %d")
    assert points[-1]["label"] == today, "last bucket must be today"
    return points[-1]


def test_impersonation_counted_as_impersonation_not_malware(auth_client):
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "impersonation", "subtopicId": "government-impersonation",
        "subtopicTitle": "Government Official Impersonation",
        "textInput": "This is CBI officer. A case is registered against your Aadhaar for money laundering. "
                     "You are under digital arrest. Do not tell anyone. Transfer Rs 95,000 to the RBI "
                     "verification account immediately or police will arrest you today.",
    })
    assert r.status_code == 200
    assert r.json()["classification"] in ("suspicious", "high_risk", "critical")
    p = _today_point(auth_client)
    assert p["impersonation"] == 1
    assert p["malware"] == 0


def test_safe_scan_is_not_a_detection(auth_client):
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "sms-analysis", "subtopicTitle": "SMS / Message Analysis",
        "textInput": "Hi, are we still meeting for lunch at 1 tomorrow?",
    })
    assert r.status_code == 200
    assert r.json()["classification"] in ("safe", "low_risk")
    assert _today_point(auth_client)["phishing"] == 0


def test_24h_range_shows_today(auth_client):
    _today_point(auth_client, days=1)

    

def test_top_targets_lists_impersonated_org_and_attacked_account(auth_client):
    # An SBI KYC scam SMS -> service "SBI"
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "sms-analysis", "subtopicTitle": "SMS / Message Analysis",
        "textInput": "Dear SBI customer, your YONO account will be blocked today. Update KYC now at "
                     "http://sbi-yono-kyc.web.app/update and enter OTP to avoid suspension.",
    })
    assert r.status_code == 200
    assert r.json()["classification"] in ("suspicious", "high_risk", "critical")

    # A phishing link -> service found from the URL itself
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "malicious-url", "subtopicTitle": "Malicious URL Analysis",
        "urlInput": "https://sbi-yono-kyc.web.app/login",
    })
    assert r.status_code == 200

    # Brand glued inside a look-alike link -> service "Microsoft"
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "malicious-url", "subtopicTitle": "Malicious URL Analysis",
        "urlInput": "https://login.microsoftonline.com.secure-auth.ru/owa/",
    })
    assert r.status_code == 200

    # A brute-force log -> account "root"
    log = "\n".join(["Oct  7 03:12:0%d srv sshd[1]: Failed password for root from 185.220.101.4 port 44%d ssh2" % (i, i)
                     for i in range(6)] + ["Oct  7 03:12:09 srv sshd[1]: Accepted password for root from 185.220.101.4"])
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "credential", "subtopicId": "failed-logins", "subtopicTitle": "Multiple Failed Login Attempts",
        "textInput": log, "extraFieldValues": '{"failedAttempts": "7", "newDevice": "true"}',
    })
    assert r.status_code == 200

    r = auth_client.get("/api/dashboard/top-targets")
    assert r.status_code == 200
    body = r.json()
    names = [s["name"] for s in body["services"]]
    assert "SBI" in names, body
    sbi = next(s for s in body["services"] if s["name"] == "SBI")
    assert sbi["count"] >= 2
    assert "Microsoft" in names, body
    assert "root" in [a["name"] for a in body["accounts"]], body


def test_top_targets_empty_for_new_user(auth_client):
    body = auth_client.get("/api/dashboard/top-targets").json()
    assert body["services"] == [] and body["accounts"] == []