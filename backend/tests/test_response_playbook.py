"""Response actions must match the threat that was detected."""
from app.services.response_playbook import build_actions


def _ind(label):
    return {"label": label, "triggered": True}


def _actions(result, module, sub, target=""):
    return {a["action"] for a in build_actions(result, module, sub, target)}


def test_safe_result_gets_no_actions():
    assert build_actions({"classification": "safe", "indicators": []}, "phishing", "sms-analysis") == []


def test_account_takeover_gets_revoke_mfa_and_ip_block():
    res = {"classification": "critical", "indicators": [_ind("Successful login after repeated failures")]}
    acts = build_actions(res, "credential", "failed-logins", "Failed password for root from 185.220.101.4")
    kinds = {a["action"] for a in acts}
    assert {"revoke_session", "require_mfa", "block_ip", "notify_soc", "escalate_incident"} <= kinds
    assert any("185.220.101.4" in a["title"] for a in acts)
    assert "quarantine_email" not in kinds


def test_private_ip_is_not_blocked():
    res = {"classification": "high_risk", "indicators": []}
    acts = build_actions(res, "credential", "failed-logins", "Failed password for admin from 192.168.1.5")
    assert not any("192.168.1.5" in a["title"] for a in acts)


def test_phishing_email_quarantined_but_real_bank_link_not_blocked():
    res = {"classification": "high_risk", "indicators": [],
           "email": {"links": [{"url": "https://www.onlinesbi.sbi/"}, {"url": "http://sbi-kyc-update.xyz/login"}]}}
    acts = build_actions(res, "phishing", "email-analysis")
    titles = [a["title"] for a in acts]
    assert "quarantine_email" in {a["action"] for a in acts}
    assert "Block sbi-kyc-update.xyz" in titles
    assert not any("onlinesbi" in t for t in titles), titles


def test_government_impersonation_gets_digital_arrest_warning_and_report():
    res = {"classification": "high_risk", "indicators": []}
    acts = build_actions(res, "impersonation", "government-impersonation")
    assert "report_impersonation" in {a["action"] for a in acts}
    assert any("digital arrest" in a["title"].lower() for a in acts)


def test_deepfake_flagged_for_manual_verification():
    assert "flag_media" in _actions({"classification": "suspicious", "indicators": []}, "deepfake", "video-analysis")


def test_api_returns_specific_recommendations(auth_client):
    log = "\n".join(["Oct  7 03:12:0%d srv sshd[1]: Failed password for root from 185.220.101.4 port 44%d ssh2" % (i, i)
                     for i in range(6)] + ["Oct  7 03:12:09 srv sshd[1]: Accepted password for root from 185.220.101.4"])
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "credential", "subtopicId": "failed-logins", "subtopicTitle": "Failed Logins",
        "textInput": log, "extraFieldValues": '{"failedAttempts": "7", "newDevice": "true"}',
    })
    body = r.json()
    assert body["classification"] in ("high_risk", "critical")
    assert {"revoke_session", "block_ip"} <= {a["action"] for a in body["responseActions"]}
    assert body["recommendations"][0].startswith(body["responseActions"][0]["title"])

def test_cut_off_target_does_not_create_bogus_block(auth_client):
    # The URL crosses the 80-character cut used for the scan's short "target",
    # so the cut-off copy ("indiapost-f") must not become a second block action.
    sms = ("India Post: your parcel is on hold, unpaid fee Rs 25. Pay now "
           "http://indiapost-fee.top/pay?id=8842 or it returns. Act urgently, last warning today.")
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "sms-analysis", "subtopicTitle": "SMS / Message Analysis",
        "textInput": sms,
    })
    titles = [a["title"] for a in r.json()["responseActions"]]
    blocks = [t for t in titles if "indiapost" in t]
    assert blocks and all("indiapost-fee.top" in t for t in blocks), titles
