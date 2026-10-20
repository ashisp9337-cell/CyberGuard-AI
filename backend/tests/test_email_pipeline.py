"""
Tests for the Email Intelligence Pipeline (app/email_pipeline).

All live lookups (DNS, WHOIS, SSL, VirusTotal, URLhaus) are stubbed, so the
suite runs offline and gives the same result every time.
"""
import os

import pytest

from app.email_pipeline import analyze_email
from app.email_pipeline.parser import parse_email, parse_body_only
from app.email_pipeline.enrich import enrich

SAMPLES = os.path.join(os.path.dirname(__file__), "email_samples")


def _read(name):
    with open(os.path.join(SAMPLES, name), "rb") as f:
        return f.read()


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    from app.services import network_intel, threat_intelligence
    from app.email_pipeline import attachments
    un = lambda *a, **k: {"status": "unavailable"}  # noqa: E731
    monkeypatch.setattr(network_intel, "resolve_domain", un)
    monkeypatch.setattr(network_intel, "get_domain_age", un)
    monkeypatch.setattr(network_intel, "get_ssl_info", un)
    monkeypatch.setattr(threat_intelligence, "check_virustotal_url_sync", un)
    monkeypatch.setattr(threat_intelligence, "check_urlhaus_sync", un)
    monkeypatch.setattr(attachments, "_vt_hash_lookup", un)


# ---------------------------------------------------------------- step 1: parser
def test_parser_extracts_headers_links_and_attachments():
    ev = parse_email(_read("attack_sbi_kyc_spoof.eml"))
    assert ev.is_structured
    assert ev.from_address == "alerts@sbi-yono-kyc.com"
    assert ev.from_display_name == "State Bank of India"
    assert ev.reply_to_address == "sbi.kyc.helpdesk@gmail.com"
    assert "dmarc=fail" in ev.authentication_results
    assert any(l.display_text == "https://www.onlinesbi.sbi/kyc" and "web.app" in l.url for l in ev.links)
    assert ev.x_mailer.startswith("PHPMailer")

    ev = parse_email(_read("attack_invoice_malware.eml"))
    names = {a.filename for a in ev.attachments}
    assert {"INV-20931.pdf.exe", "remittance.zip", "statement.docm", "Remittance_View.html"} <= names
    assert all(len(a.sha256) == 64 for a in ev.attachments)


def test_parser_handles_pasted_body_text():
    ev = parse_body_only("Your account is locked. Visit www.example-locked.com now", sender="x@evil.top")
    assert not ev.is_structured
    assert ev.from_domain == "evil.top"
    assert ev.links and ev.links[0].url.startswith("http://www.example-locked.com")


def test_pasted_raw_email_with_headers_is_parsed_as_email():
    raw = _read("attack_ceo_giftcard_bec.eml").decode()
    ev = parse_email(raw)
    assert ev.is_structured and ev.from_address == "rajesh.ceo.acme@gmail.com"


# ---------------------------------------------------------------- step 2: enrichment
def _triggered(ev):
    return {i["label"] for i in ev.enrichment_indicators if i["triggered"]}


def test_enrichment_auth_and_sender_checks():
    ev = enrich(parse_email(_read("attack_sbi_kyc_spoof.eml")), network=False)
    assert ev.auth["dmarc"] == "fail" and ev.auth["spf"] == "fail"
    labels = _triggered(ev)
    assert {"DMARC failed", "Sender impersonates an organisation", "Look-alike sender domain",
            "Link text hides the real destination", "Replies go to a different domain"} <= labels
    assert ev.originating_ip == "185.220.101.4"


def test_enrichment_freemail_executive_and_fake_reply():
    labels = _triggered(enrich(parse_email(_read("attack_ceo_giftcard_bec.eml")), network=False))
    assert "Free email account claiming authority" in labels
    assert "Fake reply thread" in labels


def test_enrichment_genuine_sender_has_no_red_flags():
    ev = enrich(parse_email(_read("genuine_hdfc_statement.eml")), network=False)
    assert ev.auth["dmarc"] == "pass" and ev.auth["dkim_aligned"]
    assert not _triggered(ev)


# ---------------------------------------------------------------- steps 3-4: full pipeline
ATTACKS = {
    "attack_sbi_kyc_spoof.eml": "Bank / financial institution impersonation",
    "attack_ceo_giftcard_bec.eml": "Business Email Compromise",
    "attack_invoice_malware.eml": "Malware delivery",
    "attack_qr_quishing.eml": "QR code phishing",
    "attack_cbi_digital_arrest.eml": "Government impersonation",
    "attack_fake_microsoft_alert.eml": "Credential phishing",
}
GENUINE = ["genuine_google_signin_alert.eml", "genuine_hdfc_statement.eml",
           "genuine_university_notice.eml", "genuine_amazon_shipment.eml"]


@pytest.mark.parametrize("name,category", ATTACKS.items())
def test_attacks_are_flagged_with_the_right_category(name, category):
    r = analyze_email(_read(name), network=False)
    assert r["riskScore"] > 70, (name, r["riskScore"], r["explanation"])
    assert r["classification"] in ("high_risk", "critical")
    assert r["category"].startswith(category), r["category"]
    assert r["mitre"]


@pytest.mark.parametrize("name", GENUINE)
def test_genuine_emails_are_not_flagged(name):
    r = analyze_email(_read(name), network=False)
    assert r["classification"] == "safe", (name, r["riskScore"], r["explanation"])


def test_attachment_scanner_findings():
    r = analyze_email(_read("attack_invoice_malware.eml"), network=False)
    labels = " | ".join(i["label"] for i in r["indicators"] if i["triggered"])
    for expected in ("Executable or script attachment", "Double file extension", "Password-protected archive",
                     "Office document with macros", "Login form inside attachment"):
        assert expected in labels, expected


def test_qr_code_in_image_attachment_is_decoded():
    r = analyze_email(_read("attack_qr_quishing.eml"), network=False)
    assert any(c["component"] == "qr" and c["score"] >= 60 for c in r["components"])


def test_genuine_security_alert_becomes_account_takeover_signal_not_phishing():
    r = analyze_email(_read("genuine_google_signin_alert.eml"), network=False)
    assert r["category"].startswith("Genuine account-security notification")
    assert any(c["component"] == "account_takeover" for c in r["components"])


def test_fake_security_alert_is_phishing():
    r = analyze_email(_read("attack_fake_microsoft_alert.eml"), network=False)
    ato = [c for c in r["components"] if c["component"] == "account_takeover"]
    assert ato and "Unverified security alert" in str(r["indicators"])


def test_result_is_json_serialisable():
    import json
    for name in list(ATTACKS) + GENUINE:
        json.dumps(analyze_email(_read(name), network=False))


# ---------------------------------------------------------------- API
def test_email_api_upload_saves_record_and_history(auth_client):
    for _ in range(2):
        r = auth_client.post("/api/email/analyze",
                             files={"file": ("sbi.eml", _read("attack_sbi_kyc_spoof.eml"), "message/rfc822")})
        assert r.status_code == 200, r.text
    body = r.json()
    assert body["classification"] == "critical" and body["emailRecordId"] and body["scanId"]

    recs = auth_client.get("/api/email/records").json()
    assert len(recs) == 2 and recs[0]["dmarc"] == "fail"
    detail = auth_client.get(f"/api/email/records/{recs[0]['id']}").json()
    assert detail["components"] and detail["auth"]["spf"] == "fail"

    # it also appears in normal scan history
    scans = auth_client.get("/api/scans").json()
    items = scans["items"] if isinstance(scans, dict) and "items" in scans else scans
    assert any(s.get("scanId") == body["scanId"] for s in items)


def test_email_api_paste_and_validation(auth_client):
    r = auth_client.post("/api/email/analyze", data={"rawEmail": _read("attack_ceo_giftcard_bec.eml").decode()})
    assert r.status_code == 200 and r.json()["category"].startswith("Business Email Compromise")
    assert auth_client.post("/api/email/analyze", data={}).status_code == 422
    r = auth_client.post("/api/email/analyze", files={"file": ("x.exe", b"MZ", "application/octet-stream")})
    assert r.status_code == 400


def test_existing_email_analysis_screen_uses_pipeline(auth_client):
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "email-analysis", "subtopicTitle": "Email Analysis"},
        files={"file": ("invoice.eml", _read("attack_invoice_malware.eml"), "message/rfc822")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "Email Intelligence Pipeline" in body["analysisEngine"]
    assert body["classification"] == "critical"
    assert len(auth_client.get("/api/email/records").json()) == 1


def test_email_api_requires_login(client):
    assert client.post("/api/email/analyze", data={"rawEmail": "hi"}).status_code == 401
