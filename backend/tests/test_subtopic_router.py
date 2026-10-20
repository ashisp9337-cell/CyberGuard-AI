"""Auto subtopic classification + routing (app/services/subtopic_router.py).

Detectors are replaced by spies, so these tests check WHICH existing detector is
called, WITH WHAT input, and that its result is passed back untouched -- without
changing or depending on any detection logic.
"""
import os
import struct
import zlib

import pytest

from app.services import analysis_service, subtopic_router as sr
from app.services.subtopic_router import RoutingError

SAMPLES = os.path.join(os.path.dirname(__file__), "email_samples")
SSH_LOG = "\n".join(f"Oct  7 03:12:0{i} srv sshd[1]: Failed password for root from 185.220.101.4 port 44{i} ssh2"
                    for i in range(6))


def _sample(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return f.read()


def _png(path):
    raw = b"\x00\xff\xff\xff"
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    data = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
    path.write_bytes(data)
    return str(path)


def classify(module, text=None, url=None, fp=None, fn=None, extra=None):
    return sr.classify(module_id=module, text_input=text, url_input=url, file_path=fp, file_name=fn,
                       extra_field_values=extra or {})


def route(module, text=None, url=None, fp=None, fn=None, extra=None):
    return sr.route(module_id=module, text_input=text, url_input=url, file_path=fp, file_name=fn,
                    extra_field_values=extra or {})


class Spy:
    """Stands in for a detector: records the call and returns a sentinel result."""
    def __init__(self, name):
        self.name, self.calls = name, []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {"riskScore": 42, "classification": "suspicious", "severity": "medium", "confidenceScore": 50,
                "analysisEngine": f"SPY:{self.name}", "threatType": "spy", "indicators": [],
                "recommendations": [], "explanation": "sentinel", "_sentinel": self.name}


DETECTORS = {
    "analyze_text": (analysis_service.phishing, "analyze_text"),
    "analyze_url": (analysis_service.malicious_url, "analyze_url"),
    "analyze_qr": (analysis_service.qr_analyzer, "analyze_qr"),
    "analyze_media": (analysis_service.deepfake, "analyze_media"),
    "analyze_identity": (analysis_service.impersonation, "analyze_identity"),
    "government": (analysis_service.government_impersonation, "analyze_government_impersonation"),
    "management": (analysis_service.senior_management_impersonation, "analyze_senior_management_impersonation"),
    "teacher": (analysis_service.teacher_university_impersonation, "analyze_teacher_university_impersonation"),
    "financial": (analysis_service.financial_impersonation, "analyze_financial_impersonation"),
    "brand": (analysis_service.brand_impersonation, "analyze_brand_impersonation"),
    "contact": (analysis_service.known_contact_impersonation, "analyze_known_contact_message"),
    "analyze_event": (analysis_service.account_takeover, "analyze_event"),
    "analyze_event_text": (analysis_service.cyber_threat, "analyze_event_text"),
}


@pytest.fixture()
def spies(monkeypatch):
    import app.email_pipeline as ep
    all_spies = {}
    for key, (mod, attr) in DETECTORS.items():
        s = Spy(key)
        monkeypatch.setattr(mod, attr, s)
        all_spies[key] = s
    s = Spy("analyze_email")
    monkeypatch.setattr(ep, "analyze_email", s)
    all_spies["analyze_email"] = s
    return all_spies


def called(spies):
    return [k for k, s in spies.items() if s.calls]


# ---------------------------------------------------------------------------
# 1. Classification of representative inputs
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("module,kwargs,expected", [
    ("phishing", {"text": "SAMPLE:attack_sbi_kyc_spoof.eml"}, "email-analysis"),
    ("phishing", {"text": "Dear customer, your account is blocked. Update KYC http://kyc-upd.xyz/u"}, "sms-analysis"),
    ("phishing", {"text": "Your Instagram has a copyright strike. DM @meta_support_team to appeal"}, "social-media-analysis"),
    ("phishing", {"text": "Claim your gift", "extra": {"platform": "facebook"}}, "social-media-analysis"),
    ("phishing", {"text": "https://sbi-yono-kyc.web.app/login"}, "malicious-url"),
    ("phishing", {"url": "https://paypa1-secure.com"}, "fraudulent-website"),
    ("impersonation", {"text": "SAMPLE:attack_cbi_digital_arrest.eml"}, "government-impersonation"),
    ("impersonation", {"text": "SAMPLE:attack_ceo_giftcard_bec.eml"}, "management-impersonation"),
    ("impersonation", {"text": "Dear SBI customer, your KYC is pending. Call now to avoid a block."}, "financial-impersonation"),
    ("impersonation", {"text": "Your Amazon refund is pending, verify here.\nAmazon Customer Support"}, "brand-impersonation"),
    ("impersonation", {"text": "Dear student, pay the re-evaluation fee today.\nRegards,\nProf. Mishra, HOD"}, "teacher-impersonation"),
    ("impersonation", {"text": "Hi beta, this is your mom, my phone is broken. Send 5000 to this new number"}, "contact-impersonation"),
    ("credential", {"text": SSH_LOG}, "failed-logins"),
    ("credential", {"text": "\n".join(f"2026-10-07 10:0{i}:00 login failed user={u} ip=45.9.1.2"
                                      for i, u in enumerate("alice bob carol dave erin frank".split()))}, "password-spraying"),
    ("credential", {"text": "2026-10-07 09:00:00 login success user=a location=Mumbai\n"
                            "2026-10-07 09:40:00 login success user=a location=London"}, "unusual-location"),
    ("credential", {"text": "2026-10-01 09:11:00 sign-in success user=asha ip=117.200.45.10 country=IN ASN=AS9829\n"
                            "2026-10-02 09:12:00 sign-in success user=asha ip=117.200.45.10 country=IN ASN=AS9829"},
     "unusual-location"),    # successful logins only: checked against the account's own history
    ("credential", {"text": "\n".join(f"Oct  7 04:0{i}:10 srv sshd[9]: Failed password for invalid user {u} from 45.155.205.10 port 4 ssh2"
                                      for i, u in enumerate(["oracle", "test", "guest", "ubuntu", "pi"]))},
     "failed-logins"),       # guessing usernames that do not exist is password guessing, not spraying
    ("credential", {"text": "", "extra": {"newDevice": "true"}}, "unknown-device"),
    ("credential", {"text": "MFA method changed for ashis; recovery email changed"}, "behavior-changes"),
    ("credential", {"text": "", "extra": {"massDownload": "true"}}, "session-activity"),
    ("url-security", {"url": "https://login.microsoftonline.com.secure-auth.ru/owa/"}, "domain-spoofing"),
    ("url-security", {"url": "https://www.amaz0n-prime.com/billing"}, "lookalike-domain"),
    ("url-security", {"url": "https://xn--pple-43d.com/id"}, "lookalike-domain"),
    ("url-security", {"url": "http://user@203.0.113.9:8080/x"}, "url-manipulation"),
    ("url-security", {"url": "https://bit.ly/3kYcQ9z"}, "redirect-analysis"),
    ("url-security", {"url": "https://example-shop.com/account/signin"}, "fake-login-page"),
    ("url-security", {"url": "http://example-shop.com/catalogue"}, "ssl-domain-analysis"),
    ("cyber-threat", {"text": "Oct 10 12:00:01 fw01 kernel: DROP SRC=45.9.1.2 DST=10.0.0.5 PROTO=TCP DPT=22"}, "network-traffic"),
    ("cyber-threat", {"text": '10.0.0.7 - - [10/Oct/2026:12:00:01 +0530] "GET /api/v1/users?page=2 HTTP/1.1" 200 512'}, "api-abuse"),
    ("cyber-threat", {"text": "EventID=4688 NewProcessName=cmd.exe CommandLine=powershell -enc SQBFAFgA"}, "malware-detection"),
    ("cyber-threat", {"text": "2026-10-10 02:11:00 user=ravi uploaded 4.2 GB to mega.nz via rclone"}, "data-exfiltration"),
    ("cyber-threat", {"text": "2026-10-10 user=ravi action=copy file=payroll.xlsx dest=USB removable drive"}, "insider-threat"),
    ("cyber-threat", {"text": "2026-10-10 03:00:00 user=ravi action=login\n2026-10-10 03:05:00 user=ravi action=file_read"}, "abnormal-activity"),
    ("cyber-threat", {"text": "2026-10-10T12:00:00Z ERROR db-pool: connection refused after 3 retries"}, "log-analysis"),
])
def test_classifies_subtopic(module, kwargs, expected):
    kwargs = dict(kwargs)
    if str(kwargs.get("text", "")).startswith("SAMPLE:"):
        kwargs["text"] = _sample(kwargs["text"][7:])
    assert classify(module, **kwargs).subtopic_id == expected


def test_file_types_by_content(tmp_path):
    img = _png(tmp_path / "x.png")
    assert classify("phishing", fp=img, fn="x.png").subtopic_id == "qr-phishing"
    assert classify("deepfake", fp=img, fn="x.png").subtopic_id == "image-analysis"
    eml = tmp_path / "m.eml"
    eml.write_text(_sample("genuine_hdfc_statement.eml"), encoding="utf-8")
    assert classify("phishing", fp=str(eml), fn="m.eml").subtopic_id == "email-analysis"
    vid = tmp_path / "clip.mp4"
    vid.write_bytes(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 32)
    assert classify("deepfake", fp=str(vid), fn="clip.mp4").subtopic_id == "video-analysis"
    call = tmp_path / "zoom_0.mp4"
    call.write_bytes(vid.read_bytes())
    assert classify("deepfake", fp=str(call), fn="zoom_0.mp4").subtopic_id == "video-call"
    assert classify("deepfake", fp=img, fn="x.png", extra={"aiGenerated": "true"}).subtopic_id == "ai-multimedia"
    # a .png name on non-image content is NOT trusted as an image
    fake = tmp_path / "fake.png"
    fake.write_bytes(b"MZ\x90\x00 not an image")
    with pytest.raises(RoutingError):
        classify("deepfake", fp=str(fake), fn="fake.png")


def test_type_is_not_threat():
    """A genuine e-mail is still classified as an e-mail: the classifier never judges maliciousness."""
    c = classify("phishing", text=_sample("genuine_amazon_shipment.eml"))
    assert c.subtopic_id == "email-analysis" and c.status == "routed"


# ---------------------------------------------------------------------------
# 2. Routing to the correct existing detector, with the ORIGINAL input
# ---------------------------------------------------------------------------
def test_routes_sms_to_message_detector_unchanged(spies):
    text = "  Dear customer, your account is BLOCKED. Update KYC http://kyc-upd.xyz/u  \n"
    result, c = route("phishing", text=text, extra={"sender": "VK-ALERT"})
    assert called(spies) == ["analyze_text"]
    args, kwargs = spies["analyze_text"].calls[0]
    assert args[0] == text                                   # exact original text, not stripped
    assert kwargs["subtopic_id"] == "sms-analysis" and kwargs["sender"] == "VK-ALERT"
    assert result["_sentinel"] == "analyze_text" and result["riskScore"] == 42   # detector result untouched


def test_routes_email_text_to_email_pipeline(spies):
    raw = _sample("attack_sbi_kyc_spoof.eml")
    result, c = route("phishing", text=raw)
    assert called(spies) == ["analyze_email"]
    assert spies["analyze_email"].calls[0][0][0] == raw
    assert result["_sentinel"] == "analyze_email"


def test_email_with_url_still_goes_to_email_detector(spies):
    raw = "From: a@b.com\nSubject: hi\n\nclick https://evil.example/login now"
    route("phishing", text=raw)
    assert called(spies) == ["analyze_email"]


def test_routes_url_and_qr(spies, tmp_path):
    route("phishing", url="https://sbi-yono-kyc.web.app/login")
    args, kwargs = spies["analyze_url"].calls[0]
    assert args[0] == "https://sbi-yono-kyc.web.app/login" and kwargs["subtopic_id"] == "malicious-url"
    img = _png(tmp_path / "qr.png")
    route("phishing", fp=img, fn="qr.png")
    assert spies["analyze_qr"].calls[0][0][0] == img


def test_routes_impersonation_to_category_detector(spies):
    text = _sample("attack_cbi_digital_arrest.eml")
    result, c = route("impersonation", text=text, extra={"claimedSenderName": "CBI"})
    assert called(spies) == ["government"]
    args = spies["government"].calls[0][0]
    assert args[0] == text and args[1] == {"claimedSenderName": "CBI"}
    assert result["_sentinel"] == "government"


def test_unclear_identity_runs_every_impersonation_detector(spies):
    result, c = route("impersonation", text="Please send me the files by evening.")
    assert c.status == "fallback"
    assert sorted(called(spies)) == sorted(["government", "management", "teacher", "financial", "brand",
                                            "contact", "analyze_identity"])
    assert len(result["checkedDetectors"]) == 7


def test_message_to_a_student_goes_to_teacher_university():
    text = ("Dear Student, your hall ticket for the semester exam is blocked due to pending fees of Rs 3,450. "
            "Pay within 2 hours at bit.ly/exam-fee-pay or you will not be allowed to appear.")
    c = sr._classify_impersonation(text, {}, None, None)
    assert c.subtopic_id == "teacher-impersonation"


def test_routes_credential_and_cyber_and_url_module(spies):
    _, c = route("credential", text=SSH_LOG, extra={"failedAttempts": "6"})
    args, kwargs = spies["analyze_event"].calls[0]
    assert args[0] == {"failedAttempts": "6"} and kwargs["text"] == SSH_LOG and c.subtopic_id == "failed-logins"

    log = "Oct 10 12:00:01 fw01 kernel: DROP SRC=45.9.1.2 DST=10.0.0.5 PROTO=TCP DPT=22"
    route("cyber-threat", text=log)
    assert spies["analyze_event_text"].calls[0][0][0] == log

    route("url-security", url="https://bit.ly/3kYcQ9z")
    assert spies["analyze_url"].calls[0][0][0] == "https://bit.ly/3kYcQ9z"


def test_auto_result_identical_to_choosing_the_subtopic_by_hand():
    """No spies: the real detector gives the same verdict whether the subtopic was chosen or detected."""
    def strip(r):
        return {k: v for k, v in r.items() if k != "indicators"} | {
            "indicators": [{k: v for k, v in i.items() if k != "id"} for i in r["indicators"]]}
    cases = [("credential", "failed-logins", {"text_input": SSH_LOG}),
             ("impersonation", "government-impersonation", {"text_input": _sample("attack_cbi_digital_arrest.eml")}),
             ("cyber-threat", "network-traffic",
              {"text_input": "Oct 10 12:00:01 fw01 kernel: DROP SRC=45.9.1.2 DST=10.0.0.5 PROTO=TCP DPT=22"})]
    for module, sub, kw in cases:
        base = dict(text_input=None, url_input=None, file_path=None, file_name=None, extra_field_values={}) | kw
        auto, c = sr.route(module_id=module, **base)
        assert c.subtopic_id == sub
        manual = analysis_service.run_scan(module_id=module, subtopic_id=sub, subtopic_title=c.subtopic_title, **base)
        assert strip(auto) == strip(manual)


# ---------------------------------------------------------------------------
# 3. Ambiguous, unsupported and missing-detector inputs call NO detector
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("module,kwargs,code", [
    ("phishing", {"text": "   "}, "undetermined"),
    ("credential", {"text": "Hello, how are you today?"}, "undetermined"),
    ("cyber-threat", {"text": "My colleague is behaving strangely"}, "undetermined"),
    ("url-security", {"text": "this is not a url at all"}, "undetermined"),
    ("deepfake", {"text": "is this video fake?"}, "undetermined"),
    ("impersonation", {"text": ""}, "undetermined"),
    ("nonsense-module", {"text": "x"}, "unsupported"),
])
def test_unclear_inputs_call_no_detector(spies, module, kwargs, code):
    with pytest.raises(RoutingError) as e:
        route(module, **kwargs)
    assert e.value.code == code
    assert called(spies) == []


def test_missing_detectors_are_reported_not_faked(spies, tmp_path):
    wav = tmp_path / "voice.wav"
    wav.write_bytes(b"RIFF\x24\x00\x00\x00WAVEfmt " + b"\x00" * 24)
    with pytest.raises(RoutingError) as e:
        route("deepfake", fp=str(wav), fn="voice.wav")
    assert e.value.code == "unavailable" and e.value.details["subtopicId"] == "audio-analysis"

    exe = tmp_path / "setup.exe"
    exe.write_bytes(b"MZ\x90\x00" + b"\x00" * 60)
    with pytest.raises(RoutingError) as e:
        route("cyber-threat", fp=str(exe), fn="setup.exe")
    assert e.value.code == "unavailable"

    pdf = tmp_path / "doc.pdf"
    pdf.write_bytes(b"%PDF-1.7\n" + b"\x00" * 40)
    with pytest.raises(RoutingError) as e:
        route("phishing", fp=str(pdf), fn="doc.pdf")
    assert e.value.code == "unsupported"
    assert called(spies) == []


# ---------------------------------------------------------------------------
# 4. API: subtopicId="auto"
# ---------------------------------------------------------------------------
def test_api_auto_routes_and_reports_routing(auth_client):
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "credential", "subtopicId": "auto", "subtopicTitle": "Auto-detect", "textInput": SSH_LOG})
    assert r.status_code == 200
    body = r.json()
    assert body["subtopicId"] == "failed-logins"
    assert body["subtopicTitle"] == "Multiple Failed Login Attempts"
    assert body["routing"]["detector"] == "account_takeover.analyze_event" and body["routing"]["mode"] == "auto"
    from app.db.database import SessionLocal
    from app.db.models import Scan
    db = SessionLocal()
    try:
        assert db.get(Scan, body["scanId"]).subtopic_id == "failed-logins"      # saved under the detected subtopic
    finally:
        db.close()


def test_api_auto_undetermined_is_a_controlled_422(auth_client):
    before = len(auth_client.get("/api/scans").json()["items"])
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "cyber-threat", "subtopicId": "auto", "subtopicTitle": "Auto-detect",
        "textInput": "My colleague is behaving strangely"})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "SUBTOPIC_UNDETERMINED"
    assert len(auth_client.get("/api/scans").json()["items"]) == before      # nothing saved


def test_api_explicit_subtopic_unchanged(auth_client):
    r = auth_client.post("/api/analysis/scan", data={
        "moduleId": "credential", "subtopicId": "password-spraying", "subtopicTitle": "Password Spraying Detection",
        "textInput": SSH_LOG})
    body = r.json()
    assert r.status_code == 200 and body["subtopicId"] == "password-spraying" and body["routing"] is None
