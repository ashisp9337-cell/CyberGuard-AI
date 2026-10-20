"""Automatic alerts to the admin / SOC (Telegram, email, WhatsApp). All channels are faked, nothing real is sent."""
import pytest

from app.core.config import get_settings
from app.services import notifier

BRUTE_FORCE_LOG = "\n".join(
    ["Oct  7 03:12:0%d srv sshd[1]: Failed password for root from 185.220.101.4 port 44%d ssh2" % (i, i) for i in range(6)]
    + ["Oct  7 03:12:09 srv sshd[1]: Accepted password for root from 185.220.101.4"])


class FakeTelegram:
    def __init__(self):
        self.sent = []

    def post(self, url, json=None, timeout=None):
        self.sent.append(json)

        class R:
            ok = True
            status_code = 200
            text = "ok"

            @staticmethod
            def json():
                return {"ok": True}
        return R()


@pytest.fixture()
def telegram(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "TELEGRAM_BOT_TOKEN", "123:fake")
    monkeypatch.setattr(s, "TELEGRAM_CHAT_ID", "999")
    fake = FakeTelegram()
    monkeypatch.setattr(notifier.requests, "post", fake.post)
    return fake


def _scan(client, log=BRUTE_FORCE_LOG):
    return client.post("/api/analysis/scan", data={
        "moduleId": "credential", "subtopicId": "failed-logins", "subtopicTitle": "Failed Logins",
        "textInput": log, "extraFieldValues": '{"failedAttempts": "7", "newDevice": "true"}',
    }).json()


def _alerts_on_event(client, scan_id):
    from app.db.database import SessionLocal
    from app.db.models import ThreatEvent
    db = SessionLocal()
    try:
        for e in db.query(ThreatEvent).all():
            if (e.event_metadata or {}).get("scanId") == scan_id:
                return e.event_metadata.get("alerts", [])
    finally:
        db.close()
    return None


def test_message_contains_level_evidence_and_actions():
    msg = notifier.build_alert({
        "id": "SCN1", "threatType": "Account Takeover", "classification": "critical", "severity": "critical",
        "riskScore": 92, "target": "root@server", "explanation": "Brute force succeeded.",
        "indicators": [{"label": "Successful login after repeated failures", "triggered": True, "weight": 40,
                        "mitre": "T1110"}],
        "responseActions": [{"title": "Block IP 185.220.101.4", "priority": "immediate"}],
    })
    assert "CRITICAL" in msg["subject"] and "92" in msg["subject"]
    for part in ("Successful login after repeated failures", "Block IP 185.220.101.4", "T1110", "SCN1"):
        assert part in msg["text"]
    assert "<b>" in msg["html"]


def test_high_risk_scan_sends_telegram_alert(auth_client, telegram):
    body = _scan(auth_client)
    assert body["riskScore"] >= get_settings().ALERT_MIN_SCORE
    assert len(telegram.sent) == 1
    assert telegram.sent[0]["chat_id"] == "999"
    assert "185.220.101.4" in telegram.sent[0]["text"]
    alerts = _alerts_on_event(auth_client, body["scanId"])
    assert any(a["channel"] == "telegram" and a["status"] == "sent" for a in alerts)
    assert any(a["channel"] == "email" and a["status"] == "not_configured" for a in alerts)


def test_same_threat_twice_is_alerted_once(auth_client, telegram):
    _scan(auth_client)
    second = _scan(auth_client)
    assert len(telegram.sent) == 1
    alerts = _alerts_on_event(auth_client, second["scanId"])
    assert alerts and alerts[0]["status"] == "suppressed_duplicate"


def test_safe_scan_sends_nothing(auth_client, telegram):
    auth_client.post("/api/analysis/scan", data={
        "moduleId": "phishing", "subtopicId": "sms-analysis", "subtopicTitle": "SMS",
        "textInput": "Hi, are we still meeting for lunch at 1 tomorrow?"})
    assert telegram.sent == []


def test_user_who_turned_alerts_off_gets_none(auth_client, telegram):
    assert auth_client.put("/api/settings", json={"notificationsEnabled": False}).status_code == 200
    _scan(auth_client)
    assert telegram.sent == []


def test_status_and_test_endpoint_without_config(admin_client):
    auth_client = admin_client
    st = auth_client.get("/api/alerts/status").json()
    assert st == {"telegram": False, "email": False, "whatsapp": False, "whatsappProvider": "callmebot",
                  "minScore": get_settings().ALERT_MIN_SCORE, "dedupMinutes": get_settings().ALERT_DEDUP_MINUTES}
    res = auth_client.post("/api/alerts/test").json()
    assert {r["status"] for r in res["results"]} == {"not_configured"}


# ---------------------------------------------------------------------------
# Email and WhatsApp (fake SMTP server / fake HTTP, nothing real is sent)
# ---------------------------------------------------------------------------
class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.calls, self.sent = host, port, [], []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def send_message(self, msg, to_addrs=None):
        self.sent.append((msg, to_addrs))


@pytest.fixture()
def smtp(monkeypatch):
    s = get_settings()
    for k, v in {"SMTP_HOST": "smtp.gmail.com", "SMTP_PORT": 587, "SMTP_USER": "me@gmail.com",
                 "SMTP_PASSWORD": "abcd efgh ijkl mnop", "ALERT_EMAIL_TO": "soc@example.com, admin@example.com"}.items():
        monkeypatch.setattr(s, k, v)
    FakeSMTP.instances = []
    monkeypatch.setattr(notifier.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(notifier.smtplib, "SMTP_SSL", FakeSMTP)
    return FakeSMTP


def test_email_alert_is_html_goes_to_every_address_and_strips_app_password_spaces(smtp):
    res = notifier.send_email(notifier.build_alert({"id": "S1", "threatType": "Phishing", "classification": "critical",
                                                    "severity": "critical", "riskScore": 92, "target": "x.top"}))
    assert res["status"] == "sent"
    server = smtp.instances[0]
    assert "starttls" in server.calls and ("login", "me@gmail.com", "abcdefghijklmnop") in server.calls
    msg, to = server.sent[0]
    assert to == ["soc@example.com", "admin@example.com"]
    assert "CRITICAL" in msg["Subject"]
    assert msg.get_body(("html",)) is not None and msg.get_body(("plain",)) is not None


def test_cyberguard_emails_are_signed_and_recognised_so_alerts_never_loop(smtp):
    """Alerts go to the inbox the watcher reads; the watcher must recognise them and skip them."""
    notifier.send_email(notifier.build_alert({"id": "S1", "threatType": "Bank / financial institution impersonation",
                                              "classification": "critical", "severity": "critical", "riskScore": 100,
                                              "target": "URGENT: Your SBI account is suspended - verify KYC now"}))
    msg, _ = smtp.instances[0].sent[0]
    raw = msg.as_bytes()
    assert msg[notifier.OWN_MAIL_HEADER] and notifier.is_own_mail(raw)

    forged = raw.replace(msg[notifier.OWN_MAIL_HEADER].encode(), b"0" * 40)          # attacker guesses a signature
    assert not notifier.is_own_mail(forged)
    other = (b"From: SBI <alerts@sbi-kyc-verify-login.xyz>\r\nSubject: URGENT: verify KYC\r\n"
             b"Message-ID: <1@x>\r\n" + notifier.OWN_MAIL_HEADER.encode() + b": abc\r\n\r\nhi")
    assert not notifier.is_own_mail(other)                                           # normal mail is scanned


def test_old_unsigned_alert_from_own_address_is_recognised_but_spoofed_one_is_not(smtp):
    old = b"From: me@gmail.com\r\nSubject: [CYBERGUARD CRITICAL] Phishing email - risk 90\r\n\r\nbody"
    assert notifier.is_own_mail(old)
    spoof = (b"Authentication-Results: mx.google.com; dmarc=fail header.from=gmail.com\r\n" + old)
    assert not notifier.is_own_mail(spoof)
    stranger = old.replace(b"me@gmail.com", b"attacker@gmail.com")
    assert not notifier.is_own_mail(stranger)


def test_alert_duplicates_are_blocked_for_a_day_by_default():
    assert get_settings().ALERT_DEDUP_MINUTES >= 1440


def test_email_port_465_uses_ssl_without_starttls(smtp, monkeypatch):
    monkeypatch.setattr(get_settings(), "SMTP_PORT", 465)
    assert notifier.send_email(notifier.build_alert({"riskScore": 80}))["status"] == "sent"
    assert "starttls" not in smtp.instances[0].calls


def test_email_switched_off_in_settings_is_not_sent(auth_client, telegram, smtp):
    assert auth_client.put("/api/settings", json={"emailNotifications": False}).status_code == 200
    scan = _scan(auth_client)
    alerts = _alerts_on_event(auth_client, scan["scanId"])
    assert any(a["channel"] == "email" and a["status"] == "disabled_by_user" for a in alerts)
    assert smtp.instances == []
    assert len(telegram.sent) == 1   # other channels still work


class FakeHTTP:
    def __init__(self, status=200, text="Message queued. You will receive it in a few seconds."):
        self.status, self.text, self.calls = status, text, []

    def _resp(self):
        class R:
            status_code, text = self.status, self.text
        return R()

    def get(self, url, params=None, timeout=None):
        self.calls.append(("GET", url, params))
        return self._resp()

    def post(self, url, data=None, auth=None, timeout=None, json=None):
        self.calls.append(("POST", url, data, auth))
        return self._resp()


def test_whatsapp_callmebot_sends_to_own_number(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "WHATSAPP_PROVIDER", "callmebot")
    monkeypatch.setattr(s, "WHATSAPP_TO", "+91 98765 43210")
    monkeypatch.setattr(s, "CALLMEBOT_APIKEY", "123456")
    http = FakeHTTP()
    monkeypatch.setattr(notifier.requests, "get", http.get)
    msg = notifier.build_alert({"id": "S2", "threatType": "SMS phishing", "classification": "high_risk",
                                "severity": "high", "riskScore": 81, "target": "indiapost-fee.top"})
    assert notifier.send_whatsapp(msg)["status"] == "sent"
    method, url, params = http.calls[0]
    assert "callmebot" in url and params["phone"] == "919876543210" and params["apikey"] == "123456"
    assert params["text"].startswith("*") and len(params["text"]) <= 1500
    assert notifier.channel_status()["whatsapp"] is True


def test_whatsapp_callmebot_error_page_is_reported_as_failed(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "WHATSAPP_TO", "+919876543210")
    monkeypatch.setattr(s, "CALLMEBOT_APIKEY", "wrong")
    monkeypatch.setattr(notifier.requests, "get", FakeHTTP(text="ERROR: APIKey is invalid").get)
    res = notifier.send_whatsapp(notifier.build_alert({"riskScore": 80}))
    assert res["status"] == "failed" and "APIKey" in res["error"]


def test_whatsapp_twilio(monkeypatch):
    s = get_settings()
    for k, v in {"WHATSAPP_PROVIDER": "twilio", "WHATSAPP_TO": "+919876543210", "TWILIO_ACCOUNT_SID": "AC1",
                 "TWILIO_AUTH_TOKEN": "tok", "TWILIO_WHATSAPP_FROM": "whatsapp:+14155238886"}.items():
        monkeypatch.setattr(s, k, v)
    http = FakeHTTP(status=201)
    monkeypatch.setattr(notifier.requests, "post", http.post)
    assert notifier.send_whatsapp(notifier.build_alert({"riskScore": 80}))["status"] == "sent"
    _, url, data, auth = http.calls[0]
    assert "AC1" in url and data["To"] == "whatsapp:+919876543210" and auth == ("AC1", "tok")


def test_test_alert_endpoint_reports_all_three_channels(admin_client):
    auth_client = admin_client
    res = auth_client.post("/api/alerts/test").json()
    assert {r["channel"] for r in res["results"]} == {"telegram", "email", "whatsapp"}


# ---- Settings -> Alert sensitivity really decides which scans alert -----------------------------
def _scan_with_score(client, score):
    import uuid as _uuid

    from app.db.database import SessionLocal
    from app.db.models import User
    from app.services import scan_store
    from app.services.risk_scoring import classify_risk as classify
    db = SessionLocal()
    try:
        uid = db.query(User).filter(User.email == client._test_email).first().id
        cls = classify(score)
        scan = scan_store.save_result(db, user_id=uid, module_id="url-security", subtopic_id="general",
                                      subtopic_title="URL", target=f"http://x-{_uuid.uuid4().hex[:6]}.example/",
                                      target_type="url", result={"riskScore": score, "classification": cls,
                                      "severity": "high", "confidenceScore": 90, "analysisEngine": "test",
                                      "threatType": "test", "indicators": [], "recommendations": [],
                                      "explanation": "test"})
        db.commit()
        return scan.id
    finally:
        db.close()


@pytest.mark.parametrize("level,score,expect", [
    ("conservative", 80, False), ("conservative", 90, True),
    ("balanced", 65, False), ("balanced", 75, True),
    ("aggressive", 45, False), ("aggressive", 60, True),
])
def test_alert_sensitivity_decides_which_scans_alert(auth_client, telegram, level, score, expect):
    assert auth_client.put("/api/settings", json={"sensitivity": level}).status_code == 200
    out = notifier.alert_for_scan(_scan_with_score(auth_client, score))
    assert bool(out) is expect and (not expect or any(o["status"] == "sent" for o in out))


def test_unknown_sensitivity_is_refused_and_old_names_are_mapped(auth_client):
    assert auth_client.put("/api/settings", json={"sensitivity": "extreme"}).status_code == 422
    assert auth_client.put("/api/settings", json={"sensitivity": "high"}).json()["sensitivity"] == "aggressive"
