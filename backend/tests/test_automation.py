"""Automatic protection: the four watchers (Gmail, CyberGuard sign-ins, Windows logons, Downloads) and their API."""
import os
import uuid

import pytest

from helpers import login_user, register_user


def _labels(source):
    """Triggered indicator labels of every scan saved by this automatic source."""
    from app.db.database import SessionLocal
    from app.db.models import DetectedIndicatorRow, ThreatEvent
    db = SessionLocal()
    try:
        ids = {(e.event_metadata or {}).get("scanId")
               for e in db.query(ThreatEvent).filter(ThreatEvent.source == f"automation:{source}").all()}
        rows = db.query(DetectedIndicatorRow).filter(DetectedIndicatorRow.scan_id.in_(ids)).all()
        return {r.label for r in rows if r.triggered}
    finally:
        db.close()


@pytest.fixture()
def fresh_state(monkeypatch, tmp_path):
    from app.automation import engine
    monkeypatch.setattr(engine, "STATE_FILE", str(tmp_path / "state.json"))
    return tmp_path


# ---- API ---------------------------------------------------------------------------------------
def test_status_lists_four_watchers_and_toggle_persists(admin_client, fresh_state):
    auth_client = admin_client
    r = auth_client.get("/api/automation/status")
    assert r.status_code == 200
    names = {w["name"] for w in r.json()["watchers"]}
    assert names == {"email", "logins", "windows", "downloads"}
    w = auth_client.post("/api/automation/downloads/toggle", json={"enabled": False}).json()
    assert w["enabled"] is False and w["state"] == "off"
    assert auth_client.post("/api/automation/downloads/toggle", json={"enabled": True}).json()["enabled"] is True
    assert auth_client.post("/api/automation/nope/run").status_code == 404


def test_status_needs_login(client):
    assert client.get("/api/automation/status").status_code == 401


def test_a_failing_watcher_reports_the_error_instead_of_crashing(fresh_state):
    from app.automation.engine import Watcher

    class Boom(Watcher):
        name = "boom"

        def check(self):
            raise RuntimeError("Gmail refused the login")
    st = Boom().run_once()
    assert "Gmail refused" in st["lastError"]


# ---- CyberGuard's own sign-ins -------------------------------------------------------------------
def test_password_spraying_against_cyberguard_is_detected(client, fresh_state):
    from app.automation.login_monitor import LoginMonitor
    real = []
    for _ in range(2):
        email = f"victim_{uuid.uuid4().hex[:6]}@example.com"
        assert register_user(client, {"name": "V", "email": email, "password": "RightPass123"}).status_code == 201
        real.append(email)
    client.post("/api/auth/logout")
    targets = real + [f"ghost{i}_{uuid.uuid4().hex[:4]}@example.com" for i in range(4)]
    for email in targets:
        assert client.post("/api/auth/login", json={"email": email, "password": "Summer2026!"}).status_code == 401
    out = LoginMonitor().run_once()
    assert out["lastError"] is None and out["threats"] >= 1
    assert "Password spraying" in _labels("logins")
    again = LoginMonitor().run_once()                     # nothing new -> no duplicate finding
    assert again["threats"] == 0


def test_wrong_otp_codes_are_recorded_as_failed_sign_ins(client, fresh_state):
    from app.db.database import SessionLocal
    from app.db.models import LoginEvent
    email = f"otp_{uuid.uuid4().hex[:6]}@example.com"
    register_user(client, {"name": "O", "email": email, "password": "RightPass123"})
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"email": email, "password": "RightPass123"})
    bad = "000000" if r.json()["devOtp"] != "000000" else "111111"
    client.post("/api/auth/login/verify", json={"challengeId": r.json()["challengeId"], "code": bad})
    assert login_user(client, email, "RightPass123").status_code == 200
    db = SessionLocal()
    try:
        rows = db.query(LoginEvent).filter(LoginEvent.email == email).all()
        assert {(r.stage, r.success) for r in rows} >= {("otp", False), ("otp", True)}
    finally:
        db.close()


# ---- Gmail inbox (fake IMAP server) -----------------------------------------------------------
SAMPLES = os.path.join(os.path.dirname(__file__), "email_samples")


class FakeIMAP:
    mails = {}          # the inbox
    spam = {}           # Gmail's Spam folder
    log = []

    def __init__(self, host, port, timeout=None):
        FakeIMAP.log.append(("connect", host, port))
        self.box = {}

    def login(self, user, pw):
        FakeIMAP.log.append(("login", user, pw))

    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"', b'(\\HasNoChildren \\Junk) "/" "[Gmail]/Spam"']

    def select(self, folder, readonly=False):
        FakeIMAP.log.append(("select", folder, readonly))
        self.box = FakeIMAP.spam if "Spam" in folder else FakeIMAP.mails
        return "OK", [b"2"]

    def response(self, name):
        return name, [b"777"]

    def uid(self, cmd, *args):
        FakeIMAP.log.append(("uid", cmd) + args)
        if cmd == "search":
            crit = args[-1]
            lo = int(crit.split()[1].split(":")[0]) if crit.startswith("UID") else 1
            hits = [u for u in sorted(self.box) if u >= lo] or ([max(self.box)] if self.box else [])
            return "OK", [b" ".join(str(u).encode() for u in hits)]
        return "OK", [(b"1 (BODY[] {n}", self.box[int(args[0])]), b")"]

    def logout(self):
        pass


def test_gmail_watcher_reads_new_mail_read_only_and_only_once(monkeypatch, fresh_state, auth_client):
    import imaplib

    from app.automation import email_watcher
    from app.core.config import get_settings
    from app.services import email_ingest
    real = email_ingest.analyze_email
    monkeypatch.setattr(email_ingest, "analyze_email", lambda raw, **kw: real(raw, **{**kw, "network": False}))
    with open(os.path.join(SAMPLES, "attack_sbi_kyc_spoof.eml"), "rb") as f:
        FakeIMAP.mails = {41: f.read()}
    FakeIMAP.spam = {}
    FakeIMAP.log = []
    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeIMAP)
    s = get_settings()
    monkeypatch.setattr(s, "IMAP_USER", "me@gmail.com")
    monkeypatch.setattr(s, "IMAP_PASSWORD", "abcd efgh ijkl mnop")
    monkeypatch.setattr(s, "EMAIL_BACKFILL", 5)
    w = email_watcher.EmailWatcher()
    st = w.run_once()
    assert st["lastError"] is None and st["checked"] == 1 and st["threats"] == 1
    recent = st["recent"][0]                                                      # shown in Settings: which email
    assert recent["item"].startswith('"') and " from " in recent["item"] and recent["score"] > 25
    assert ("login", "me@gmail.com", "abcdefghijklmnop") in FakeIMAP.log          # spaces removed
    assert ("select", '"INBOX"', True) in FakeIMAP.log                           # read-only
    fetches = [e for e in FakeIMAP.log if e[:2] == ("uid", "fetch")]
    assert fetches and all(e[3] == "(BODY.PEEK[])" for e in fetches)            # never marks as read
    assert w.run_once()["checked"] == 1                                           # nothing new the 2nd time


def test_gmail_watcher_also_checks_spam_folder(monkeypatch, fresh_state, auth_client):
    """Gmail files many phishing emails under Spam; they must be checked too (read-only), each folder once."""
    import imaplib

    from app.automation import email_watcher
    from app.core.config import get_settings
    from app.services import email_ingest
    real = email_ingest.analyze_email
    monkeypatch.setattr(email_ingest, "analyze_email", lambda raw, **kw: real(raw, **{**kw, "network": False}))
    with open(os.path.join(SAMPLES, "attack_sbi_kyc_spoof.eml"), "rb") as f:
        phish = f.read()
    FakeIMAP.mails, FakeIMAP.spam, FakeIMAP.log = {}, {9: phish}, []
    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeIMAP)
    s = get_settings()
    monkeypatch.setattr(s, "IMAP_USER", "me@gmail.com")
    monkeypatch.setattr(s, "IMAP_PASSWORD", "abcdefghijklmnop")
    monkeypatch.setattr(s, "EMAIL_BACKFILL", 5)
    w = email_watcher.EmailWatcher()
    st = w.run_once()
    assert st["lastError"] is None and st["checked"] == 1 and st["threats"] == 1
    assert st["recent"][0]["item"].endswith("[Spam]")                              # user sees where it was
    assert ("select", '"[Gmail]/Spam"', True) in FakeIMAP.log                     # read-only
    fetches = [e for e in FakeIMAP.log if e[:2] == ("uid", "fetch")]
    assert fetches and all(e[3] == "(BODY.PEEK[])" for e in fetches)
    assert w.run_once()["checked"] == 1                                           # not checked twice

    monkeypatch.setattr(s, "IMAP_SPAM_FOLDER", "off")                             # can be switched off
    FakeIMAP.log = []
    w.run_once()
    assert not any(e[0] == "select" and "Spam" in e[1] for e in FakeIMAP.log)


def test_gmail_watcher_skips_cyberguards_own_alert_emails(monkeypatch, fresh_state, auth_client):
    """An alert email lands in the watched inbox; scanning it would raise another alert, forever."""
    import imaplib
    from email.message import EmailMessage

    from app.automation import email_watcher
    from app.core.config import get_settings
    from app.services import email_ingest, notifier
    s = get_settings()
    monkeypatch.setattr(s, "SMTP_USER", "me@gmail.com")
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "me@gmail.com", "me@gmail.com", "[CYBERGUARD CRITICAL] Bank impersonation - risk 100"
    m["Message-ID"] = "<alert-1@gmail.com>"
    m[notifier.OWN_MAIL_ID_HEADER] = "a1b2c3"
    m[notifier.OWN_MAIL_HEADER] = notifier.own_mail_signature("a1b2c3")
    m.set_content("URGENT: Your SBI account is suspended - verify KYC now http://sbi-kyc-verify-login.xyz/update "
                  "Enter your account number, ATM PIN and OTP")
    real = email_ingest.analyze_email
    monkeypatch.setattr(email_ingest, "analyze_email", lambda raw, **kw: real(raw, **{**kw, "network": False}))
    with open(os.path.join(SAMPLES, "attack_sbi_kyc_spoof.eml"), "rb") as f:
        FakeIMAP.mails, FakeIMAP.spam, FakeIMAP.log = {50: m.as_bytes(), 51: f.read()}, {}, []
    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeIMAP)
    monkeypatch.setattr(s, "IMAP_USER", "me@gmail.com")
    monkeypatch.setattr(s, "IMAP_PASSWORD", "abcdefghijklmnop")
    monkeypatch.setattr(s, "EMAIL_BACKFILL", 5)
    sent = []
    monkeypatch.setattr(notifier, "alert_for_scan", lambda scan_id: sent.append(scan_id))
    st = email_watcher.EmailWatcher().run_once()
    assert st["lastError"] is None and st["checked"] == 1                      # only the real phishing email
    assert len(sent) == 1 and "CYBERGUARD" not in st["recent"][0]["item"]


def test_gmail_watcher_needs_setup_without_password(monkeypatch, fresh_state):
    from app.automation import email_watcher
    from app.core.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "IMAP_USER", "")
    monkeypatch.setattr(s, "SMTP_USER", "")
    d = email_watcher.EmailWatcher().describe()
    assert d["configured"] is False and "App Password" in d["setupHint"]


# ---- Downloads folder ------------------------------------------------------------------------
def test_downloads_watcher_checks_only_new_finished_files_and_never_deletes(monkeypatch, fresh_state, auth_client):
    from app.automation import downloads_watcher
    from app.core.config import get_settings
    folder = fresh_state / "Downloads"
    folder.mkdir()
    (folder / "old_setup.exe").write_bytes(b"MZ" + b"\x00" * 200)            # was there before: left alone
    monkeypatch.setattr(get_settings(), "DOWNLOADS_DIR", str(folder))
    w = downloads_watcher.DownloadsWatcher()
    assert w.run_once()["checked"] == 0                                          # first round = baseline
    bad = folder / "Invoice_2026.pdf.exe"
    bad.write_bytes(b"MZ" + b"\x90" * 500)
    (folder / "movie.mp4.crdownload").write_bytes(b"partial")                    # still downloading: ignored
    assert w.run_once()["checked"] == 0                                          # waits one round (size stable?)
    st = w.run_once()
    assert st["checked"] == 1 and st["threats"] == 1 and "Invoice_2026.pdf.exe" in st["lastFinding"]
    assert bad.exists() and (folder / "old_setup.exe").exists()                  # nothing deleted or moved
    assert w.run_once()["checked"] == 1                                          # total unchanged: not scanned twice


def test_harmless_download_is_not_reported(monkeypatch, fresh_state, auth_client):
    from app.automation import downloads_watcher
    from app.core.config import get_settings
    folder = fresh_state / "dl2"
    folder.mkdir()
    monkeypatch.setattr(get_settings(), "DOWNLOADS_DIR", str(folder))
    w = downloads_watcher.DownloadsWatcher()
    w.run_once()
    (folder / "notes.txt").write_text("lecture notes")
    w.run_once()
    st = w.run_once()
    assert st["checked"] == 1 and st["threats"] == 0


# ---- Windows sign-in events (parser + analysis; wevtutil itself only exists on Windows) ----------
def _event(eid, rec, minute, user, ip, logon_type="3", sub="0xc000006a"):
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="2026-10-12T02:{minute:02d}:00.000Z"/><EventRecordID>{rec}</EventRecordID>'
            f'</System><EventData><Data Name="TargetUserName">{user}</Data><Data Name="IpAddress">{ip}</Data>'
            f'<Data Name="LogonType">{logon_type}</Data><Data Name="SubStatus">{sub}</Data></EventData></Event>')


def test_windows_events_brute_force_then_success_is_saved_once(fresh_state, auth_client):
    from app.automation import windows_logons
    from app.detectors import account_takeover
    xml = "".join(_event(4625, 100 + i, 10 + i, "ashis", "45.155.205.10") for i in range(8))
    xml += _event(4624, 120, 20, "ashis", "45.155.205.10", logon_type="10")
    xml += _event(4624, 121, 21, "SYSTEM", "-", logon_type="5")                 # service noise: ignored
    events = windows_logons.parse_events(xml)
    lines = windows_logons.to_log_lines(events)
    assert len(lines) == 9 and not any("SYSTEM" in ln for ln in lines)
    w = windows_logons.WindowsLogonWatcher()
    out = w.analyse(events, account_takeover)
    assert out["threats"] == 1 and "score" in out["finding"]
    assert w.analyse(events, account_takeover)["checked"] == 0                   # same events: nothing new
