"""Real, reversible quarantine: dangerous Gmail inbox emails move to the "CyberGuard-Quarantine" label and dangerous
downloads move to the quarantine folder. Nothing is ever deleted, every move is logged, and every move can be undone.
Gmail is a fake IMAP server here; nothing real is touched."""
import os

import pytest

from test_automation import SAMPLES, FakeIMAP


@pytest.fixture()
def fresh_state(monkeypatch, tmp_path):
    from app.automation import engine
    monkeypatch.setattr(engine, "STATE_FILE", str(tmp_path / "state.json"))
    return tmp_path


@pytest.fixture()
def gmail(monkeypatch, fresh_state, admin_client):
    """Fake Gmail with one dangerous email in the inbox, owned by admin_client's account."""
    import imaplib

    from app.core.config import get_settings
    from app.services import email_ingest
    real = email_ingest.analyze_email
    monkeypatch.setattr(email_ingest, "analyze_email", lambda raw, **kw: real(raw, **{**kw, "network": False}))
    with open(os.path.join(SAMPLES, "attack_sbi_kyc_spoof.eml"), "rb") as f:
        raw = f.read()
    FakeIMAP.mails, FakeIMAP.spam, FakeIMAP.labels, FakeIMAP.log = {41: raw}, {}, {}, []
    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeIMAP)
    s = get_settings()
    monkeypatch.setattr(s, "IMAP_USER", "me@gmail.com")
    monkeypatch.setattr(s, "IMAP_PASSWORD", "abcdefghijklmnop")
    monkeypatch.setattr(s, "EMAIL_BACKFILL", 5)
    monkeypatch.setattr(s, "AUTOMATION_USER_EMAIL", admin_client._test_email)
    return admin_client


def _record(client):
    items = client.get("/api/email/quarantine?status=all").json()["items"]
    return next(i for i in items if "SBI" in (i["subject"] or "") or "KYC" in (i["subject"] or "").upper())


def test_dangerous_inbox_email_moves_to_gmail_quarantine_label_and_release_moves_it_back(gmail):
    from app.automation import email_watcher
    client = gmail
    st = email_watcher.EmailWatcher().run_once()
    assert st["lastError"] is None and st["threats"] == 1
    label = FakeIMAP.labels.get("CyberGuard-Quarantine", {})
    assert 41 not in FakeIMAP.mails and len(label) == 1                     # out of the inbox, NOT deleted
    assert ("select", '"INBOX"', True) in FakeIMAP.log                       # the reading stays read-only
    rec = _record(client)
    assert rec["status"] == "quarantined" and rec["mailbox"] == {"status": "moved", "label": "CyberGuard-Quarantine"}
    assert any(h["action"] == "mailbox-quarantined" for h in rec["history"])
    audit = client.get("/api/audit").json()
    rows = audit["items"] if isinstance(audit, dict) else audit
    assert any(r["action"] == "quarantine.mailbox" for r in rows)

    r = client.post(f"/api/email/records/{rec['id']}/action", json={"action": "release", "note": "it was fine"})
    assert r.status_code == 200 and r.json()["status"] == "released"
    assert len(FakeIMAP.mails) == 1 and not FakeIMAP.labels["CyberGuard-Quarantine"]   # back in the inbox
    assert any(h["action"] == "mailbox-released" for h in r.json()["history"])

    st = email_watcher.EmailWatcher().run_once()                          # comes back with a NEW uid ...
    assert len(FakeIMAP.mails) == 1 and not FakeIMAP.labels["CyberGuard-Quarantine"]   # ... and is NOT re-quarantined

    r = client.post(f"/api/email/records/{rec['id']}/action", json={"action": "quarantine"})
    assert r.status_code == 200 and not FakeIMAP.mails and len(FakeIMAP.labels["CyberGuard-Quarantine"]) == 1


def test_delete_action_never_deletes_from_gmail(gmail):
    from app.automation import email_watcher
    email_watcher.EmailWatcher().run_once()
    rec = _record(gmail)
    r = gmail.post(f"/api/email/records/{rec['id']}/action", json={"action": "delete"})
    assert r.status_code == 200 and r.json()["status"] == "deleted"
    assert len(FakeIMAP.labels["CyberGuard-Quarantine"]) == 1               # still held in Gmail
    assert not any(e[:2] == ("uid", "STORE") or e[0] == "expunge" for e in FakeIMAP.log)


def test_mailbox_quarantine_can_be_switched_off(gmail, monkeypatch):
    from app.automation import email_watcher
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "MAILBOX_QUARANTINE", False)
    st = email_watcher.EmailWatcher().run_once()
    assert st["threats"] == 1 and 41 in FakeIMAP.mails and not FakeIMAP.labels   # Gmail untouched
    assert not any(e[:2] == ("uid", "MOVE") for e in FakeIMAP.log)


def test_spam_folder_emails_are_not_moved(gmail):
    from app.automation import email_watcher
    FakeIMAP.spam, FakeIMAP.mails = dict(FakeIMAP.mails), {}
    st = email_watcher.EmailWatcher().run_once()
    assert st["threats"] == 1 and len(FakeIMAP.spam) == 1 and not FakeIMAP.labels.get("CyberGuard-Quarantine")


def test_a_failed_gmail_move_is_recorded_and_never_breaks_the_scan(gmail, monkeypatch):
    from app.automation import email_watcher

    def refuse(self, cmd, *args):
        if cmd == "MOVE":
            return "NO", [b"[CANNOT] simulated failure"]
        return real_uid(self, cmd, *args)
    real_uid = FakeIMAP.uid
    monkeypatch.setattr(FakeIMAP, "uid", refuse)
    st = email_watcher.EmailWatcher().run_once()
    assert st["lastError"] is None and st["threats"] == 1 and 41 in FakeIMAP.mails
    rec = _record(gmail)
    assert rec["status"] == "quarantined" and rec["mailbox"]["status"] == "move-failed"
    assert any(h["action"] == "mailbox-quarantine-failed" for h in rec["history"])


# ---- Downloads ------------------------------------------------------------------------------------
def _watch(monkeypatch, fresh_state, name="dl"):
    from app.automation import downloads_watcher
    from app.core.config import get_settings
    folder = fresh_state / name
    folder.mkdir()
    monkeypatch.setattr(get_settings(), "DOWNLOADS_DIR", str(folder))
    w = downloads_watcher.DownloadsWatcher()
    w.run_once()                                                           # baseline
    return folder, w


def _settle(w):
    w.run_once()                                                           # size seen
    return w.run_once()                                                    # size stable -> scanned


def test_dangerous_download_is_moved_and_restore_puts_it_back(monkeypatch, fresh_state, admin_client):
    from app.automation import file_quarantine
    folder, w = _watch(monkeypatch, fresh_state)
    bad = folder / "Salary_Slip.pdf.exe"
    bad.write_bytes(b"MZ" + b"\x90" * 700)
    st = _settle(w)
    assert st["threats"] == 1 and not bad.exists()
    held = [h for h in file_quarantine.list_files() if h["name"] == bad.name]
    assert len(held) == 1 and held[0]["originalPath"] == str(bad.resolve()) and held[0]["score"] >= 71

    listing = admin_client.get("/api/quarantine/files").json()
    assert listing["enabled"] is True and any(i["id"] == held[0]["id"] for i in listing["items"])
    r = admin_client.post(f"/api/quarantine/files/{held[0]['id']}/restore")
    assert r.status_code == 200 and r.json()["status"] == "restored" and bad.exists()
    assert bad.read_bytes() == b"MZ" + b"\x90" * 700
    st = _settle(w)                                                        # the restored file is not re-quarantined
    assert bad.exists()
    assert admin_client.post(f"/api/quarantine/files/{held[0]['id']}/restore").status_code == 409   # only once
    rows = admin_client.get("/api/audit").json()
    rows = rows["items"] if isinstance(rows, dict) else rows
    assert "quarantine.file_restore" in {r["action"] for r in rows}


def test_restore_never_overwrites_a_file_with_the_same_name(monkeypatch, fresh_state, admin_client):
    from app.automation import file_quarantine
    folder, w = _watch(monkeypatch, fresh_state, "dl_same")
    bad = folder / "update.exe.pdf.exe"
    bad.write_bytes(b"MZ" + b"\x01" * 300)
    _settle(w)
    assert not bad.exists()
    bad.write_bytes(b"a different file the user saved later")
    qid = next(h["id"] for h in file_quarantine.list_files() if h["name"] == bad.name)
    out = admin_client.post(f"/api/quarantine/files/{qid}/restore").json()
    assert bad.read_bytes() == b"a different file the user saved later"   # untouched
    assert out["restoredTo"].endswith("(restored).exe") and os.path.exists(out["restoredTo"])


def test_harmless_download_and_switched_off_quarantine_leave_files_in_place(monkeypatch, fresh_state, auth_client):
    from app.core.config import get_settings
    folder, w = _watch(monkeypatch, fresh_state, "dl_ok")
    ok = folder / "notes.txt"
    ok.write_text("lecture notes")
    _settle(w)
    assert ok.exists()
    monkeypatch.setattr(get_settings(), "FILE_QUARANTINE", False)
    bad = folder / "game_crack.pdf.exe"
    bad.write_bytes(b"MZ" + b"\x02" * 300)
    st = _settle(w)
    assert st["threats"] >= 1 and bad.exists()


def test_quarantine_api_rejects_non_admin_and_path_tricks(client):
    import uuid

    from helpers import register_user
    email = f"plain_{uuid.uuid4().hex[:8]}@example.com"
    assert register_user(client, {"name": "Plain", "email": email, "password": "TestPass123"}).status_code == 201
    assert client.get("/api/quarantine/files").status_code == 403
    assert client.post("/api/quarantine/files/abc/restore").status_code == 403


def test_restore_rejects_ids_that_are_not_quarantine_ids(admin_client):
    for bad in ("..%2F..%2Fetc%2Fpasswd", "0" * 31, "Z" * 32, "../" + "a" * 32):
        r = admin_client.post(f"/api/quarantine/files/{bad}/restore")
        assert r.status_code in (404, 405), (bad, r.status_code)


def test_file_changed_after_scan_is_left_in_place(fresh_state):
    from app.automation import file_quarantine
    f = fresh_state / "x.exe"
    f.write_bytes(b"MZ new content")
    with pytest.raises(file_quarantine.QuarantineError):
        file_quarantine.quarantine_file(f, sha256="0" * 64, score=90, reason="test", scan_id=None)
    assert f.exists()
