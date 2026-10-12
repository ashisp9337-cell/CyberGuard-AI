"""
Watcher 1 -- Gmail inbox (Modules 1, 2, 3, 5: phishing, impersonation, QR, links, attachments).

Technology: IMAP over SSL (port 993) with Python's built-in imaplib + a Gmail App Password.
Every EMAIL_POLL_SECONDS:
   1. log in to imap.gmail.com and open the inbox READ-ONLY (emails are not even marked as read)
   2. ask for messages newer than the last one we checked (IMAP "UID" = each email's permanent number)
   3. each new email goes through the same Email Intelligence Pipeline as a manual upload:
      sender checks (SPF/DKIM/DMARC), phishing text model, impersonation detectors, every link,
      QR codes, attachments -> saved, auto-quarantined in CyberGuard if dangerous, alert if risky
Nothing in your Gmail is changed, moved or deleted.
"""
import imaplib
import re

from app.automation.engine import Watcher, get_state, owner_user_id, update_state
from app.core.config import get_settings

MAX_PER_ROUND = 20


class EmailWatcher(Watcher):
    name = "email"
    title = "Gmail inbox"
    what = "Every new email in your inbox is checked for phishing, impersonation, dangerous links, QR codes and attachments."
    modules = ["Phishing", "Impersonation", "Malicious URL", "Cyber threat (attachments)"]
    technology = "IMAP over SSL (Python imaplib, read-only) + CyberGuard Email Intelligence Pipeline"

    def __init__(self):
        super().__init__()
        self.interval_seconds = max(30, get_settings().EMAIL_POLL_SECONDS)

    @staticmethod
    def _creds():
        s = get_settings()
        user = (s.IMAP_USER or s.SMTP_USER).strip()
        pw = (s.IMAP_PASSWORD or s.SMTP_PASSWORD).replace(" ", "").strip()   # App Passwords are shown with spaces
        return s.IMAP_HOST, user, pw, s.IMAP_FOLDER

    def configured(self):
        _, user, pw, _ = self._creds()
        if not user or not pw:
            return False, "Add IMAP_USER and IMAP_PASSWORD (a Gmail App Password) to backend/.env, then restart."
        return True, ""

    def _connect(self):
        host, user, pw, folder = self._creds()
        imap = imaplib.IMAP4_SSL(host, 993, timeout=20)
        try:
            imap.login(user, pw)
        except imaplib.IMAP4.error as e:
            imap.logout()
            raise RuntimeError(f"Gmail refused the login ({e}). Use a 16-letter App Password, not your normal password.")
        typ, _ = imap.select(f'"{folder}"', readonly=True)
        if typ != "OK":
            imap.logout()
            raise RuntimeError(f"Could not open the folder '{folder}'.")
        return imap

    def check(self) -> dict:
        from app.db.database import SessionLocal
        from app.services import notifier
        from app.services.email_ingest import process_email

        s = get_settings()
        imap = self._connect()
        try:
            validity = imap.response("UIDVALIDITY")[1][0]
            validity = validity.decode() if isinstance(validity, bytes) else str(validity)
            st = get_state(self.name)
            last = int(st.get("lastUid", 0)) if st.get("uidValidity") == validity else None
            if last is None:                       # first run (or mailbox rebuilt): start from the newest emails
                typ, data = imap.uid("search", None, "ALL")
                uids = [int(u) for u in (data[0] or b"").split()]
                newest = uids[-max(0, s.EMAIL_BACKFILL):] if s.EMAIL_BACKFILL else []
                last = (newest[0] - 1) if newest else (uids[-1] if uids else 0)
                update_state(self.name, uidValidity=validity, lastUid=last)
            typ, data = imap.uid("search", None, f"UID {last + 1}:*")
            uids = sorted(u for u in (int(x) for x in (data[0] or b"").split()) if u > last)[:MAX_PER_ROUND]
            checked = threats = 0
            finding = None
            for uid in uids:
                typ, msg = imap.uid("fetch", str(uid), "(BODY.PEEK[])")      # PEEK = do not mark as read
                raw = next((part[1] for part in msg if isinstance(part, tuple)), None)
                if raw and len(raw) <= s.MAX_UPLOAD_MB * 1024 * 1024:
                    db = SessionLocal()
                    try:
                        owner = owner_user_id(db)
                        if owner:
                            scan, _rec, result = process_email(db, owner, raw, source="gmail")
                            db.commit()
                            checked += 1
                            em = result.get("email", {}) or {}
                            subj = re.sub(r"\s+", " ", em.get("subject", "") or "(no subject)")[:80]
                            self.record(f'"{subj}" from {em.get("from_address") or "unknown sender"}',
                                        result["riskScore"], result["classification"])
                            if result["classification"] != "safe":
                                threats += 1
                                finding = f"{result.get('category', 'Threat')}: \"{subj}\" (score {result['riskScore']})"
                            if result["riskScore"] >= s.ALERT_MIN_SCORE:
                                notifier.alert_for_scan(scan.id)
                    finally:
                        db.close()
                update_state(self.name, uidValidity=validity, lastUid=uid)      # bookmark after each email
            return {"checked": checked, "threats": threats, "finding": finding,
                    "note": f"{checked} new email(s) checked" if uids else "No new emails"}
        finally:
            try:
                imap.logout()
            except Exception:
                pass
