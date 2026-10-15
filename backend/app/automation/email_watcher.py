"""
Watcher 1 -- Gmail inbox (Modules 1, 2, 3, 5: phishing, impersonation, QR, links, attachments).

Technology: IMAP over SSL (port 993) with Python's built-in imaplib + a Gmail App Password.
Every EMAIL_POLL_SECONDS:
   1. log in to imap.gmail.com and open the inbox READ-ONLY (emails are not even marked as read),
      then the Spam folder the same way -- Gmail often files phishing there, and it is still a threat.
      CyberGuard's own alert and sign-in-code emails are recognised by their signature and skipped.
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

    @staticmethod
    def _spam_folder(imap) -> str | None:
        """Gmail's Spam folder: the folder marked \\Junk by the server (its name depends on the account's
        language), else IMAP_SPAM_FOLDER. None when switched off."""
        want = (get_settings().IMAP_SPAM_FOLDER or "").strip()
        if want.lower() in ("", "off", "none", "no", "false"):
            return None
        try:
            typ, rows = imap.list()
            for row in (rows or []) if typ == "OK" else []:
                line = row.decode("utf-8", "replace") if isinstance(row, bytes) else str(row)
                if "\\Junk" in line:
                    m = re.search(r'"((?:[^"\\]|\\.)*)"\s*$', line) or re.search(r"(\S+)\s*$", line)
                    if m:
                        return m.group(1)
        except Exception:
            pass
        return want

    def _scan_folder(self, imap, folder_key: str | None, label: str) -> tuple[int, int, str | None, int]:
        """Check the new emails in the currently selected folder. folder_key None = the main inbox
        (bookmark kept where it always was); otherwise the bookmark lives under state["folders"][key]."""
        from app.db.database import SessionLocal
        from app.services import notifier
        from app.services.email_ingest import process_email

        s = get_settings()
        validity = imap.response("UIDVALIDITY")[1][0]
        validity = validity.decode() if isinstance(validity, bytes) else str(validity)

        def load():
            st = get_state(self.name)
            return st if folder_key is None else (st.get("folders", {}) or {}).get(folder_key, {})

        def save(**values):
            if folder_key is None:
                update_state(self.name, **values)
            else:
                folders = dict(get_state(self.name).get("folders", {}) or {})
                folders[folder_key] = {**folders.get(folder_key, {}), **values}
                update_state(self.name, folders=folders)

        st = load()
        last = int(st.get("lastUid", 0)) if st.get("uidValidity") == validity else None
        if last is None:                       # first run (or mailbox rebuilt): start from the newest emails
            typ, data = imap.uid("search", None, "ALL")
            uids = [int(u) for u in (data[0] or b"").split()]
            newest = uids[-max(0, s.EMAIL_BACKFILL):] if s.EMAIL_BACKFILL else []
            last = (newest[0] - 1) if newest else (uids[-1] if uids else 0)
            save(uidValidity=validity, lastUid=last)
        typ, data = imap.uid("search", None, f"UID {last + 1}:*")
        uids = sorted(u for u in (int(x) for x in (data[0] or b"").split()) if u > last)[:MAX_PER_ROUND]
        checked = threats = 0
        finding = None
        where = "" if folder_key is None else f" [{label}]"
        for uid in uids:
            typ, msg = imap.uid("fetch", str(uid), "(BODY.PEEK[])")      # PEEK = do not mark as read
            raw = next((part[1] for part in msg if isinstance(part, tuple)), None)
            if raw and notifier.is_own_mail(raw):
                pass                        # CyberGuard's own alert / code email: never re-scan it (alert loop)
            elif raw and len(raw) <= s.MAX_UPLOAD_MB * 1024 * 1024:
                db = SessionLocal()
                try:
                    owner = owner_user_id(db)
                    if owner:
                        scan, _rec, result = process_email(db, owner, raw,
                                                           source="gmail" if folder_key is None else f"gmail-{folder_key}")
                        db.commit()
                        checked += 1
                        em = result.get("email", {}) or {}
                        subj = re.sub(r"\s+", " ", em.get("subject", "") or "(no subject)")[:80]
                        self.record(f'"{subj}" from {em.get("from_address") or "unknown sender"}{where}',
                                    result["riskScore"], result["classification"])
                        if result["classification"] != "safe":
                            threats += 1
                            finding = f"{result.get('category', 'Threat')}: \"{subj}\"{where} (score {result['riskScore']})"
                        if result["riskScore"] >= s.ALERT_MIN_SCORE:
                            notifier.alert_for_scan(scan.id)
                finally:
                    db.close()
            save(uidValidity=validity, lastUid=uid)                         # bookmark after each email
        return checked, threats, finding, len(uids)

    def check(self) -> dict:
        s = get_settings()
        imap = self._connect()                 # logs in and opens the inbox read-only
        try:
            checked, threats, finding, seen = self._scan_folder(imap, None, s.IMAP_FOLDER)
            spam = self._spam_folder(imap)
            notes = []
            if spam and spam.strip('"').lower() != s.IMAP_FOLDER.strip('"').lower():
                typ, _ = imap.select(f'"{spam}"', readonly=True)
                if typ == "OK":
                    c, t, f, n = self._scan_folder(imap, "spam", "Spam")
                    checked, threats, seen = checked + c, threats + t, seen + n
                    finding = f or finding
                else:
                    notes.append(f"Spam folder '{spam}' not found, inbox only")
            note = f"{checked} new email(s) checked" if seen else "No new emails"
            return {"checked": checked, "threats": threats, "finding": finding,
                    "note": "; ".join([note] + notes)}
        finally:
            try:
                imap.logout()
            except Exception:
                pass
