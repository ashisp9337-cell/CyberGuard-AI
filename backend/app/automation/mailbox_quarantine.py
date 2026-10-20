"""
Real, REVERSIBLE quarantine inside the Gmail mailbox.

When the Gmail watcher finds a dangerous email in the INBOX (risk >= QUARANTINE_MIN_SCORE), the email is MOVED
to the Gmail label MAILBOX_QUARANTINE_LABEL ("CyberGuard-Quarantine"):
  * it leaves the inbox, so the user is not tempted to click it,
  * it is NOT deleted: it stays in Gmail under that label (visible in Gmail's left menu),
  * "Release" in CyberGuard moves it back to the inbox,
  * every move is written to the email's quarantine history and to the audit log.

How: standard IMAP MOVE (RFC 6851, supported by Gmail) over SSL with the same App Password the watcher uses.
The watcher itself keeps its own connection READ-ONLY; moves use a separate short connection.
Emails found in the Spam folder are left where they are (Gmail already holds them away from the inbox).
Switched off with MAILBOX_QUARANTINE=false in backend/.env.
"""
from __future__ import annotations

import imaplib
import re
from datetime import datetime, timezone

from app.core.config import get_settings

INBOX = "INBOX"
MAX_RELEASED = 500


class MailboxError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _quote(name: str) -> str:
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _connect():
    from app.automation.email_watcher import EmailWatcher
    host, user, pw, _folder = EmailWatcher._creds()
    if not user or not pw:
        raise MailboxError("Gmail is not connected (IMAP_USER / IMAP_PASSWORD missing in backend/.env)")
    imap = imaplib.IMAP4_SSL(host, 993, timeout=20)
    try:
        imap.login(user, pw)
    except imaplib.IMAP4.error as e:
        imap.logout()
        raise MailboxError(f"Gmail refused the login ({e})") from e
    return imap


def _select(imap, folder: str) -> None:
    typ, data = imap.select(_quote(folder), readonly=False)
    if typ != "OK":
        raise MailboxError(f"could not open the Gmail folder '{folder}': {data}")


def _ensure_label(imap, label: str) -> None:
    typ, data = imap.create(_quote(label))            # "already exists" is fine
    if typ != "OK" and b"exist" not in b" ".join(d for d in data if isinstance(d, bytes)).lower():
        raise MailboxError(f"could not create the Gmail label '{label}': {data}")


def _copyuid(data) -> str:
    """New UID from a MOVE response ("[COPYUID <validity> <old> <new>]", UIDPLUS), '' if not given."""
    for part in data or []:
        text = part.decode("utf-8", "replace") if isinstance(part, bytes) else str(part)
        m = re.search(r"COPYUID\s+\d+\s+\S+\s+(\S+)", text, re.I)
        if m:
            return m.group(1)
    return ""


def _find(imap, message_id: str) -> str | None:
    """UID of the email with this Message-ID in the selected folder."""
    if not message_id:
        return None
    mid = message_id.strip().replace('"', "")
    typ, data = imap.uid("search", None, "HEADER", "Message-ID", f'"{mid}"')
    uids = (data[0] or b"").split() if typ == "OK" and data else []
    return uids[-1].decode() if uids else None


def quarantine_uid(uid: int | str, message_id: str = "", folder: str | None = None) -> dict:
    """Move one email (by its UID in `folder`, default the inbox) to the quarantine label.
    -> {"status": "moved", "label", "folder", "messageId", "newUid", "at"}"""
    s = get_settings()
    label = s.MAILBOX_QUARANTINE_LABEL
    folder = folder or s.IMAP_FOLDER or INBOX
    imap = _connect()
    try:
        _ensure_label(imap, label)
        _select(imap, folder)
        typ, data = imap.uid("MOVE", str(uid), _quote(label))
        if typ != "OK":
            raise MailboxError(f"Gmail refused to move the email: {data}")
        return {"status": "moved", "label": label, "folder": folder, "messageId": message_id,
                "newUid": _copyuid(data), "at": _now()}
    finally:
        try:
            imap.logout()
        except Exception:
            pass


def release(message_id: str, new_uid: str = "", back_to: str | None = None) -> dict:
    """Move a quarantined email from the quarantine label back to the inbox (found by Message-ID).
    -> {"status": "released", "folder", "at"}"""
    s = get_settings()
    label = s.MAILBOX_QUARANTINE_LABEL
    back_to = back_to or s.IMAP_FOLDER or INBOX
    imap = _connect()
    try:
        _select(imap, label)
        uid = _find(imap, message_id) or (new_uid or None)
        if not uid:
            raise MailboxError("the email is no longer in the quarantine label (it was moved or deleted in Gmail)")
        typ, data = imap.uid("MOVE", str(uid), _quote(back_to))
        if typ != "OK":
            raise MailboxError(f"Gmail refused to move the email back: {data}")
        remember_released(message_id)
        return {"status": "released", "folder": back_to, "at": _now()}
    finally:
        try:
            imap.logout()
        except Exception:
            pass


def requarantine(message_id: str) -> dict:
    """An email the user released earlier, quarantined again by hand: find it in the inbox and move it back."""
    s = get_settings()
    imap = _connect()
    try:
        _select(imap, s.IMAP_FOLDER or INBOX)
        uid = _find(imap, message_id)
    finally:
        try:
            imap.logout()
        except Exception:
            pass
    if not uid:
        raise MailboxError("the email is no longer in the inbox")
    info = quarantine_uid(uid, message_id)
    from app.automation.engine import get_state, update_state
    ids = [m for m in (get_state("email").get("releasedMessageIds") or []) if m != message_id]
    update_state("email", releasedMessageIds=ids)
    return info


def remember_released(message_id: str) -> None:
    """A released email comes back into the inbox with a NEW UID; the watcher must not quarantine it again."""
    from app.automation.engine import get_state, update_state
    if not message_id:
        return
    ids = [m for m in (get_state("email").get("releasedMessageIds") or []) if m != message_id]
    update_state("email", releasedMessageIds=(ids + [message_id])[-MAX_RELEASED:])


def was_released(message_id: str) -> bool:
    from app.automation.engine import get_state
    return bool(message_id) and message_id in (get_state("email").get("releasedMessageIds") or [])


def record_move(rec, info: dict, *, action: str, by: str) -> None:
    """Write a mailbox move into the EmailRecord's quarantine history (details["quarantine"]["mailbox"])."""
    details = dict(rec.details or {})
    q = dict(details.get("quarantine") or {"history": []})
    q["mailbox"] = {**(q.get("mailbox") or {}), **info}
    note = (f"Moved out of the inbox to the Gmail label '{info.get('label')}' (not deleted)"
            if action == "mailbox-quarantined" else
            f"Moved back to the Gmail folder '{info.get('folder')}'" if action == "mailbox-released" else
            info.get("error", ""))
    q["history"] = list(q.get("history", [])) + [{"action": action, "by": by, "at": _now(), "note": note[:500]}]
    details["quarantine"] = q
    rec.details = details
