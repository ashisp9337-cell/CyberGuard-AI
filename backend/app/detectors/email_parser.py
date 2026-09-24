"""
Real .eml/.msg header + body parsing using Python's built-in `email`
library — no external services, no guessing. This is what actually makes
uploaded email files analyzable at all (previously, uploaded files were
saved to disk but never read for the email-analysis subtopic).

Falls back to treating the raw content as plain text when it doesn't
parse as a structured email (e.g. a .txt file, or pasted body-only text).
"""
import email
import re
from email.header import decode_header
from email.utils import parseaddr

DISPLAY_NAME_RE = re.compile(r'^(.*?)<(.+?)>$')


def _decode(value: str | None) -> str:
    if not value:
        return ""
    try:
        parts = decode_header(value)
        return "".join(
            part.decode(enc or "utf-8", errors="ignore") if isinstance(part, bytes) else part
            for part, enc in parts
        )
    except Exception:
        return value


def parse_email_file(raw_bytes: bytes) -> dict:
    """
    Returns: {
        "body": str, "subject": str, "from_display_name": str,
        "from_address": str, "reply_to_address": str, "is_structured": bool,
    }
    """
    try:
        msg = email.message_from_bytes(raw_bytes)
    except Exception:
        return _plain_text_fallback(raw_bytes)

    # A file with no recognizable email headers parses "successfully" but
    # has no useful fields — treat it as plain text instead.
    if not msg.get("From") and not msg.get("Subject") and not msg.is_multipart():
        payload = msg.get_payload()
        if isinstance(payload, str) and not msg.get("From"):
            return _plain_text_fallback(raw_bytes)

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")
            if content_type == "text/plain" and "attachment" not in disposition:
                try:
                    body += part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                except Exception:
                    pass
        if not body:
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    try:
                        html = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                        body = re.sub(r"<[^>]+>", " ", html)
                    except Exception:
                        pass
                    break
    else:
        try:
            payload = msg.get_payload(decode=True)
            body = payload.decode(msg.get_content_charset() or "utf-8", errors="ignore") if payload else str(msg.get_payload())
        except Exception:
            body = str(msg.get_payload())

    from_display_name, from_address = parseaddr(_decode(msg.get("From")))
    _, reply_to_address = parseaddr(_decode(msg.get("Reply-To")))
    subject = _decode(msg.get("Subject"))

    return {
        "body": body.strip(),
        "subject": subject,
        "from_display_name": from_display_name.strip(),
        "from_address": from_address.strip().lower(),
        "reply_to_address": reply_to_address.strip().lower(),
        "is_structured": bool(from_address or subject),
    }


def _plain_text_fallback(raw_bytes: bytes) -> dict:
    try:
        text = raw_bytes.decode("utf-8", errors="ignore")
    except Exception:
        text = ""
    return {
        "body": text.strip(), "subject": "", "from_display_name": "",
        "from_address": "", "reply_to_address": "", "is_structured": False,
    }