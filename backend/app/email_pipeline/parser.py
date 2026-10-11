"""
Step 1 - Parse a raw email into an EmailEvent.

Extracts everything the detectors need in one pass:
  * identity headers (From, display name, Reply-To, Return-Path, To, Message-ID,
    In-Reply-To, References)
  * authentication headers (Authentication-Results, Received-SPF) and the full
    Received: hop chain, X-Mailer
  * plain-text and HTML bodies
  * every link, keeping BOTH the real destination (href) and the text the user
    sees, so deceptive links can be caught
  * every attachment and inline image, with its SHA-256 hash and raw bytes

Works on a full .eml file, on a raw email pasted as text (headers + body),
or on body-only text (is_structured=False). Never raises.
"""
import email
import email.policy
import hashlib
import re
from email.header import decode_header
from email.utils import parseaddr, getaddresses
from html.parser import HTMLParser

from app.email_pipeline.schemas import EmailEvent, Link, Attachment

URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'\)\]]+)""")
HEADER_LINE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{1,40}:\s")
MAX_LINKS = 50
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _decode(value) -> str:
    if not value:
        return ""
    value = str(value)
    try:
        return "".join(
            part.decode(enc or "utf-8", errors="ignore") if isinstance(part, bytes) else part
            for part, enc in decode_header(value)
        )
    except Exception:
        return value


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip(">").strip() if "@" in address else ""


class _HTMLExtractor(HTMLParser):
    """Collects visible text and <a href> links (with their visible text)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._anchor_text: list[str] = []
        self._skip = 0  # inside <script>/<style>

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor_text = []
        if tag in ("br", "p", "div", "tr", "li"):
            self.text_parts.append("\n")
        if tag in ("form",):
            # forms inside an email body are a red flag; keep the action URL
            action = dict(attrs).get("action")
            if action:
                self.links.append((action, "[form submit]"))

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._anchor_text).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


def _html_to_text_and_links(html: str) -> tuple[str, list[tuple[str, str]]]:
    p = _HTMLExtractor()
    try:
        p.feed(html)
        p.close()
    except Exception:
        return re.sub(r"<[^>]+>", " ", html), []
    text = re.sub(r"[ \t]+", " ", "".join(p.text_parts))
    text = re.sub(r"\n\s*\n+", "\n\n", text)
    return text.strip(), p.links


def _add_link(ev: EmailEvent, url: str, text: str, source: str, seen: set):
    url = (url or "").strip()
    if not url or url.lower().startswith(("mailto:", "tel:", "cid:", "#", "javascript:void")):
        return
    if url.lower().startswith("www."):
        url = "http://" + url
    if not url.lower().startswith(("http://", "https://", "javascript:", "data:")):
        return
    key = (url, text)
    if key in seen or len(ev.links) >= MAX_LINKS:
        return
    seen.add(key)
    ev.links.append(Link(url=url, display_text=text or "", source=source))


def _looks_like_raw_email(text: str) -> bool:
    """True when pasted text starts with real mail headers (From:, Subject: ...)."""
    first = [l for l in text.lstrip().splitlines()[:15] if l.strip()]
    hits = sum(1 for l in first if HEADER_LINE_RE.match(l))
    has_key = any(l.lower().startswith(("from:", "subject:", "received:", "return-path:", "message-id:")) for l in first)
    return has_key and hits >= 2


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
def parse_email(raw: bytes | str) -> EmailEvent:
    """Parse .eml bytes, a pasted raw email, or plain body text."""
    if isinstance(raw, str):
        if not _looks_like_raw_email(raw):
            return parse_body_only(raw)
        raw = raw.encode("utf-8", errors="ignore")

    try:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    except Exception:
        return parse_body_only(raw.decode("utf-8", errors="ignore"))

    if not msg.get("From") and not msg.get("Subject") and not msg.is_multipart():
        return parse_body_only(raw.decode("utf-8", errors="ignore"))

    ev = EmailEvent(is_structured=True)

    # ---- headers ---------------------------------------------------------
    for k, v in msg.items():
        ev.headers.setdefault(k.lower(), []).append(_decode(v))

    ev.subject = _decode(msg.get("Subject")).strip()
    ev.date = _decode(msg.get("Date")).strip()
    ev.message_id = _decode(msg.get("Message-ID")).strip()
    ev.in_reply_to = _decode(msg.get("In-Reply-To")).strip()
    ev.references = _decode(msg.get("References")).strip()

    name, addr = parseaddr(_decode(msg.get("From")))
    ev.from_display_name = name.strip().strip('"')
    ev.from_address = addr.strip().lower()
    ev.from_domain = _domain(ev.from_address)
    ev.reply_to_address = parseaddr(_decode(msg.get("Reply-To")))[1].strip().lower()
    ev.return_path = parseaddr(_decode(msg.get("Return-Path")))[1].strip().lower()
    ev.to_addresses = [a.lower() for _, a in getaddresses([_decode(v) for v in msg.get_all("To", [])]) if a]

    ev.authentication_results = " ; ".join(
        _decode(v) for v in (msg.get_all("Authentication-Results", []) + msg.get_all("ARC-Authentication-Results", []))
    )
    ev.received_spf = _decode(msg.get("Received-SPF"))
    ev.received_chain = [" ".join(_decode(v).split()) for v in msg.get_all("Received", [])]
    ev.x_mailer = _decode(msg.get("X-Mailer") or msg.get("User-Agent"))

    # ---- body parts & attachments -------------------------------------------
    plain_parts, html_parts = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = (part.get_content_type() or "application/octet-stream").lower()
        disposition = str(part.get("Content-Disposition") or "").lower()
        filename = _decode(part.get_filename()) if part.get_filename() else ""
        is_attachment = "attachment" in disposition or bool(filename)

        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""

        if not is_attachment and ctype == "text/plain":
            plain_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="ignore"))
            continue
        if not is_attachment and ctype == "text/html":
            html_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="ignore"))
            continue

        if payload and len(payload) <= MAX_ATTACHMENT_BYTES:
            ev.attachments.append(Attachment(
                filename=filename or f"inline.{ctype.split('/')[-1]}",
                content_type=ctype,
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                data=payload,
                is_inline="inline" in disposition or bool(part.get("Content-ID")) and not filename,
            ))

    ev.body_html = "\n".join(html_parts)
    html_text, html_links = _html_to_text_and_links(ev.body_html) if ev.body_html else ("", [])
    ev.body_text = ("\n".join(plain_parts).strip() or html_text).strip()

    # ---- links -------------------------------------------------------------
    seen: set = set()
    for href, text in html_links:
        _add_link(ev, href, text, "html", seen)
    for m in URL_RE.finditer(ev.body_text):
        _add_link(ev, m.group(1).rstrip(".,;:!?"), "", "body", seen)

    return ev


def parse_body_only(text: str, sender: str = "", subject: str = "") -> EmailEvent:
    """Body text with no headers (e.g. pasted into the UI). Sender can be supplied separately."""
    text = text or ""
    ev = EmailEvent(is_structured=False, body_text=text.strip(), subject=subject or "")
    if "<html" in text.lower() or "<a " in text.lower():
        ev.body_html = text
        ev.body_text, html_links = _html_to_text_and_links(text)
    else:
        html_links = []
    if sender:
        name, addr = parseaddr(sender)
        ev.from_display_name = name.strip()
        ev.from_address = (addr or sender).strip().lower()
        ev.from_domain = _domain(ev.from_address)
    seen: set = set()
    for href, t in html_links:
        _add_link(ev, href, t, "html", seen)
    for m in URL_RE.finditer(ev.body_text):
        _add_link(ev, m.group(1).rstrip(".,;:!?"), "", "body", seen)
    return ev
