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


# (10 Nov) An e-mail COPIED FROM A MAIL APP'S SCREEN (Gmail, Outlook, Yahoo ...) has no raw headers - it starts with
#   DigiLocker <noreply@digilocker.gov.in>
#   Sun 8 Nov, 13:40 (2 days ago)
#   to me
# The sender line is the most important fact of an e-mail (real domain or look-alike?), so it is recognised and used.
_SENDER_LINE_RE = re.compile(r"^\s*(?:from:\s*)?(?P<name>[^<>\n]{0,80}?)\s*<(?P<addr>[^<>@\s]{1,64}@[^<>@\s]{1,190}\.[A-Za-z]{2,24})>"
                             r"\s*(?:\(.{0,40}\))?\s*(?:via\s+[\w.-]{1,80}\.[A-Za-z]{2,24})?\s*(?:unsubscribe)?\s*$", re.I)
_BARE_ADDR_RE = re.compile(r"^\s*(?:from:\s*)?(?P<addr>[^<>@\s]{1,64}@[^<>@\s]{1,190}\.[A-Za-z]{2,24})"
                           r"\s*(?:via\s+[\w.-]{1,80}\.[A-Za-z]{2,24})?\s*(?:unsubscribe)?\s*$", re.I)
# (10 Nov) Gmail shows "<sender> via amazonses.com" and an "Unsubscribe" link on the sender line: both are copied.
# Wording that only e-mails use - a body copied WITHOUT the sender line is still an e-mail.
MAIL_ONLY_WORDS_RE = re.compile(r"\b(?:(?:do not|don'?t|please do not) reply to this (?:e-?mail|mail)|"
                                r"this (?:is an? )?(?:auto(?:matically)?[- ]generated|system[- ]generated|computer[- ]generated)"
                                r" (?:e-?mail|mail)|this e-?mail (?:was|is|has been) (?:sent|intended|generated)|"
                                r"you (?:are )?receiv(?:ed|ing) this e-?mail|unsubscribe from (?:these|our|this) (?:e-?mails?|mailing))", re.I)
_TO_LINE_RE = re.compile(r"^\s*to\s*:?\s+(me\b.*|[^\n]{1,120}@[^\n]{1,120}|[\w .,'&-]{1,80})\s*$", re.I)
_DATE_LINE_RE = re.compile(r"^\s*(?:(?:mon|tue|wed|thu|fri|sat|sun)[a-z]*,?\s+.{0,40}\d{1,2}:\d{2}.*|"
                           r"\d{1,2}[\s/.-](?:\d{1,2}|[a-z]{3,9})[\s/.-]\d{2,4},?\s+\d{1,2}:\d{2}.*|"
                           r".{0,40}\d{1,2}:\d{2}\s*(?:am|pm)?\s*\(\s*\d+\s+(?:minutes?|hours?|days?|weeks?)\s+ago\s*\).*)$", re.I)
_MAIL_WORDS_RE = re.compile(r"\b(?:this|the above) e-?mail\b|\breply to this e-?mail\b|\bauto(?:matically)?[- ]generated "
                            r"e-?mail\b|\bunsubscribe\b", re.I)
_LABEL_LINES = {"inbox", "spam", "updates", "promotions", "social", "important", "external", "starred"}


def pasted_mail_view(text: str) -> tuple[str, str, str] | None:
    """(sender, subject, body) when the text was copied from a mail app's reading view, else None.

    Needs a sender line ("Name <address>", or a bare address) within the first 4 lines AND one more mail sign: a
    recipient line ("to me"), a date line ("Sun 8 Nov, 13:40 (2 days ago)") or e-mail wording ("Do not reply to this
    email", "unsubscribe"). A short SMS that merely mentions an address does not qualify."""
    if not text or _looks_like_raw_email(text):
        return None
    lines = text.strip().splitlines()
    first = [(i, ln) for i, ln in enumerate(lines[:12]) if ln.strip()][:4]
    hit = None
    for i, ln in first:
        m = _SENDER_LINE_RE.match(ln) or _BARE_ADDR_RE.match(ln)
        if m:
            hit = (i, m)
            break
    if hit is None:
        return None
    idx, m = hit
    head = lines[idx + 1: idx + 6]
    signs = sum([any(_TO_LINE_RE.match(l) for l in head), any(_DATE_LINE_RE.match(l) for l in head),
                 bool(_MAIL_WORDS_RE.search(text))])
    if signs < 1:
        return None
    name = (m.groupdict().get("name") or "").strip().strip('"').strip()
    addr = m.group("addr").strip()
    sender = f"{name} <{addr}>" if name else addr
    before = [l.strip() for l in lines[:idx] if l.strip() and l.strip().lower() not in _LABEL_LINES]
    subject = before[0][:200] if before else ""
    rest = lines[idx + 1:]
    k = 0
    while k < len(rest) and k < 6 and (not rest[k].strip() or _TO_LINE_RE.match(rest[k]) or _DATE_LINE_RE.match(rest[k])):
        k += 1                                          # drop the date / "to me" lines under the sender
    return sender, subject, "\n".join(rest[k:]).strip()


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
            view = pasted_mail_view(raw)            # (10 Nov) copied from a mail app's screen: keep the sender
            if view:
                return parse_body_only(view[2], sender=view[0], subject=view[1])
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
