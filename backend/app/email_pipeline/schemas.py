"""
Data structures shared by every stage of the email pipeline.

EmailEvent is the single object that the parser fills, the enricher adds to,
and every detector reads from. Keeping one object means each detector gets
exactly the part of the email it needs, and nothing is parsed twice.
"""
from dataclasses import dataclass, field, asdict


@dataclass
class Link:
    url: str                       # the real destination (href)
    display_text: str = ""         # what the user sees, e.g. "www.sbi.co.in"
    source: str = "body"           # body | html | attachment:<name>


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    data: bytes = field(repr=False, default=b"")
    is_inline: bool = False        # inline images (cid:) vs real attachments


@dataclass
class EmailEvent:
    # --- identity -------------------------------------------------------
    message_id: str = ""
    subject: str = ""
    date: str = ""
    from_display_name: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to_address: str = ""
    return_path: str = ""
    to_addresses: list[str] = field(default_factory=list)
    in_reply_to: str = ""
    references: str = ""

    # --- content ----------------------------------------------------------
    body_text: str = ""            # plain text (or HTML converted to text)
    body_html: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)

    # --- transport / authentication (raw, interpreted later by enrich.py) --
    headers: dict[str, list[str]] = field(default_factory=dict)
    authentication_results: str = ""
    received_spf: str = ""
    received_chain: list[str] = field(default_factory=list)
    x_mailer: str = ""

    is_structured: bool = False    # False = pasted body text with no headers

    # --- filled by enrich.py ---------------------------------------------
    auth: dict = field(default_factory=dict)          # {"spf": "pass", "dkim": "fail", ...}
    originating_ip: str = ""
    sender_history: dict = field(default_factory=dict)
    enrichment_indicators: list[dict] = field(default_factory=list)
    claimed_entities: list[dict] = field(default_factory=list)

    @property
    def full_text(self) -> str:
        """Subject + body: what the text classifiers should read."""
        return f"{self.subject}\n{self.body_text}".strip()

    @property
    def images(self) -> list[Attachment]:
        return [a for a in self.attachments if a.content_type.startswith("image/")]

    def summary(self) -> dict:
        """JSON-safe view for API responses and the database (no raw bytes)."""
        claimed = [{k: v for k, v in c.items() if not k.startswith("_")} for c in self.claimed_entities]
        self_claimed, self.claimed_entities = self.claimed_entities, []
        try:
            d = asdict(self)
        finally:
            self.claimed_entities = self_claimed
        d["claimed_entities"] = claimed
        for a in d["attachments"]:
            a.pop("data", None)
        d.pop("headers", None)
        d.pop("body_html", None)
        d["body_text"] = self.body_text[:2000]
        return d
