"""
What is inside a QR code? A QR code is only a container: the text it holds
can be a web link, a payment request, a Wi-Fi login, a pre-filled SMS, and so
on. Each kind carries different risks, so we classify the decoded text first
and then apply checks that make sense for that kind.

All checks are deterministic and static: nothing here opens a link or makes a
network request.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

from app.detectors.url_features_v2 import (
    DYNAMIC_QR_SERVICES, SHORTENERS, brand_in_host, has_redirect_param,
    registered_domain, split_url,
)

BARE_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?::\d{1,5})?(?:[/?#]\S*)?$", re.I
)
UNKNOWN_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]{1,20}):\S")

CRYPTO_SCHEMES = {"bitcoin", "ethereum", "litecoin", "monero", "bitcoincash", "dogecoin", "solana"}
SMS_SCHEMES = {"sms", "smsto", "mms", "mmsto"}
DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file", "intent", "ms-msdt", "search-ms", "ms-officecmd"}

KIND_LABELS = {
    "url": "web link", "upi": "UPI payment request", "wifi": "Wi-Fi network login", "sms": "pre-filled SMS",
    "tel": "phone number", "mailto": "email address", "vcard": "contact card", "geo": "map location",
    "crypto": "cryptocurrency payment request", "otpauth": "authenticator (2FA) setup",
    "dangerous_scheme": "script/executable link", "app_link": "app-store link",
    "other_scheme": "custom link", "text": "plain text",
}


@dataclass
class Payload:
    kind: str
    raw: str
    url: str | None = None
    scheme_missing: bool = False
    fields: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return KIND_LABELS.get(self.kind, self.kind)

    @property
    def display(self) -> str:
        """Safe-to-store text: secrets inside the payload are masked."""
        text = self.raw
        if self.kind == "wifi":
            text = re.sub(r"(?i)(;P:)(?:\\.|[^;])*", r"\1[hidden]", text)
        elif self.kind == "otpauth":
            text = re.sub(r"(?i)(secret=)[^&]+", r"\1[hidden]", text)
        elif self.kind == "url":
            text = re.sub(r"(://[^/@:\s]+:)[^/@\s]+@", r"\1[hidden]@", text)
        return text[:500]


def _parse_wifi(text: str) -> dict:
    parts, buf, escaped = [], "", False
    for ch in text[5:]:
        if escaped:
            buf += ch
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ";":
            parts.append(buf)
            buf = ""
        else:
            buf += ch
    parts.append(buf)
    fields = {}
    for part in parts:
        if ":" in part:
            key, value = part.split(":", 1)
            fields[key.upper()] = value
    return fields


def classify_payload(raw: str) -> Payload:
    text = (raw or "").replace("\x00", "").strip()
    if not text:
        return Payload("text", "")

    upper = text.upper()
    if upper.startswith("WIFI:"):
        return Payload("wifi", text, fields=_parse_wifi(text))
    if upper.startswith("BEGIN:VCARD") or upper.startswith("MECARD:"):
        return Payload("vcard", text)

    if BARE_DOMAIN_RE.match(text):  # "example.com/login" with no scheme
        return Payload("url", text, url="https://" + text, scheme_missing=True)

    match = UNKNOWN_SCHEME_RE.match(text)
    if not match:
        return Payload("text", text)

    scheme = match.group(1).lower()
    if scheme in ("http", "https"):
        parsed = urlparse(text)
        if parsed.netloc:
            return Payload("url", text, url=text)
        return Payload("text", text)
    if scheme == "upi":
        parsed = urlparse(text)
        query = {k.lower(): v[0] for k, v in parse_qs(parsed.query).items() if v}
        query["_action"] = (parsed.netloc or parsed.path.strip("/")).lower()
        return Payload("upi", text, fields=query)
    if scheme in SMS_SCHEMES:
        rest = text.split(":", 1)[1]
        number, _, body = rest.partition("?body=") if "?body=" in rest else rest.partition(":")
        return Payload("sms", text, fields={"number": number.strip("/"), "body": body})
    if scheme == "tel":
        return Payload("tel", text)
    if scheme in ("mailto", "matmsg"):
        return Payload("mailto", text)
    if scheme == "geo":
        return Payload("geo", text)
    if scheme in CRYPTO_SCHEMES:
        return Payload("crypto", text)
    if scheme in ("otpauth", "otpauth-migration"):
        return Payload("otpauth", text)
    if scheme in DANGEROUS_SCHEMES:
        return Payload("dangerous_scheme", text)
    if scheme == "market":
        return Payload("app_link", text)
    return Payload("other_scheme", text)


# ---- UPI (NPCI "upi://pay?pa=...&pn=...&am=...&tn=..." deep links) ------------------------------------
# Handles (the part after @) of the UPI apps and banks in use in India (NPCI list of PSP handles).
UPI_HANDLES = {
    # PhonePe, Google Pay, Paytm, Amazon Pay, BHIM, WhatsApp, CRED, MobiKwik, Freecharge, Navi, Jupiter, Slice ...
    "ybl", "ibl", "axl", "okaxis", "okhdfcbank", "okicici", "oksbi", "paytm", "ptyes", "ptaxis", "pthdfc", "ptsbi",
    "apl", "yapl", "rapl", "upi", "waicici", "waaxis", "wahdfcbank", "wasbi", "axisb", "ikwik", "freecharge",
    "naviaxis", "jupiteraxis", "fam", "superyes", "slc", "goaxb", "tapicici", "timecosmos", "kmbl", "dlb",
    # banks
    "sbi", "hdfcbank", "icici", "axisbank", "kotak", "kkbk", "yesbank", "yesbankltd", "pnb", "barodampay",
    "cnrb", "boi", "unionbank", "unionbankofindia", "idbi", "idfcbank", "idfcfirst", "indus", "federal", "fbl",
    "rbl", "aubank", "citi", "hsbc", "sc", "dbs", "uco", "centralbank", "cboi", "iob", "indianbank", "allbank",
    "mahb", "psb", "jkb", "kbl", "kvb", "tjsb", "equitas", "ujjivan", "esaf", "csbpay", "dcb", "karurvysyabank",
    "lvb", "postbank", "airtel", "jio", "abfspay", "pockets", "icicipay", "hdfcbankjd", "rmhdfcbank",
}
UPI_SCAM_WORDS = re.compile(
    r"\b(refund|cash ?back|reward|prize|lottery|lucky|winner|won|bonus|gift|kyc|verify|verification|"
    r"customer ?care|helpline|support|receive|credit(ed)?|claim|electricity|bill update|disconnect|"
    r"income ?tax|tax refund|police|court|fine|penalty|army|loan|job|registration fee|deposit back)\b", re.I)
UPI_ORG_WORDS = re.compile(
    r"\b(bank|sbi|hdfc|icici|axis|kotak|paytm|phonepe|google ?pay|amazon|flipkart|irctc|govt|government|"
    r"ministry|uidai|aadhaar|income ?tax|electricity|bescom|msedcl|tneb|police|rbi|npci|lic|epfo|customer care)\b", re.I)
VPA_RE = re.compile(r"^[a-z0-9._\-]{2,256}@[a-z][a-z0-9.\-]{1,64}$", re.I)


def upi_indicators(f: dict) -> list[dict]:
    """Checks on the fields of a UPI payment link (pa = payee UPI ID, pn = payee name, am = amount,
    tn = note, mc = merchant category code, cu = currency)."""
    vpa = (f.get("pa") or "").strip().lower()
    pn, tn = (f.get("pn") or "").strip(), (f.get("tn") or "").strip()
    handle = vpa.rsplit("@", 1)[-1] if "@" in vpa else ""
    local = vpa.rsplit("@", 1)[0] if "@" in vpa else vpa
    try:
        amount = float(f.get("am") or 0)
    except ValueError:
        amount = 0.0
    words_pn = UPI_SCAM_WORDS.findall(pn)
    words_tn = UPI_SCAM_WORDS.findall(tn)
    scam_words = sorted({w[0].lower() if isinstance(w, tuple) else w.lower() for w in words_pn + words_tn})
    org_name = bool(UPI_ORG_WORDS.search(pn))
    merchant = bool(f.get("mc")) and f.get("mc") not in ("0000", "0")
    personal_id = bool(re.fullmatch(r"\+?\d{10,12}", local)) or not merchant
    return [
        _ind(not vpa, "No UPI ID in the payment code",
             "A real UPI payment code always names the receiving UPI ID (pa=...).", "high", 30),
        _ind(bool(vpa) and not VPA_RE.match(vpa), "Malformed UPI ID",
             f"'{vpa[:60]}' is not a valid UPI ID (name@bank).", "high", 30),
        _ind(bool(handle) and VPA_RE.match(vpa) is not None and handle not in UPI_HANDLES,
             "Unrecognised UPI app / bank handle",
             f"The UPI ID ends in '@{handle}', which is not one of the UPI apps or banks on the NPCI list.",
             "medium", 20),
        _ind(bool(scam_words), "Scam words in the payee name or note",
             f"The payment text says: {', '.join(scam_words)}. Refunds, prizes, cashback and KYC never require "
             "you to scan and pay - this is the most common UPI QR scam.", "high", 35),
        _ind(org_name and not merchant, "Payee name claims to be an organisation, but it is not a registered merchant",
             f"The name '{pn[:60]}' looks like a bank / company / government office, but the code has no merchant "
             "category code (mc), which registered businesses' UPI QR codes carry. It is probably a personal account.",
             "high", 30),
        _ind(amount >= 10_000, "Large pre-filled amount",
             f"The code asks for ₹{amount:,.0f}.", "medium", 15 if amount < 50_000 else 25),
        _ind(bool(f.get("cu")) and f.get("cu", "").upper() != "INR", "Currency is not INR",
             f"UPI payments are in INR; this code says '{f.get('cu')}'.", "medium", 15),
        _ind(personal_id and bool(re.fullmatch(r"\+?\d{10,12}", local)), "Payment goes to a mobile-number UPI ID",
             f"The money goes to a personal UPI ID based on a phone number ({local[:4]}******).", "low", 5),
    ]


def _ind(triggered: bool, label: str, description: str, severity: str, weight: int) -> dict:
    return {"label": label, "description": description, "severity": severity,
            "weight": weight, "triggered": bool(triggered)}


def url_context_indicators(p: Payload) -> list[dict]:
    """QR-specific checks on a web link (added on top of the general URL engine)."""
    parts = split_url(p.url or "")
    host, query = parts["host"], parts["query"]
    reg = registered_domain(host)
    brand = brand_in_host(host)
    is_dynamic = host in DYNAMIC_QR_SERVICES or reg in DYNAMIC_QR_SERVICES
    is_short = (host in SHORTENERS or reg in SHORTENERS)

    return [
        _ind(is_short, "URL shortener hides the destination",
             f"The QR points to a link shortener ({reg}); the real website is unknown until it is opened.",
             "medium", 30),
        _ind(is_dynamic, "Dynamic QR redirect service",
             f"The code points to a QR-management service ({reg}) whose owner can change the destination after printing.",
             "low", 10),
        _ind(has_redirect_param(query), "Open-redirect parameter in the link",
             "The link carries another web address in a redirect-style parameter, a common way to bounce victims to a fake page.",
             "high", 18),
        _ind(bool(brand), "Brand name used on an unrelated domain",
             f"The domain uses the name '{brand}' but is not one of that brand's known domains ({reg})." if brand
             else "The domain does not imitate a known brand.",
             "high", 25),
        _ind(p.scheme_missing, "Link has no http/https prefix",
             "The QR holds a bare domain instead of a full link; legitimate generators normally include the scheme.",
             "low", 6),
    ]


def payload_indicators(p: Payload) -> list[dict]:
    """Checks that depend on what kind of payload the QR holds."""
    k, f = p.kind, p.fields
    out: list[dict] = []

    if k == "upi":
        action = f.get("_action", "")
        out += [
            _ind(True, "QR starts a UPI payment",
                 "Scanning this code leads to a payment screen. Money is only ever received without scanning or entering a PIN; "
                 "a stranger asking you to scan to 'receive' money is a common scam.",
                 "low", 15),
            _ind(action == "collect", "UPI collect request",
                 "The code requests money from the scanner (a collect request) instead of paying a merchant.", "high", 40),
            _ind(bool(f.get("am")), "Payment amount is pre-filled",
                 f"The code fixes the amount ({f.get('am')}). Check it before approving.", "low", 8),
            _ind(not f.get("pn"), "No payee name in the code",
                 "The payment request has no payee name, so you cannot see who receives the money.", "low", 6),
        ] + upi_indicators(f)
    elif k == "wifi":
        encryption = (f.get("T") or "nopass").upper()
        out += [
            _ind(True, "QR joins a Wi-Fi network",
                 "Scanning connects the device to the network named in the code.", "low", 5),
            _ind(encryption in ("NOPASS", ""), "Open Wi-Fi network (no encryption)",
                 "Traffic on an open network can be read by others; fake hotspots are a classic attack.", "medium", 30),
            _ind(encryption == "WEP", "Outdated WEP encryption",
                 "WEP encryption is broken and offers little protection.", "medium", 12),
        ]
    elif k == "sms":
        number = re.sub(r"\D", "", f.get("number", ""))
        out += [
            _ind(True, "QR prepares an SMS",
                 "Scanning opens a text message that is ready to send.", "low", 10),
            _ind(0 < len(number) <= 6, "SMS to a short code",
                 "Short codes are used for premium-rate and subscription services.", "medium", 25),
            _ind(bool(f.get("body")), "Message text is pre-filled",
                 "The text is already written for you; read it before sending.", "low", 12),
        ]
    elif k == "tel":
        out.append(_ind(True, "QR starts a phone call", "Scanning opens the dialer with the number filled in.", "low", 12))
    elif k == "mailto":
        out.append(_ind(True, "QR starts an email", "Scanning opens a pre-addressed email.", "low", 8))
    elif k == "vcard":
        out.append(_ind(True, "QR adds a contact card", "Scanning offers to save contact details from an unknown source.", "low", 5))
    elif k == "crypto":
        out.append(_ind(True, "Cryptocurrency payment request",
                        "Crypto transfers cannot be reversed; verify the address independently.", "medium", 30))
    elif k == "otpauth":
        out.append(_ind(True, "Authenticator (2FA) enrolment code",
                        "This code contains a two-factor secret. Only scan it from the service's own setup page, and never share it.",
                        "medium", 20))
    elif k == "dangerous_scheme":
        out.append(_ind(True, "Script or executable link scheme",
                        f"The code uses a '{p.raw.split(':', 1)[0].lower()}:' link, which can run code or open local content and has no legitimate use in a printed QR.",
                        "critical", 90))
    elif k == "app_link":
        out.append(_ind(True, "Opens an app-store deep link",
                        "The code launches an app installation page directly.", "medium", 25))
    elif k == "other_scheme":
        out.append(_ind(True, "Custom link scheme",
                        f"The code uses an unusual '{p.raw.split(':', 1)[0].lower()}:' scheme that opens a specific app.", "low", 15))
    return out


def extra_recommendations(p: Payload) -> list[str]:
    tips = {
        "upi": ["Never scan a QR code to receive money, and never enter your UPI PIN to receive money."],
        "wifi": ["Only join Wi-Fi networks you can confirm belong to the venue."],
        "sms": ["Read the pre-filled message before sending anything."],
        "crypto": ["Verify the wallet address through a second channel before sending funds."],
        "otpauth": ["Do not scan authenticator codes from emails, chats or posters."],
        "dangerous_scheme": ["Do not open this code with any app."],
    }
    return tips.get(p.kind, [])