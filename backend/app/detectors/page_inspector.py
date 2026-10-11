"""
Fake-login-page checks on a page's HTML (fetched read-only by app/services/safe_fetch.py).

Nothing here runs the page: the HTML is parsed as text with Python's built-in parser.
Signals (each one is a real, explainable property of the page):
  * a password field                         -> the page wants your login
  * the page names a brand (title / headings / logo text) whose official domains do NOT include
    this site                                -> it pretends to be someone else
  * a form that sends what you type to a DIFFERENT website
  * fields asking for card number / CVV / OTP / PIN / Aadhaar / UPI details
"""
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from app.detectors.url_features_v2 import BRAND_DOMAINS, registered_domain

SENSITIVE_FIELD = re.compile(r"(card.?(?:no|num)|cardnumber|\bcc.?num|cvv|cvc|expiry|exp.?date|\botp\b|one.?time|"
                             r"\bpin\b|mpin|atm|aadhaar|aadhar|\bpan\b|upi|ifsc|account.?(?:no|num)|ssn)", re.I)
# Readable names for brands whose dictionary key is not how people write them
BRAND_LABELS = {"onlinesbi": ("sbi", "state bank of india"), "hdfcbank": ("hdfc",), "icicibank": ("icici",),
                "axisbank": ("axis bank",), "bankofamerica": ("bank of america",), "wellsfargo": ("wells fargo",)}


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self.text, self.forms, self.inputs = "", [], [], []
        self._in_title, self._in_script = False, False
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag in ("script", "style"):
            self._in_script = True
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "password": False, "sensitive": []}
            self.forms.append(self._form)
        elif tag == "input":
            kind = a.get("type", "text").lower()
            desc = " ".join(a.get(k, "") for k in ("name", "id", "placeholder", "autocomplete", "aria-label"))
            item = {"type": kind, "desc": desc}
            self.inputs.append(item)
            if self._form is not None:
                if kind == "password":
                    self._form["password"] = True
                if SENSITIVE_FIELD.search(desc):
                    self._form["sensitive"].append(desc.strip()[:40])
        elif tag == "img":
            self.text.append(a.get("alt", ""))

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag in ("script", "style"):
            self._in_script = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self._in_script and data.strip():
            self.text.append(data.strip())


def _brands_named(text: str) -> list[str]:
    low = text.lower()
    found = []
    for brand in BRAND_DOMAINS:
        names = (brand,) + BRAND_LABELS.get(brand, ())
        if any(re.search(rf"(?<![a-z]){re.escape(n)}(?![a-z])", low) for n in names if len(n) >= 3):
            found.append(brand)
    return found


def inspect(html: str, page_url: str) -> dict:
    """Facts about the page used by the URL detector's indicators."""
    c = _Collector()
    try:
        c.feed(html or "")
    except Exception:
        pass
    host = (urlparse(page_url).hostname or "").lower()
    site = registered_domain(host)
    visible = " ".join(c.text)[:6000]
    # type="password", or a plain text box labelled as a password (common in Google-Forms-style phishing)
    has_password = any(i["type"] == "password" or re.search(r"pass(?:word|wd|code)", i["desc"], re.I)
                       for i in c.inputs)
    sensitive = sorted({d.strip()[:40] for i in c.inputs for d in [i["desc"]] if SENSITIVE_FIELD.search(d)})
    external_forms = []
    for f in c.forms:
        act = f["action"].strip()
        if act.lower().startswith(("http://", "https://", "//")):
            target = (urlparse(urljoin(page_url, act)).hostname or "").lower()
            if target and registered_domain(target) != site:
                external_forms.append(target)
    named = _brands_named(c.title + " " + visible[:2000])
    imitated = [b for b in named if site not in BRAND_DOMAINS[b] and host not in BRAND_DOMAINS[b]]
    return {"title": c.title.strip()[:120], "has_password": has_password, "sensitive_fields": sensitive[:5],
            "external_form_targets": sorted(set(external_forms))[:3], "brands_named": named[:5],
            "brands_imitated": imitated[:3], "forms": len(c.forms), "text_chars": len(visible)}
