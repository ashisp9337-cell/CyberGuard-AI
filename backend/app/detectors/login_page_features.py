"""
Fake Login Page model - the clues read from a page's HTML. ONE implementation shared by the training script
(app/ml/training/train_fake_login.py, on urlscan.io's stored page copies) and the live scan (the page fetched
read-only by safe_fetch.py), so the model sees exactly the same numbers in training and in use.

Nothing here runs the page: the HTML is parsed as text with Python's built-in parser (no JavaScript, no rendering,
no requests). Every clue is a real, explainable property of the page:
  * what it asks for       - password / OTP / card / ID fields, how many inputs
  * where your data goes   - a form posting to another website, a .php script, Telegram / Discord / Google Apps Script
  * what it pretends to be - a brand named in the title / text while the site is not that brand's
  * copied pages           - logos, styles and scripts loaded from the real brand's own servers, many dead links (#)
  * hiding tricks          - scrambled JavaScript (atob / eval / unescape), hidden frames, "noindex", disabled right-click
  * the address            - free hosting platforms, raw IP, long / hyphenated names, risky endings
"""
from __future__ import annotations

import math
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from app.detectors import domain_model
from app.detectors.page_inspector import SENSITIVE_FIELD, _brands_named
from app.detectors.url_features_v2 import BRAND_DOMAINS, registered_domain

MAX_HTML = 400_000                  # characters of HTML looked at (pages are cut, never read without limit)
EXFIL_RE = re.compile(r"api\.telegram\.org|/bot\d{6,}:|discord(?:app)?\.com/api/webhooks|script\.google\.com/macros|"
                      r"formspree\.io|formsubmit\.co|getform\.io|submit-form\.com|webhook\.site|pipedream\.net|"
                      r"ngrok|requestbin|/(?:next|post|send|mail|log|login|verify|submit|result)\.php", re.I)
OBFUSCATION_RE = re.compile(r"\batob\s*\(|\beval\s*\(|\bunescape\s*\(|String\.fromCharCode|document\.write\s*\(|"
                            r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}", re.I)
ANTI_INSPECT_RE = re.compile(r"contextmenu|\bdebugger\b|devtools|keyCode\s*==\s*123|ctrlKey.{0,40}(?:85|73|74)", re.I)
LONG_B64_RE = re.compile(r"[A-Za-z0-9+/]{400,}={0,2}")
URGENT_RE = re.compile(r"\b(verify|verification|suspend|suspended|locked|unlock|confirm your|update your|"
                       r"unusual activity|expire|expired|restricted|limited|reactivate|security alert|"
                       r"re-?enter|validate)\b", re.I)
LOGIN_WORDS_RE = re.compile(r"\b(sign ?in|log ?in|password|passcode|username|user id|email address)\b", re.I)
ABUSED_TLDS = {"top", "xyz", "shop", "click", "cyou", "icu", "buzz", "online", "site", "live", "info", "rest", "cfd",
               "sbs", "lol", "pics", "autos", "beauty", "homes", "monster", "quest", "bond", "ink", "lat", "help",
               "support", "vip", "work", "fun", "space", "website", "store", "cc", "pw", "tk", "ml", "ga", "cf", "gq"}

# Shared web infrastructure and social buttons that ORDINARY sites use every day (Google Fonts / reCAPTCHA / Blogger
# images, YouTube embeds, "follow us" links, WhatsApp chat buttons, PayPal checkout). They belong to big brands, but
# loading or linking them is not "copying the brand's page", so they never count as brand-official resources / links.
SHARED_INFRA = {"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "googletagmanager.com",
                "google-analytics.com", "googlesyndication.com", "doubleclick.net", "youtube.com", "youtu.be",
                "ytimg.com", "blogger.com", "blogspot.com", "facebook.com", "facebook.net", "fb.com", "instagram.com",
                "twitter.com", "x.com", "linkedin.com", "pinterest.com", "tiktok.com", "whatsapp.com", "wa.me",
                "t.me", "telegram.org", "telegram.me", "apple.com", "paypal.com", "paypalobjects.com"}
# "Sign in with Google", "Continue with Apple", "Pay with PayPal": a real site naming its sign-in / payment partners
SSO_RE = re.compile(r"\b(?:sign ?in|log ?in|sign ?up|continue|register|connect|pay|checkout|share)\s+(?:with|using|via|on)\s+"
                    r"[A-Za-z][\w.&-]*(?:\s+[A-Za-z][\w.&-]*)?", re.I)

FEATURES = [
    # what it asks for
    "has_password", "n_password", "n_inputs", "n_text_inputs", "n_hidden_inputs", "n_sensitive_fields",
    "n_forms", "has_login_words",
    # where the data goes
    "form_external", "form_php", "form_empty_action", "exfil_endpoint", "form_mailto",
    # what it pretends to be
    "brand_named", "brand_mismatch", "title_has_brand_mismatch", "urgent_words",
    # copied pages
    "n_links", "share_dead_links", "share_external_links", "links_to_brand_official", "resources_from_brand_official",
    "share_external_resources", "favicon_external",
    # hiding tricks
    "obfuscation", "long_base64", "anti_inspect", "hidden_iframe", "meta_noindex", "meta_refresh", "n_scripts",
    "share_inline_script",
    # size
    "log_html_chars", "log_text_chars", "title_len",
    # the address
    "url_platform", "url_ip", "url_subdomains", "url_hyphens", "url_len", "url_abused_tld", "url_login_path",
]


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self.text, self.forms, self.inputs = "", [], [], []
        self.links, self.resources, self.scripts_inline, self.scripts_src = [], [], 0, 0
        self.iframes_hidden = self.noindex = self.refresh = 0
        self.favicon = ""
        self._in_title = self._in_script = False
        self._script_buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "script":
            self._in_script = True
            if a.get("src"):
                self.scripts_src += 1
                self.resources.append(a["src"])
            else:
                self.scripts_inline += 1
        elif tag == "style":
            self._in_script = True
        elif tag == "form":
            self.forms.append(a.get("action", "").strip())
        elif tag == "input":
            self.inputs.append((a.get("type", "text").lower(),
                                " ".join(a.get(k, "") for k in ("name", "id", "placeholder", "autocomplete", "aria-label"))))
        elif tag == "a":
            self.links.append(a.get("href", "").strip())
        elif tag in ("img", "source"):
            if a.get("src"):
                self.resources.append(a["src"])
            self.text.append(a.get("alt", ""))
        elif tag == "link":
            rel = a.get("rel", "").lower()
            if a.get("href"):
                self.resources.append(a["href"])
                if "icon" in rel:
                    self.favicon = a["href"]
        elif tag == "iframe":
            style = (a.get("style", "") + a.get("width", "") + a.get("height", "")).replace(" ", "").lower()
            if "display:none" in style or "visibility:hidden" in style or a.get("width") in ("0", "1") \
                    or a.get("height") in ("0", "1") or "hidden" in a:
                self.iframes_hidden += 1
        elif tag == "meta":
            name, equiv, content = a.get("name", "").lower(), a.get("http-equiv", "").lower(), a.get("content", "").lower()
            if name == "robots" and "noindex" in content:
                self.noindex = 1
            if equiv == "refresh":
                self.refresh = 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag in ("script", "style"):
            self._in_script = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif self._in_script:
            self._script_buf.append(data)
        elif data.strip():
            self.text.append(data.strip())


def _site(host: str) -> str:
    try:
        return domain_model.site_parts(host)["site"] or host
    except Exception:
        return host


def _official_sites() -> set[str]:
    return {d for ds in BRAND_DOMAINS.values() for d in ds}


_OFFICIAL = _official_sites()


def extract(html: str, page_url: str) -> dict:
    """HTML of one page + its address -> {feature name: number} (same keys/order as FEATURES) + a few readable facts
    under "_facts" for explanations."""
    html = (html or "")[:MAX_HTML]
    c = _Collector()
    try:
        c.feed(html)
    except Exception:                                   # broken HTML: keep what was read so far
        pass
    script_text = " ".join(c._script_buf)
    host = (urlparse(page_url).hostname or "").lower()
    site = registered_domain(host)
    parts = domain_model.site_parts(host) if host else {"platform": None, "ip": False, "subdomain": "", "site": ""}
    visible = " ".join(c.text)
    text_low = (c.title + " " + visible[:4000]).lower()

    pw = [d for t, d in c.inputs if t == "password" or re.search(r"pass(?:word|wd|code)", d, re.I)]
    sensitive = [d for t, d in c.inputs if SENSITIVE_FIELD.search(d)]
    text_inputs = [d for t, d in c.inputs if t in ("text", "email", "tel", "number", "")]
    hidden = [d for t, d in c.inputs if t == "hidden"]

    ext_form = php = empty = mailto = 0
    for act in c.forms:
        low = act.lower()
        if not low or low in ("#", "javascript:void(0)", "javascript:;"):
            empty += 1
        if low.startswith("mailto:"):
            mailto += 1
        if ".php" in low:
            php += 1
        if low.startswith(("http://", "https://", "//")):
            target = (urlparse(urljoin(page_url, act)).hostname or "").lower()
            if target and registered_domain(target) != site:
                ext_form += 1

    named = _brands_named(c.title + " " + SSO_RE.sub(" ", visible[:2000]))
    official_here = site in _OFFICIAL or host in _OFFICIAL      # a brand's own site naming partners is not imitation
    mismatch = [] if official_here else [b for b in named if site not in BRAND_DOMAINS[b] and host not in BRAND_DOMAINS[b]]
    title_mismatch = [] if official_here else [b for b in _brands_named(c.title)
                                               if site not in BRAND_DOMAINS[b] and host not in BRAND_DOMAINS[b]]

    def target_site(u):
        if not u or u.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return None
        h = (urlparse(urljoin(page_url, u)).hostname or "").lower()
        return _site(h) if h else None

    link_sites = [target_site(u) for u in c.links]
    dead = sum(1 for u in c.links if not u or u == "#" or u.lower().startswith("javascript:"))
    ext_links = [s for s in link_sites if s and s != site]
    res_sites = [target_site(u) for u in c.resources]
    ext_res = [s for s in res_sites if s and s != site]
    fav = target_site(c.favicon) if c.favicon else None

    n_links, n_res = len(c.links), len(c.resources)
    path = urlparse(page_url).path.lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    values = {
        "has_password": float(bool(pw)), "n_password": float(len(pw)), "n_inputs": float(len(c.inputs)),
        "n_text_inputs": float(len(text_inputs)), "n_hidden_inputs": float(len(hidden)),
        "n_sensitive_fields": float(len(sensitive)), "n_forms": float(len(c.forms)),
        "has_login_words": float(bool(LOGIN_WORDS_RE.search(text_low))),
        "form_external": float(ext_form), "form_php": float(php), "form_empty_action": float(empty),
        "exfil_endpoint": float(bool(EXFIL_RE.search(html))), "form_mailto": float(mailto),
        "brand_named": float(bool(named)), "brand_mismatch": float(bool(mismatch)),
        "title_has_brand_mismatch": float(bool(title_mismatch)),
        "urgent_words": float(len(URGENT_RE.findall(text_low[:3000]))),
        "n_links": float(n_links), "share_dead_links": dead / n_links if n_links else 0.0,
        "share_external_links": len(ext_links) / n_links if n_links else 0.0,
        "links_to_brand_official": float(sum(1 for s in ext_links if s in _OFFICIAL and s not in SHARED_INFRA))
        if not official_here else 0.0,
        "resources_from_brand_official": float(sum(1 for s in ext_res if s in _OFFICIAL and s not in SHARED_INFRA))
        if not official_here else 0.0,
        "share_external_resources": len(ext_res) / n_res if n_res else 0.0,
        "favicon_external": float(bool(fav and fav != site)),
        "obfuscation": float(len(OBFUSCATION_RE.findall(script_text[:200_000]))),
        "long_base64": float(bool(LONG_B64_RE.search(html))), "anti_inspect": float(bool(ANTI_INSPECT_RE.search(script_text))),
        "hidden_iframe": float(c.iframes_hidden), "meta_noindex": float(c.noindex), "meta_refresh": float(c.refresh),
        "n_scripts": float(c.scripts_inline + c.scripts_src),
        "share_inline_script": c.scripts_inline / (c.scripts_inline + c.scripts_src) if (c.scripts_inline + c.scripts_src) else 0.0,
        "log_html_chars": math.log1p(len(html)), "log_text_chars": math.log1p(len(visible)), "title_len": float(len(c.title.strip())),
        "url_platform": float(bool(parts.get("platform"))), "url_ip": float(bool(parts.get("ip"))),
        "url_subdomains": float(len([p for p in (parts.get("subdomain") or "").split(".") if p])),
        "url_hyphens": float(host.count("-")), "url_len": float(len(page_url)), "url_abused_tld": float(tld in ABUSED_TLDS),
        "url_login_path": float(bool(re.search(r"log-?in|sign-?in|verify|account|secure|auth|wallet|update", path))),
    }
    values["_facts"] = {"title": c.title.strip()[:120], "brands_imitated": mismatch[:3], "password_fields": len(pw),
                        "sensitive_fields": [s.strip()[:40] for s in sensitive[:4]],
                        "external_form": ext_form > 0, "exfil": bool(values["exfil_endpoint"]),
                        "copied_from_brand": int(values["resources_from_brand_official"]),
                        "dead_link_share": round(values["share_dead_links"], 2), "obfuscation": int(values["obfuscation"])}
    return values


def vector(values: dict) -> list[float]:
    return [float(values[k]) for k in FEATURES]
