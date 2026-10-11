"""
Well-known official domains.

WHY: the URL model is trained on a small dataset and is not sure about popular
sites (it gave google.com a 58% "malicious" probability). A short list of
domains that are verifiably the real thing lets us stop worrying real sites.

SAFETY RULES (so attackers cannot hide behind a trusted name):
  * Matching is on the REAL host's registered domain, so
    "google.com.evil.tk" and "google.com@evil.tk" are NOT trusted.
  * Places where anyone can publish content (docs.google.com forms, sites.google.com,
    sharepoint.com, github.io ...) are never trusted.
  * A trusted link that redirects to an untrusted site
    (google.com/url?q=https://evil.tk) is NOT trusted.
  * Even for trusted domains the score is only capped low, never set to zero.

TO EXTEND: add domains to STARTER below, or drop a text file with one domain
per line at  app/ml/training/data/tranco_top.txt  (e.g. the top 5,000 lines of
the free Tranco list from tranco-list.eu) and it is loaded automatically.
"""
import os
from urllib.parse import parse_qsl, urlparse

from app.detectors.url_features_v2 import (BRAND_DOMAINS, SHORTENERS, DYNAMIC_QR_SERVICES,
                                           registered_domain, split_url)

STARTER = {
    # --- global ---------------------------------------------------------
    "google.com", "youtube.com", "gmail.com", "microsoft.com", "office.com", "live.com", "outlook.com",
    "microsoftonline.com", "bing.com", "apple.com", "icloud.com", "amazon.com", "amazon.in", "facebook.com",
    "instagram.com", "whatsapp.com", "twitter.com", "x.com", "linkedin.com", "github.com", "gitlab.com",
    "stackoverflow.com", "wikipedia.org", "reddit.com", "netflix.com", "paypal.com", "zoom.us", "adobe.com",
    "dropbox.com", "python.org", "mozilla.org", "wireshark.org", "kali.org", "medium.com", "cloudflare.com",
    "ycombinator.com", "coursera.org", "udemy.com", "w3schools.com", "geeksforgeeks.org", "hackerone.com",
    "yahoo.com", "openai.com", "anthropic.com", "claude.ai", "spotify.com", "ebay.com", "slack.com",
    "telegram.org", "docusign.com", "owasp.org", "mitre.org", "nist.gov", "virustotal.com", "cisco.com",
    # --- India ----------------------------------------------------------------
    "onlinesbi.sbi", "sbi.co.in", "sbicard.com", "hdfcbank.com", "hdfcbank.net", "icicibank.com", "axisbank.com",
    "kotak.com", "yesbank.in", "idfcfirstbank.com", "pnbindia.in", "canarabank.com", "bankofbaroda.in",
    "irctc.co.in", "incometax.gov.in", "uidai.gov.in", "digilocker.gov.in", "npci.org.in", "rbi.org.in",
    "india.gov.in", "nptel.ac.in", "bput.ac.in", "paytm.com", "phonepe.com", "flipkart.com", "swiggy.com",
    "zomato.com", "makemytrip.com", "hotstar.com", "naukri.com", "jio.com", "airtel.in", "myntra.com",
    "bigbasket.com", "ola.com", "policybazaar.com", "zerodha.com", "groww.in", "indiapost.gov.in",
}

# Registered domains where anyone can publish: never trusted, even if they appear above.
USER_CONTENT_DOMAINS = {
    "sharepoint.com", "onedrive.com", "1drv.ms", "amazonaws.com", "googleusercontent.com", "googleapis.com",
    "gstatic.com", "github.io", "githubusercontent.com", "blogspot.com", "wordpress.com", "web.app",
    "firebaseapp.com", "pages.dev", "workers.dev", "vercel.app", "netlify.app", "herokuapp.com",
    "weebly.com", "wixsite.com", "webflow.io", "ngrok.io", "ngrok-free.app", "glitch.me", "repl.co",
    "azurewebsites.net", "cloudfront.net", "notion.site", "carrd.co", "forms.gle", "t.co", "wa.me",
}
# Specific hosts on otherwise-trusted domains that host user content.
USER_CONTENT_HOSTS = {
    "docs.google.com", "drive.google.com", "sites.google.com", "script.google.com", "forms.office.com",
    "storage.googleapis.com", "onedrive.live.com", "dl.dropboxusercontent.com", "gist.github.com",
    "raw.githubusercontent.com", "medium.com",
}
# Registration is tightly controlled for these suffixes, so any name under them is official.
TRUSTED_SUFFIXES = (".gov.in", ".nic.in")


def _load_file() -> set[str]:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "training", "data", "tranco_top.txt")
    try:
        with open(path, encoding="utf-8") as f:
            return {ln.strip().lower().split(",")[-1] for ln in f if ln.strip() and not ln.startswith("#")}
    except OSError:
        return set()


def _build() -> set[str]:
    trusted = set(STARTER) | _load_file()
    for official in BRAND_DOMAINS.values():
        trusted |= official
    trusted -= USER_CONTENT_DOMAINS
    trusted -= SHORTENERS
    trusted -= DYNAMIC_QR_SERVICES
    return trusted


TRUSTED = _build()


def _host_trusted(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host or host in USER_CONTENT_HOSTS:
        return False
    reg = registered_domain(host)
    if reg in USER_CONTENT_DOMAINS:
        return False
    return reg in TRUSTED or host.endswith(TRUSTED_SUFFIXES)


def _redirects_to_untrusted(query: str) -> bool:
    """True if any parameter value is a link to a site that is not trusted."""
    for _, value in parse_qsl(query, keep_blank_values=True):
        if value.lower().startswith(("http://", "https://", "//")):
            target = urlparse(value if "://" in value else "http:" + value).hostname or ""
            if not _host_trusted(target):
                return True
    return False


def is_trusted(url: str) -> bool:
    """True when the URL really belongs to a well-known official site."""
    parts = split_url(url)
    if parts["has_at"] or not _host_trusted(parts["host"]):
        return False
    return not _redirects_to_untrusted(parts["query"])