"""QR / link checks added 21 Oct after the 2026-link benchmark: brand or login words in a free-hosted site's name,
pages planted in WordPress system folders, and the domain-name model's 2026 "verify" level. All offline."""
import json

import pytest

from app.detectors import domain_model as DM
from app.detectors import malicious_url as M


def scan(url):
    return M.analyze_url(url, "QR Code Phishing", subtopic_id="qr-phishing", network=False)


def fired(result):
    return {i["label"] for i in result["indicators"] if i["triggered"]}


@pytest.mark.parametrize("host,expected", [
    ("paypal-verify.netlify.app", ("netlify.app", "paypal", "verify")),
    ("auth-spectrum-net-login1.vercel.app", ("vercel.app", None, "login")),
    ("usdt-bep20-check.vercel.app", ("vercel.app", None, "usdt")),
    ("idspectrumsigninnow.weeblysite.com", ("weeblysite.com", None, "signin")),     # host not on the suffix list
    ("x-login.ey.r.appspot.com", ("appspot.com", None, "login")),
    ("microsoft.github.io", ("github.io", None, None)),            # real organisations own their GitHub names
    ("shiny-frangipane-8e8943.netlify.app", ("netlify.app", None, None)),
    ("login.wordpress.com", ("wordpress.com", None, None)),        # the host's own sign-in page
    ("example.com", (None, None, None)),
])
def test_words_in_free_hosted_names(host, expected):
    assert M.hosted_name_words(host) == expected


def test_free_hosted_lure_name_is_at_least_verify_and_plain_projects_are_not():
    r = scan("https://secure-login-update.netlify.app/")
    assert M.HOSTED_NAME_LABEL in fired(r) and r["riskScore"] >= 51
    plain = scan("https://my-portfolio.vercel.app/")
    assert M.HOSTED_NAME_LABEL not in fired(plain) and plain["riskScore"] < 51


@pytest.mark.parametrize("url,planted", [
    ("https://greenvalleybakery.com/wp-includes/css/densem.html", True),
    ("https://greenvalleybakery.com/wp-content/uploads/2026/01/pay.php", True),
    ("https://greenvalleybakery.com/wp-content/themes/x/style.css", False),
    ("https://riverside-school.org/wp-admin/admin-ajax.php", False),
    ("https://riverside-school.org/wp-login.php", False),
    ("https://greenvalleybakery.com/wp-content/uploads/2026/01/menu.pdf", False),
])
def test_page_planted_in_wordpress_folders(url, planted):
    r = scan(url)
    assert (M.WP_PLANTED_LABEL in fired(r)) is planted
    if planted:
        assert r["riskScore"] >= 51


# ---- domain-name model: 2026 "verify" level ---------------------------------------------------------------------
@pytest.fixture()
def fake_domain_model(tmp_path, monkeypatch):
    """A stand-in domain model (fixed probability) and its 2026 levels file, so no trained model is needed."""
    path = tmp_path / "url_domain_model.modern.json"
    state = {"p": 0.6}
    monkeypatch.setattr(DM, "MODERN_PATH", str(path))
    monkeypatch.setattr(DM, "load", lambda: {"threshold": 0.9, "card": {"trained_at": "model-A"}})
    monkeypatch.setattr(DM, "probability", lambda b, name, suffix: state["p"])
    monkeypatch.setattr(M, "_popular_sites", lambda: set())          # no popular-site list unless a test sets one
    DM._modern_cache.clear()

    def write(content, p=0.6):
        state["p"] = p
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        DM._modern_cache.clear()
    yield write
    DM._modern_cache.clear()


def test_domain_model_2026_level_makes_it_verify(fake_domain_model):
    fake_domain_model({"verify_level": 0.5, "model_trained_at": "model-A"}, p=0.6)
    a = DM.assess("quiet-river-gifts.xyz")
    assert a["verify"] and not a["flagged"]
    r = scan("https://quiet-river-gifts.xyz/")
    assert M.DOMAIN_2026_LABEL in fired(r) and r["riskScore"] >= 51


def test_domain_model_2026_level_below_level_or_other_model_or_broken_file(fake_domain_model):
    fake_domain_model({"verify_level": 0.5, "model_trained_at": "model-A"}, p=0.4)
    assert not DM.assess("quiet-river-gifts.xyz")["verify"]                     # below the level
    fake_domain_model({"verify_level": 0.5, "model_trained_at": "an older model"}, p=0.6)
    assert DM.modern_verify_level() is None and not DM.assess("quiet-river-gifts.xyz")["verify"]
    fake_domain_model("not json", p=0.6)
    assert DM.modern_verify_level() is None                                      # a broken file never breaks scans
    assert M.DOMAIN_2026_LABEL not in fired(scan("https://quiet-river-gifts.xyz/"))


def test_popular_sites_are_never_raised_by_the_domain_model_alone(fake_domain_model, monkeypatch):
    fake_domain_model({"verify_level": 0.5, "model_trained_at": "model-A"}, p=0.6)
    monkeypatch.setattr(M, "_popular_sites", lambda: {"quiet-river-gifts.xyz"})   # e.g. steamcommunity.com, gq.com
    assert M.DOMAIN_2026_LABEL not in fired(scan("https://quiet-river-gifts.xyz/"))
    monkeypatch.setattr(M, "_popular_sites", lambda: None)                        # look-alike model missing
    assert M.DOMAIN_2026_LABEL not in fired(scan("https://quiet-river-gifts.xyz/"))


def test_words_real_company_apps_use_do_not_count():
    # 'sso', 'auth', 'update' are as common in real company apps as in phishing (2026 data)
    for host in ("kddi-sso.appspot.com", "seek-ode-prod-auth.firebaseapp.com", "updatechecker2.firebaseapp.com"):
        assert M.hosted_name_words(host)[1:] == (None, None)


def test_trusted_sites_stay_capped(fake_domain_model):
    fake_domain_model({"verify_level": 0.01, "model_trained_at": "model-A"}, p=0.99)
    assert scan("https://www.onlinesbi.sbi/")["riskScore"] <= 15


# ---- real Indian payment links on shop QR codes (razorpay.me scored 53 before 21 Oct: "same name, other ending") ---
@pytest.mark.parametrize("url", ["https://razorpay.me/@greenvalleybakery", "https://rzp.io/l/fees2026",
                                 "https://paytm.me/ab-CdEf", "https://paypal.me/someone"])
def test_brands_own_payment_link_domains_are_not_flagged(url):
    assert scan(url)["riskScore"] < 51


@pytest.mark.parametrize("url", ["https://razorpay-kyc-update.xyz/login", "https://razorpey.com/",
                                 "https://razorpay.verify-account.netlify.app/"])
def test_fake_payment_brand_sites_are_still_flagged(url):
    assert scan(url)["riskScore"] >= 51
