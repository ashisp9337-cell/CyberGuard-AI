"""Redirect fixes (Phase 2 audit, 19 Oct) and the background model warm-up."""
import socket

from app.detectors import malicious_url as M


def scan(url, sub="redirect-analysis"):
    return M.analyze_url(url, "Redirect Analysis", subtopic_id=sub, network=False)


def test_open_redirect_to_a_phishing_page_is_flagged():
    r = scan("https://www.google.com/url?q=http://hdfc-netbanking-verify.top/login")
    assert r["riskScore"] >= 71
    assert any(i["label"] == "Hidden redirect to another website" and i["triggered"] for i in r["indicators"])


def test_redirect_parameter_hiding_a_phishing_domain():
    assert scan("https://t.co/x9?u=https%3A%2F%2Fpaypal-account-verify.top%2F")["riskScore"] >= 51


def test_redirects_to_real_sites_stay_low():
    for u in ("https://www.google.com/url?q=https://www.wikipedia.org/",
              "https://accounts.google.com/signin?continue=https://mail.google.com/",
              "https://www.facebook.com/l.php?u=https%3A%2F%2Fwww.youtube.com%2F"):
        assert scan(u)["riskScore"] < 51, u


def test_shortener_that_cannot_be_followed_is_verify_in_redirect_analysis_only():
    assert 51 <= scan("https://bit.ly/3abcXYZ")["riskScore"] <= 70
    assert scan("https://bit.ly/3abcXYZ", sub="malicious-url")["riskScore"] <= 70     # short link: verify, never an alert by structure alone


def test_redirect_check_goes_only_one_level_deep():
    nested = "https://www.google.com/url?q=" + "https://t.co/a?u=https://www.google.com/url?q=http://x-login.top/"
    assert isinstance(scan(nested)["riskScore"], int)          # finishes, no endless recursion


def test_warm_up_loads_models_without_network(monkeypatch):
    from app.services.analysis_service import warm_up
    calls = []
    real = socket.getaddrinfo
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: calls.append(a[0]) or real(*a, **k))
    out = warm_up()
    assert out and all(isinstance(v, int) for v in out.values()), out
    assert calls == []
