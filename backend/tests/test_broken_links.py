"""31 Oct: a broken link - a port that is not a number, an impossible port, a broken IPv6 address - is scored, never
crashes a scan. Found by a real 2026 phishing link (":truncated" as the port). A website that redirects to a broken
link is refused by the safe fetcher instead of breaking the scan. Nothing here goes to the internet."""
import pytest

from app.detectors import malicious_url as MU
from app.detectors.url_features import extract_url_features, FEATURE_NAMES
from app.services import safe_fetch as S

BROKEN = ["http://evil.example:truncated/login", "https://a.b:99999/x", "http://[::1:bad/", "http://[zz]/",
          "https://paypa1.com:65536/login", "http://1.2.3.4:abc@x.com/"]


@pytest.mark.parametrize("url", BROKEN)
def test_broken_links_are_scored_offline(url):
    r = MU.analyze_url(url, subtopic_id="fraudulent-website", network=False)
    assert 0 <= r["riskScore"] <= 100


def test_a_broken_port_counts_as_a_port():
    f = dict(zip(FEATURE_NAMES, extract_url_features("http://evil.example:truncated/login")))
    assert f[FEATURE_NAMES[13]] == 1                      # the "has a port" feature
    assert dict(zip(FEATURE_NAMES, extract_url_features("https://google.com/")))[FEATURE_NAMES[13]] == 0


def test_safe_fetch_refuses_a_broken_link():
    r = S.fetch("http://[::1:bad/")
    assert r["status"] == "refused" and r["reason"] == "invalid link"


def test_a_redirect_to_a_broken_link_is_refused(monkeypatch):
    real = S._vet_all
    monkeypatch.setattr(S, "_vet_all", lambda u: (["93.184.216.34"], "") if "evil.example" in u else real(u))
    monkeypatch.setattr(S, "_get_pinned", lambda url, ip: (302, "http://[::1:bad/", "text/html", b""))
    r = S.fetch("http://evil.example/")
    assert r["status"] == "refused" and "broken link" in r["reason"]
