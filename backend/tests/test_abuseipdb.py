"""(11 Nov) AbuseIPDB in the link scan. Every outside call is replaced: nothing leaves the test."""
import pytest

from app.detectors import malicious_url as MU
from app.services import network_intel, threat_intelligence as TI


@pytest.fixture()
def scan(monkeypatch):
    monkeypatch.setattr(network_intel, "resolve_domain", lambda h: {"status": "ok", "ips": ["203.0.113.7"]})
    monkeypatch.setattr(network_intel, "get_domain_age", lambda h: {"status": "error"})
    monkeypatch.setattr(network_intel, "get_ssl_info", lambda h: {"status": "error"})
    monkeypatch.setattr(TI, "check_virustotal_url_sync", lambda u: {"status": "skipped"})
    monkeypatch.setattr(TI, "check_urlhaus_sync", lambda u: {"status": "skipped"})
    monkeypatch.setattr(MU, "_registry", lambda h: None)
    monkeypatch.setattr(MU.settings, "LIVE_PAGE_CHECKS", False)
    asked = []

    def run(url, abuse=None, key="test-key"):
        monkeypatch.setattr(MU.settings, "ABUSEIPDB_API_KEY", key)
        monkeypatch.setattr(TI, "check_abuseipdb_sync",
                            lambda ip: asked.append(ip) or ({"status": "ok", "ip": ip, "isp": "Example Hosting",
                                                             "isWhitelisted": False, **abuse} if abuse else {"status": "error"}))
        r = MU.analyze_url(url, "Malicious URL Detection", network=True)
        return r, {i["label"]: i for i in r["indicators"]}
    run.asked = asked
    return run


def test_reported_raw_ip_link_is_a_strong_sign(scan):
    r, ind = scan("http://198.51.100.9/files/invoice", {"abuseScore": 100, "totalReports": 240})
    i = ind["Server address reported for abuse (AbuseIPDB)"]
    assert i["triggered"] and i["weight"] == 25 and "100%" in i["description"] and "240 report" in i["description"]
    assert scan.asked == ["198.51.100.9"]                       # the address in the link itself, no DNS needed


def test_named_site_on_a_reported_shared_address_only_supports(scan):
    _, ind = scan("https://bakery-example.com/menu", {"abuseScore": 90, "totalReports": 30})
    i = ind["Server address reported for abuse (AbuseIPDB)"]
    assert i["triggered"] and i["weight"] == 12 and "shared hosting" in i["description"]
    assert scan.asked == ["203.0.113.7"]                        # the address the name resolves to


def test_clean_or_allow_listed_addresses_add_nothing(scan):
    for abuse in ({"abuseScore": 0, "totalReports": 0}, {"abuseScore": 100, "totalReports": 50, "isWhitelisted": True}):
        _, ind = scan("https://bakery-example.com/", abuse)
        i = ind["Server address checked on AbuseIPDB"]
        assert not i["triggered"] and i["weight"] == 0


def test_some_reports_is_a_small_hint(scan):
    _, ind = scan("https://bakery-example.com/", {"abuseScore": 40, "totalReports": 3})
    assert ind["Server address has some abuse reports (AbuseIPDB)"]["weight"] == 5


def test_no_key_means_no_lookup_and_no_line(scan):
    _, ind = scan("https://bakery-example.com/", {"abuseScore": 100, "totalReports": 99}, key="")
    assert scan.asked == [] and not any("AbuseIPDB" in k for k in ind)


def test_lookup_errors_never_break_the_scan(scan):
    r, ind = scan("https://bakery-example.com/", None)
    assert r["riskScore"] >= 0 and not any("AbuseIPDB" in k for k in ind)


def test_private_addresses_are_never_sent_and_results_are_cached(monkeypatch):
    calls = []

    class Resp:
        def raise_for_status(self): pass
        def json(self): return {"data": {"abuseConfidenceScore": 88, "totalReports": 12, "isp": "X"}}

    class Client:
        def __init__(self, timeout): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url, params, headers):
            calls.append(params["ipAddress"]); assert headers["Key"] == "k"; return Resp()

    monkeypatch.setattr(TI.settings, "ABUSEIPDB_API_KEY", "k")
    monkeypatch.setattr(TI.httpx, "Client", Client)
    TI._ABUSE_CACHE.clear()
    for ip in ("192.168.1.10", "127.0.0.1", "10.0.0.1", "198.51.100.20", "not-an-ip"):   # private / documentation
        assert TI.check_abuseipdb_sync(ip)["status"] == "skipped"
    a = TI.check_abuseipdb_sync("45.155.205.20")
    b = TI.check_abuseipdb_sync("45.155.205.20")
    assert a == b and a["abuseScore"] == 88 and a["totalReports"] == 12 and calls == ["45.155.205.20"]
    monkeypatch.setattr(TI.settings, "ABUSEIPDB_API_KEY", "")
    assert TI.check_abuseipdb_sync("45.155.205.21")["status"] == "unavailable"
