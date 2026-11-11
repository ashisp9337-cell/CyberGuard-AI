"""(11 Nov) Site reputation for the browser extension (opt-in). Every outside service is replaced in these tests."""
import pytest

from app.api.routes import extension as EXT
from app.services import network_intel, threat_intelligence as TI


@pytest.fixture()
def feeds(monkeypatch):
    sent = {"vt": [], "uh": [], "ab": []}

    def set_(vt=None, uh=None, ab=None):
        monkeypatch.setattr(TI, "check_virustotal_domain_sync", lambda d: sent["vt"].append(d) or (vt or {"status": "ok", "malicious": 0, "suspicious": 0, "total": 94}))
        monkeypatch.setattr(TI, "check_urlhaus_host_sync", lambda h: sent["uh"].append(h) or (uh or {"status": "ok", "listed": False}))
        monkeypatch.setattr(TI, "check_abuseipdb_sync", lambda ip: sent["ab"].append(ip) or (ab or {"status": "ok", "ip": ip, "abuseScore": 0, "totalReports": 0}))
    monkeypatch.setattr(network_intel, "resolve_domain", lambda h: {"status": "ok", "ips": ["203.0.113.5"]})
    set_()
    feeds.set = set_
    return set_, sent


def test_only_the_site_name_is_sent_never_the_full_address(feeds):
    set_, sent = feeds
    out = EXT.reputation("https://shop.bakery-example.com/cart?session=SECRET123&q=my+search")
    assert out["level"] == "safe" and out["site"] == "bakery-example.com" and out["host"] == "shop.bakery-example.com"
    assert sent["vt"] == ["bakery-example.com"] and sent["uh"] == ["shop.bakery-example.com"] and sent["ab"] == ["203.0.113.5"]
    assert "SECRET123" not in str(sent) and "search" not in str(sent)


def test_vendor_votes_and_urlhaus_listing_raise_the_level(feeds):
    set_, _ = feeds
    set_(vt={"status": "ok", "malicious": 1, "suspicious": 0, "total": 94})
    assert EXT.reputation("https://odd-example.com/")["level"] == "verify"
    set_(vt={"status": "ok", "malicious": 7, "suspicious": 2, "total": 94})
    out = EXT.reputation("https://bad-example.com/")
    assert out["level"] == "danger" and "9 of 94" in out["notes"][0]
    set_(uh={"status": "ok", "listed": True, "urlCount": 4, "online": 1, "threats": ["malware_download"]})
    out = EXT.reputation("https://files-example.com/")
    assert out["level"] == "danger" and "malware_download" in out["notes"][0]
    set_(uh={"status": "ok", "listed": True, "urlCount": 4, "online": 0, "threats": []})
    assert EXT.reputation("https://cleaned-example.com/")["level"] == "verify"          # only old, offline entries


def test_abuseipdb_alone_never_condemns_a_named_site(feeds):
    set_, _ = feeds
    set_(ab={"status": "ok", "ip": "203.0.113.5", "abuseScore": 100, "totalReports": 80})
    out = EXT.reputation("https://bakery-example.com/")
    assert out["level"] == "safe" and "shared servers" in out["notes"][0]


def test_trusted_sites_and_missing_keys(feeds, monkeypatch):
    _, sent = feeds
    out = EXT.reputation("https://www.google.com/search?q=private")
    assert out.get("trusted") and sent == {"vt": [], "uh": [], "ab": []}


def test_virustotal_free_limit_is_respected(monkeypatch):
    calls = []

    class R:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}}}}

    class C:
        def __init__(self, timeout): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url, headers): calls.append(url); return R()

    monkeypatch.setattr(TI.settings, "VIRUSTOTAL_API_KEY", "k")
    monkeypatch.setattr(TI.httpx, "Client", C)
    TI._SITE_CACHE.clear(); TI._VT_CALLS.clear()
    res = [TI.check_virustotal_domain_sync(f"site{i}.example") for i in range(6)]
    assert [r["status"] for r in res] == ["ok"] * 4 + ["skipped"] * 2 and len(calls) == 4
    assert TI.check_virustotal_domain_sync("site0.example") == res[0] and len(calls) == 4     # cached, no new call
    monkeypatch.setattr(TI.settings, "VIRUSTOTAL_API_KEY", "")
    assert TI.check_virustotal_domain_sync("other.example")["status"] == "unavailable" and len(calls) == 4


def test_endpoint_needs_the_extension_key_and_saves_dangerous_sites(feeds, auth_client, client):
    set_, _ = feeds
    from fastapi.testclient import TestClient
    from app.main import app
    assert TestClient(app).post("/api/extension/reputation", json={"url": "https://x-example.com/"}).status_code in (401, 403)
    key = auth_client.post("/api/extension/tokens", json={"name": "Test browser"}).json()
    token = key.get("token") or key.get("key")
    h = {"X-CyberGuard-Extension": token}
    assert auth_client.post("/api/extension/reputation", json={"url": "http://192.168.1.1/"}, headers=h).json()["level"] == "skip"
    set_(vt={"status": "ok", "malicious": 9, "suspicious": 0, "total": 94})
    r = auth_client.post("/api/extension/reputation", json={"url": "https://bad-example2.com/login"}, headers=h).json()
    assert r["level"] == "danger" and r["savedAsFinding"] is True
    scans = auth_client.get("/api/scans").json()
    items = scans.get("items", scans) if isinstance(scans, dict) else scans
    assert any("bad-example2.com" in str(s) for s in items)
