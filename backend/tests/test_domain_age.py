"""SSL & Domain Analysis: registry (RDAP) facts, the domain-registration model and how URL scans use them.
No real network: every lookup is replaced by a fixed answer."""
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from app.detectors import domain_age as DA
from app.detectors import domain_facts as F
from app.detectors import malicious_url as MU
from app.services import network_intel, threat_intelligence

NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)


def facts(domain="example-login.xyz", age_days=3, term_years=1, registrar="Gname.com Pte. Ltd.", ok=True, **kw):
    created = NOW - timedelta(days=age_days)
    return {"domain": domain, "ok": ok, "error": "" if ok else "not found in the registry",
            "checked_at": NOW.isoformat(), "created": created.isoformat(),
            "expires": (created + timedelta(days=365 * term_years)).isoformat(), "registrar": registrar,
            "status": kw.get("status", ["client transfer prohibited"]), "nameservers": kw.get("ns", ["ns1.dnsowl.com"]),
            "dnssec": False}


def test_rdap_parser_reads_dates_registrar_and_locks():
    doc = {"events": [{"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
                      {"eventAction": "expiration", "eventDate": "2028-09-14T04:00:00Z"}],
           "entities": [{"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "292"}],
                         "vcardArray": ["vcard", [["fn", {}, "text", "MarkMonitor Inc."]]]}],
           "status": ["server delete prohibited"], "nameservers": [{"ldhName": "NS1.GOOGLE.COM"}],
           "secureDNS": {"delegationSigned": False}}
    f = F.parse_rdap(doc)
    assert f["registrar"] == "MarkMonitor Inc." and f["registrar_iana"] == "292" and f["nameservers"] == ["ns1.google.com"]
    assert F.describe_age(F.age_days({**f, "checked_at": NOW.isoformat()})) == "29 years"
    assert F.describe_age(0.3) == "less than a day" and F.describe_age(12) == "12 days"


def test_taken_down_domains_are_recognised():
    assert DA.taken_down({"status": ["client hold"]}) and DA.taken_down({"status": ["redemption period"]})
    assert not DA.taken_down({"status": ["client transfer prohibited"]})


def test_features_are_the_same_shape_for_training_and_live():
    row = DA.features(facts(), {"gname.com pte. ltd.": 0.8}, {"xyz": 0.7}, 0.3)
    assert len(row) == len(DA.FEATURES)
    d = dict(zip(DA.FEATURES, row))
    assert d["age_under_30d"] == 1 and round(d["term_years"]) == 1 and d["registrar_rate"] == 0.8 and d["tld_rate"] == 0.7
    assert DA.features({**facts(), "created": None}, {}, {}, 0.3) is None


class Fixed:
    def __init__(self, p):
        self.p = p

    def predict_proba(self, X):
        return np.array([[1 - self.p, self.p]] * len(X))


@pytest.fixture()
def model(monkeypatch):
    def install(p):
        monkeypatch.setattr(DA, "load", lambda: {"model": Fixed(p), "registrar_rates": {}, "tld_rates": {}, "prior": 0.3,
                                                 "thr_alert": 0.9, "thr_verify": 0.6, "trained_at": "test"})
    return install


def test_assess_explains_age_in_words(model):
    model(0.95)
    a = DA.assess("example-login.xyz", facts())
    assert a["level"] == "high" and a["sentences"][0].startswith("Registered 3 days ago")
    assert "1.0-year term" in a["sentences"][1]
    gone = DA.assess("x.xyz", facts(ok=False))
    assert gone["probability"] is None and "not available" in gone["sentences"][0]


@pytest.fixture()
def offline_scan(monkeypatch):
    """URL scan with every outside call replaced: DNS ok, WHOIS fails, no TLS, no threat intel, no page fetch."""
    monkeypatch.setattr(network_intel, "resolve_domain", lambda h: {"status": "ok"})
    monkeypatch.setattr(network_intel, "get_domain_age", lambda h: {"status": "error"})
    monkeypatch.setattr(network_intel, "get_ssl_info", lambda h: {"status": "error"})
    monkeypatch.setattr(threat_intelligence, "check_virustotal_url_sync", lambda u: {"status": "skipped"})
    monkeypatch.setattr(threat_intelligence, "check_urlhaus_sync", lambda u: {"status": "skipped"})
    monkeypatch.setattr(MU.settings, "LIVE_PAGE_CHECKS", False)

    def scan(url, sub, f):
        monkeypatch.setattr(F, "lookup", lambda d, use_cache=True: f)
        return MU.analyze_url(url, "SSL & Domain Analysis", subtopic_id=sub, network=True)
    return scan


def test_registry_date_fills_in_when_whois_fails(offline_scan, model):
    model(0.2)
    r = offline_scan("http://secure-verify-account.xyz/login", "redirect-analysis", facts(age_days=5))
    labels = {i["label"]: i for i in r["indicators"]}
    assert labels["Recently registered domain"]["triggered"]                        # age rule from the registry date
    assert labels["Domain registration (registry record)"]["description"].startswith("Registered 5 days ago")
    assert "subtopicModel" not in r                                                  # model only on its own pages


def test_registration_model_decides_on_its_page(offline_scan, model):
    model(0.97)
    r = offline_scan("http://secure-verify-account.xyz/login", "ssl-domain-analysis", facts(age_days=5))
    m = r["subtopicModel"]
    assert m["subtopic"] == "ssl-domain-analysis" and m["level"] == "high" and r["riskScore"] >= 71
    assert any(t.startswith("Registered 5 days ago") for t in m["tricks"])


def test_shared_hosting_and_ip_addresses_are_not_looked_up(offline_scan, monkeypatch):
    called = []
    monkeypatch.setattr(DA, "assess", lambda d, f=None: called.append(d))
    for url in ("https://my-login.web.app/x", "http://203.0.113.5/login"):
        MU.analyze_url(url, "x", subtopic_id="ssl-domain-analysis", network=True)
    assert called == []
