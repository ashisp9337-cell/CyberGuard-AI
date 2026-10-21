"""Live-check fixes (20 Oct): no wmic warning on Windows, no WHOIS socket noise, and online URL checks that do not
wait for a slow WHOIS server when the registry (RDAP) already gave the registration date."""
import logging
import time

from app import _quiet_cpu_count
from app.detectors import malicious_url as M
from app.services import network_intel


# ---- Fix 2: joblib / scikit-learn "wmic" warning on Windows 11 ------------------------------------------------------
def test_windows_gets_a_core_count_so_no_wmic_lookup_is_needed():
    env = {}
    _quiet_cpu_count("win32", env, 8)
    assert env == {"LOKY_MAX_CPU_COUNT": "4"}


def test_a_value_set_by_the_user_is_kept_and_other_systems_are_untouched():
    env = {"LOKY_MAX_CPU_COUNT": "3"}
    _quiet_cpu_count("win32", env, 8)
    assert env["LOKY_MAX_CPU_COUNT"] == "3"
    env = {}
    _quiet_cpu_count("linux", env, 8)
    assert env == {}


def test_with_the_setting_joblib_never_runs_the_core_lookup(monkeypatch):
    import warnings
    from joblib.externals.loky.backend import context as C
    calls = []
    monkeypatch.setattr(C, "physical_cores_cache", None)
    monkeypatch.setattr(C, "_count_physical_cores", lambda: (calls.append(1), ("not found", FileNotFoundError(2, "wmic")))[1])
    monkeypatch.setattr(C.os, "cpu_count", lambda: 8)
    env = {}
    _quiet_cpu_count("win32", env, 8)
    monkeypatch.setenv("LOKY_MAX_CPU_COUNT", env["LOKY_MAX_CPU_COUNT"])
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert 1 <= C.cpu_count(only_physical_cores=True) <= 4
    assert calls == [] and caught == []


# ---- Fix 3: WHOIS library noise ---------------------------------------------------------------------------------------
def test_whois_socket_messages_are_hidden_but_our_own_warnings_are_not():
    assert not logging.getLogger("whois.whois").isEnabledFor(logging.ERROR)     # the library's socket errors
    assert logging.getLogger("app.services.network_intel").isEnabledFor(logging.WARNING)


# ---- Fix 8: do not wait for a slow WHOIS server when the registry answered ------------------------------------------
def _fake_network(monkeypatch, whois_seconds, registry):
    monkeypatch.setattr(network_intel, "resolve_domain", lambda h: {"status": "ok", "ips": ["203.0.113.5"]})
    monkeypatch.setattr(network_intel, "get_ssl_info", lambda h: {"status": "unavailable", "reason": "test"})
    def slow_whois(h):
        time.sleep(whois_seconds)
        return {"status": "ok", "age_days": 4000}
    monkeypatch.setattr(network_intel, "get_domain_age", slow_whois)
    monkeypatch.setattr(M.threat_intelligence, "check_virustotal_url_sync", lambda u: {"status": "needs_key"})
    monkeypatch.setattr(M.threat_intelligence, "check_urlhaus_sync", lambda u: {"status": "needs_key"})
    monkeypatch.setattr(M, "_registry", lambda h: registry)


def test_registry_date_means_no_waiting_for_whois(monkeypatch):
    _fake_network(monkeypatch, 3.0, {"ageDays": 2, "sentences": ["Registered 2 days ago"]})
    t0 = time.time()
    inds = M._live_indicators("http://new-login-check.top/")
    assert time.time() - t0 < 1.0                                       # did not wait the 3 s of WHOIS
    assert any(i["label"] == "Recently registered domain" and i["triggered"] for i in inds)   # registry age used


def test_whois_is_still_used_when_the_registry_has_no_date(monkeypatch):
    _fake_network(monkeypatch, 0.2, None)
    inds = M._live_indicators("http://old-site-example.in/")
    labels = {i["label"]: i["triggered"] for i in inds}
    assert labels.get("Recently registered domain") is False          # WHOIS age (4000 days) was used


# ---- Fix 4: crypto-wallet and other often-phished brands -------------------------------------------------------------
import pytest  # noqa: E402

from app.detectors import url_features_v2 as F  # noqa: E402
from app.detectors import brand_text  # noqa: E402


def offline(url):
    return M.analyze_url(url, "Malicious URL", subtopic_id="malicious-url", network=False)["riskScore"]


@pytest.mark.parametrize("host,brand", [("imtouken.com", "imtoken"), ("robiox.com", "roblox"),
                                        ("trezr-suite.com", "trezor"), ("ledger-live-verify.com", "ledger"),
                                        ("allegrolokalnie-oferta.shop", "allegro"), ("kucoin-support.xyz", "kucoin"),
                                        ("trustwallet-verify.app", "trustwallet"), ("xfinity-login.help", "xfinity")])
def test_look_alikes_of_the_new_brands_are_recognised(host, brand):
    assert F.brand_in_host(host) == brand
    assert offline(f"https://{host}/") >= 51, host


@pytest.mark.parametrize("host", ["token.im", "trustwallet.com", "trezor.io", "ledger.com", "roblox.com", "rbxcdn.com",
                                  "allegro.pl", "allegro.cz", "kucoin.com", "opensea.io", "uniswap.org", "wazirx.com",
                                  "coindcx.com", "comcast.net", "xfinity.com"])
def test_the_real_sites_of_the_new_brands_are_not_look_alikes(host):
    assert F.brand_in_host(host) is None
    assert offline(f"https://{host}/") < 51, host


@pytest.mark.parametrize("host", ["tallyledger.com", "generalledger.co.in", "allegromusic.com"])
def test_everyday_words_ledger_and_allegro_need_a_whole_word(host):
    assert F.brand_in_host(host) is None


def test_ledger_and_allegro_in_normal_text_are_not_brand_claims():
    assert brand_text.find_brands("Please update the ledger and play it allegro") == []
    assert brand_text.find_brands("Verify your Ledger Live and Trust Wallet now") == ["ledger", "trustwallet"]
