"""Credential theft / account takeover: the RBA risk model, its training script, and its use in scans."""
import csv
import random
import subprocess
import sys
from datetime import datetime, timedelta

import joblib
import pytest

from app.detectors import account_takeover, rba_risk
from app.detectors.rba_risk import GlobalTables, LoginEvent, RiskState

BASE = 1_700_000_000


def _ev(day, user="asha", ip="10.0.0.5", country="IN", asn="9829", dev="desktop", os_="Windows 10", br="Chrome 120", ok=True):
    return LoginEvent(BASE + day * 86400, user, ip, ok, country, None, None, asn, None, dev, os_, br)


def _tables(events):
    t = GlobalTables()
    for e in events:
        t.add(rba_risk.event_values(e))
    return t


# ---- the risk score ----------------------------------------------------------------------
def test_values_are_normalised_like_the_dataset():
    v = rba_risk.values_from_fields("NO", "AS29695", "1.2.3.4", "mobile", "iOS 13.4", "Chrome Mobile 81.0.4044")
    assert v["asn"] == "29695" and v["os"] == "ios 13" and v["browser"] == "chrome mobile 81" and v["country"] == "no"
    assert rba_risk.values_from_fields(country="-")["country"] is None
    dev, os_, br = rba_risk.client_from_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36")
    assert (dev, os_, br) == ("desktop", "windows 10", "chrome 120")
    assert rba_risk.client_from_ua("python-requests/2.31")[0] == "bot"


def test_no_history_means_no_account_side_risk_and_no_future_leak():
    st = RiskState(_tables([_ev(0)]))
    assert st.step(_ev(0))[0] == 0.0                      # first login: nothing to compare with
    same = st.step(_ev(1))[0]
    assert same == 0                                      # usual place and device -> nothing unusual


def test_new_country_and_device_raise_risk_more_than_new_ip_at_same_provider():
    history = [_ev(d) for d in range(10)]
    st = RiskState(_tables(history))
    for e in history:
        st.step(e)
    same = st.score(_ev(11))[0]
    new_ip = st.score(_ev(11, ip="10.0.0.77"))[0]
    new_browser = st.score(_ev(11, br="Firefox 115"))[0]
    takeover, parts = st.score(_ev(11, ip="91.240.118.2", country="RU", asn="48693", dev="mobile", os_="Android 9"))
    assert takeover > new_browser >= same and takeover > new_ip >= same and takeover > 0
    # a familiar browser must not cancel a never-seen country (attackers copy User-Agent strings)
    copied_browser = st.score(_ev(11, ip="5.188.62.140", country="NL", asn="49453"))[0]
    new_phone = st.score(_ev(11, dev="mobile", os_="Android 9", br="Chrome Mobile 80"))[0]
    assert copied_browser > 0 and new_phone > 0
    assert rba_risk.explain(parts, rba_risk.event_values(_ev(11, country="RU")))[0].startswith("country never used")


def test_failed_logins_and_unknown_accounts_do_not_become_history():
    st = RiskState(_tables([_ev(0)]))
    st.update(_ev(0, ok=False))
    st.update(LoginEvent(BASE, "ghost", "1.1.1.1", True, user_unknown=True))
    assert not st.has_history("asha") and not st.has_history("ghost")


def test_reputation_uses_attacker_frequencies():
    everyone = [_ev(d, user=f"u{d}") for d in range(50)] + [_ev(d, user=f"x{d}", country="RO", asn="9009") for d in range(50)]
    attackers = [_ev(d, user=f"x{d}", country="RO", asn="9009") for d in range(40)]
    g, a = _tables(everyone), _tables(attackers)
    ro = rba_risk.reputation(rba_risk.event_values(_ev(0, country="RO", asn="9009")), g, a)
    india = rba_risk.reputation(rba_risk.event_values(_ev(0, dev=None)), g, a)
    assert ro[0] > 0 and india[0] == 0 and ro[1] == "country"
    win = "2026-10-07 02:10:00 EventID=4625 Account Name: priya Source Network Address: 45.9.148.21 Failure Reason: Unknown user name or bad password"
    assert not account_takeover.events_from_log(win)[0].user_unknown   # generic Windows wording, account may exist
    never_seen = rba_risk.reputation(rba_risk.event_values(_ev(0, country="ZZ", asn=None, dev=None)), g, a)
    assert never_seen == (0.0, None, 0)                    # no evidence -> not scored at all
    own = rba_risk.reputation(rba_risk.event_values(_ev(0, country="RO", asn="9009")), g, a,
                              seen_paths={(("country", "ro"),), (("country", "ro"), ("asn", "9009")), (("device_type", "desktop"),)})
    assert own[0] == 0                                     # the account always logs in from there


# ---- log parsing ---------------------------------------------------------------------------
def test_log_lines_become_events_for_ssh_and_windows():
    log = ("Oct  7 03:12:01 srv sshd[1]: Failed password for invalid user admin from 45.155.205.10 port 1 ssh2\n"
           "Oct  7 03:12:09 srv sshd[1]: Accepted password for root from 45.155.205.10\n"
           "2026-10-07 02:10:30 EventID=4624 Account Name: priya Source Network Address: 203.0.113.9 London\n"
           "2026-10-07 02:11:30 sign-in success user=ravi ip=1.2.3.4 country=ro ASN=AS9009")
    ev = {e.user: e for e in account_takeover.events_from_log(log)}
    assert ev["admin"].user_unknown and not ev["admin"].success
    assert ev["root"].success and not ev["root"].user_unknown
    assert ev["priya"].country == "GB" and ev["priya"].city == "London"
    assert ev["ravi"].country == "RO" and ev["ravi"].asn == "9009"


def test_invalid_user_attempts_rule():
    text = "\n".join(f"Oct  7 03:12:{i:02d} sshd[1]: Failed password for invalid user u{i} from 45.1.1.1 port 2 ssh2" for i in range(4))
    r = account_takeover.analyze_event({}, "Multiple Failed Login Attempts", text=text)
    assert any(i["label"] == "Logins to accounts that do not exist" and i["triggered"] for i in r["indicators"])


def _labels(r):
    return {i["label"] for i in r["indicators"] if i["triggered"]}


def test_guessing_non_existent_usernames_is_not_password_spraying():
    text = "\n".join(f"Oct  7 04:0{i}:10 srv sshd[901]: Failed password for invalid user {u} from 45.155.205.10 port 4{i}11 ssh2"
                     for i, u in enumerate(["oracle", "test", "guest", "ubuntu", "pi"]))
    r = account_takeover.analyze_event({}, "Multiple Failed Login Attempts", text=text)
    assert "Password spraying" not in _labels(r)
    assert {"Multiple failed login attempts", "Logins to accounts that do not exist"} <= _labels(r)
    assert 26 <= r["riskScore"] <= 50


def test_spraying_needs_real_accounts():
    real = [f"Oct  7 03:12:0{i} srv sshd[1]: Failed password for {u} from 185.1.1.1 port 1 ssh2" for i, u in enumerate(["asha", "ravi"])]
    fake = [f"Oct  7 03:13:0{i} srv sshd[1]: Failed password for invalid user {u} from 185.1.1.1 port 1 ssh2" for i, u in enumerate(["test", "pi", "oracle"])]
    assert "Password spraying" in _labels(account_takeover.analyze_event({}, "x", text="\n".join(real + fake)))


# ---- training script on a tiny RBA-shaped file ------------------------------------------------
HEADER = ["index", "Login Timestamp", "User ID", "Round-Trip Time [ms]", "IP Address", "Country", "Region", "City",
          "ASN", "User Agent String", "Browser Name and Version", "OS Name and Version", "Device Type",
          "Login Successful", "Is Attack IP", "Is Account Takeover"]


def _fake_rba(path):
    r = random.Random(3)
    base = datetime(2020, 2, 3)
    rows = []
    users = [str(r.getrandbits(40)) for _ in range(300)]
    for u in users:
        for _ in range(r.randint(3, 15)):
            t = base + timedelta(days=r.uniform(0, 200), hours=r.choice([8, 9, 10, 11]))
            rows.append([t, u, 100, f"10.0.{hash(u) % 200}.1", "NO", "-", "-", "29695", "Mozilla/5.0 Chrome",
                         "Chrome 80.0.1", "Windows 10", "desktop", r.random() > 0.05, False, False])
    for k in range(12):
        ip, t0 = f"185.9.{k}.1", base + timedelta(days=r.uniform(0, 200))
        for j in range(60):
            rows.append([t0 + timedelta(seconds=j * 7), r.choice(users), "", ip, "RU", "-", "-", "9009",
                         "python-requests/2", "Other", "Linux", "bot", j % 20 == 0, True, False])
    victim = users[0]
    rows.append([base + timedelta(days=199), victim, "", "91.1.1.1", "RU", "-", "-", "9009", "Mozilla/5.0 Firefox",
                 "Firefox 100.0", "Android 9", "mobile", True, False, True])
    for j in range(5):
        rows.append([base + timedelta(days=50, seconds=j), "-4324475583306591935", "", "5.5.5.5", "NO", "-", "-",
                     "29695", "Mozilla/5.0", "Chrome 80.0", "Windows 10", "desktop", False, False, False])
    rows.sort(key=lambda x: x[0])
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        for i, row in enumerate(rows):
            w.writerow([i, row[0].strftime("%Y-%m-%d %H:%M:%S.000")] + row[1:])


@pytest.fixture(scope="module")
def trained_model(tmp_path_factory):
    d = tmp_path_factory.mktemp("rba")
    data, out = d / "rba-dataset.csv", d / "ato_test_model.joblib"
    _fake_rba(data)
    res = subprocess.run([sys.executable, "-m", "app.ml.training.train_ato_login", "--data", str(data),
                          "--out", str(out), "--user-sample", "1.0", "--simulate-every", "1"],
                         capture_output=True, text=True, timeout=300)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "calibrated on the first 80% of time" in res.stdout
    return out


def test_training_writes_model_and_report(trained_model):
    bundle = joblib.load(trained_model)
    assert bundle["kind"] == rba_risk.BUNDLE_KIND and len(bundle["history_quantiles"]) == 1001
    m = bundle["card"]["metrics"]
    assert m["account_side"]["simulated_attacker_naive"]["roc_auc"] > 0.9
    assert m["account_takeover_rows"]["rows"] == 1
    assert m["rule_check"]["attempts_on_non_existent_accounts"]["attempts"] == 5
    assert bundle["card"]["scenarios"]["same account, new country + network + device (should be HIGH)"]["flagged"]
    assert trained_model.with_name(trained_model.name.replace(".joblib", ".metrics.json")).exists()


# ---- model inside the scanner -----------------------------------------------------------------
UA = '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36"'
NORMAL = "\n".join(f"2026-10-{d:02d} 09:00:00 sign-in success user=asha ip=10.0.0.5 country=IN ASN=AS9829 ua={UA}"
                   for d in range(1, 15))
TAKEOVER = NORMAL + "\n2026-10-20 03:11:00 sign-in success user=asha ip=91.240.118.2 country=RU ASN=AS48693 ua=\"python-requests/2.31\""
SPRAY = "\n".join(f"2026-10-07 03:12:{i:02d} sshd[1]: Failed password for user{i} from 185.220.101.4 port 4{i} ssh2"
                  for i in range(30))


@pytest.fixture()
def with_model(trained_model, monkeypatch):
    monkeypatch.setattr(account_takeover, "MODEL_PATH", str(trained_model))
    account_takeover._model_cache.clear()
    yield
    account_takeover._model_cache.clear()


def test_scan_flags_login_unusual_for_the_account(with_model):
    r = account_takeover.analyze_event({}, "Unusual Location Login", text=TAKEOVER)
    ma = r["modelAssessment"]
    assert "RBA Risk Model" in r["analysisEngine"] and ma["loginsFlagged"] >= 1 and ma["historyPercentile"] >= 99
    assert any("country never used" in x for x in ma["reasons"])
    assert r["riskScore"] >= 50


def test_scan_normal_logins_stay_low(with_model):
    r = account_takeover.analyze_event({}, "Unusual Location Login", text=NORMAL)
    assert r["modelAssessment"]["loginsFlagged"] == 0 and r["riskScore"] <= 25


def test_model_never_lowers_rule_findings(with_model):
    text = NORMAL + "\nMFA was disabled and a mail forwarding rule to x@evil.test was created"
    assert account_takeover.analyze_event({}, "Sudden Account Behavior Changes", text=text)["riskScore"] >= 71
    assert account_takeover.analyze_event({}, "Password Spraying Detection", text=SPRAY)["riskScore"] >= 71


def test_without_model_rules_still_work(monkeypatch, tmp_path):
    monkeypatch.setattr(account_takeover, "MODEL_PATH", str(tmp_path / "missing.joblib"))
    account_takeover._model_cache.clear()
    r = account_takeover.analyze_event({}, "Password Spraying Detection", text=SPRAY)
    assert "modelAssessment" not in r and "RBA Risk Model" not in r["analysisEngine"]
    assert r["riskScore"] >= 71   # spraying rule


def test_old_or_foreign_model_file_is_refused(monkeypatch, tmp_path):
    p = tmp_path / "old.joblib"
    joblib.dump({"model": None, "features": ["hour_sin"], "threshold": 0.5}, p)   # the earlier classifier format
    monkeypatch.setattr(account_takeover, "MODEL_PATH", str(p))
    account_takeover._model_cache.clear()
    assert "modelAssessment" not in account_takeover.analyze_event({}, "x", text=TAKEOVER)
    account_takeover._model_cache.clear()


def test_medium_level_asks_for_verification(monkeypatch):
    """Between the 95th and 99th percentile the login is not 'safe': step-up verification, risk 40-55."""
    fake = {"event": LoginEvent(BASE, "priya", "5.188.62.140", True, "NL"), "percentile": 96.1, "historyPercentile": 96.1,
            "reputationPercentile": None, "flagged": False, "elevated": True, "level": "medium", "alert": 99.0,
            "medium": 95.0, "events": 7, "flagged_count": 0, "elevatedCount": 1, "withHistory": 6,
            "reasons": ["country never used by this account before (nl)"]}
    fake["flagged"] = 0
    monkeypatch.setattr(account_takeover, "model_assessment", lambda text: fake)
    r = account_takeover.analyze_event({}, "Unusual Location Login", text="2026-10-07 09:20:00 sign-in success user=priya")
    ind = [i for i in r["indicators"] if i["label"].startswith("Risk-based authentication model")][0]
    assert ind["triggered"] and "verify" in ind["label"] and ind["severity"] == "medium"
    assert 40 <= r["riskScore"] <= 55 and r["modelAssessment"]["level"] == "medium"
