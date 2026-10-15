"""The six per-subtopic credential models: features, scoring rules, scanner wiring and training."""
import gzip
import os
import random
from datetime import datetime, timezone

import joblib
import numpy as np
import pytest

from app.detectors import account_takeover as A
from app.detectors import credential_features as F
from app.detectors.rba_risk import LoginEvent

DAY = 86400.0
UA_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"


def ev(ts, ip="103.21.4.5", ok=True, country="IN", asn="24560", ua=UA_WIN, user="ashis", unknown=False):
    return LoginEvent(ts=ts, user=user, ip=ip, success=ok, country=country, asn=asn, ua=ua, user_unknown=unknown)


def test_user_agent_parsing():
    assert F.parse_ua(UA_WIN)[:5] == ("Chrome", "Chrome 120", "Windows", "Windows 10", "desktop")
    assert F.parse_ua("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Version/17.2 Mobile Safari/604.1")[2:5] == \
        ("iOS", "iOS 17", "mobile")
    assert F.parse_ua("python-requests/2.31")[4:] == ("bot", 1)
    assert F.parse_ua(None) == (None, None, None, None, None, 0)


def test_unknown_values_are_minus_one_not_new():
    h = F.AccountHistory()
    h.add(ev(0))
    x = dict(zip(F.LOCATION_FEATURES, F.location_features(h, ev(DAY, country=None, asn=None), F.Tables())))
    assert x["country_new"] == -1 and x["asn_new"] == -1 and x["ip_new"] == 0


def test_history_comes_only_from_successful_logins():
    h = F.AccountHistory()
    h.add(ev(0, ip="1.1.1.1", ok=False, country="RU"))            # attacker's failed attempt
    h.add(ev(10))
    x = dict(zip(F.LOCATION_FEATURES, F.location_features(h, ev(DAY, ip="1.1.1.1", country="RU"), F.Tables())))
    assert x["country_new"] == 1 and x["ip_new"] == 1


def test_same_scoring_rule_in_training_and_scanning():
    h = F.AccountHistory()
    first = ev(0)
    assert not F.eligible("unusual-location", h, first)              # no history yet -> not judged
    assert F.eligible("failed-logins", h, first)
    h.add(first)
    assert F.eligible("unusual-location", h, ev(DAY))
    assert not F.eligible("session-activity", h, ev(3 * 3600))        # > 2 h after the last login
    assert F.eligible("session-activity", h, ev(1800))
    assert not F.eligible("unusual-location", h, ev(DAY, ok=False))   # failures are not judged here
    assert not F.eligible("behavior-changes", h, ev(DAY))             # needs 3 earlier logins


def test_spraying_model_only_judges_ips_that_tried_several_accounts():
    h = F.IPHistory()
    one = ev(0, ip="5.5.5.5", ok=False, user="a")
    assert not F.eligible("password-spraying", h, one)
    h.add(one)
    assert not F.eligible("password-spraying", h, ev(60, ip="5.5.5.5", ok=False, user="a"))
    assert F.eligible("password-spraying", h, ev(60, ip="5.5.5.5", ok=False, user="b"))


def test_scoring_never_looks_at_later_lines():
    base = [ev(i * DAY) for i in range(5)]
    later = base + [ev(10 * DAY, ip="9.9.9.9", country="RU")]
    a = [x for _, x in F.score_events("unusual-location", base, F.Tables())]
    b = [x for _, x in F.score_events("unusual-location", later, F.Tables())]
    assert b[:len(a)] == a


def test_spraying_features_count_accounts_per_ip():
    evs = [ev(i * 60, ip="5.5.5.5", ok=False, user=f"user{i}") for i in range(8)]
    rows = list(F.score_events("password-spraying", evs, F.Tables()))
    last = dict(zip(F.SPRAY_FEATURES, rows[-1][1]))
    assert last["users_1h"] == 8 and last["users_only_failed_24h"] == 8 and last["fail_ratio_24h"] == 1


# ---- scanner wiring --------------------------------------------------------------------------
class FixedModel:
    """Stands in for a trained model: returns a fixed attack probability."""

    def __init__(self, p):
        self.p = p

    def predict_proba(self, X):
        X = np.asarray(X)
        return np.column_stack([1 - np.full(len(X), self.p), np.full(len(X), self.p)])


def _bundle(sub, p, features=None):
    return {"kind": "cyberguard-credential-subtopic", "version": 1, "subtopic": sub,
            "features": features or F.SUBTOPICS[sub][0], "model": FixedModel(p), "tables": {},
            "thr_alert": 0.8, "thr_verify": 0.5, "trained_at": "test"}


LOG = "\n".join(f"2026-10-0{d} 09:1{d}:00 login success user=ashis ip=103.21.4.5 country=IN" for d in range(1, 6)) + \
      "\n2026-10-05 10:00:00 login success user=ashis ip=45.155.205.233 country=RU" + \
      "\n2026-10-05 10:01:00 login failed user=priya ip=45.155.205.233 country=RU"     # same IP, 2nd account (spraying)


@pytest.fixture()
def model_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "SUBTOPIC_MODEL_DIR", str(tmp_path))
    A._sub_cache.clear()
    return tmp_path


@pytest.mark.parametrize("sub", list(A.SUBTOPIC_INFO))
def test_each_subtopic_uses_its_own_model(model_dir, sub):
    joblib.dump(_bundle(sub, 0.95), model_dir / f"cred_{sub}.joblib")
    r = A.analyze_event({}, sub, text=LOG, subtopic_id=sub)
    assert r["subtopicModel"]["subtopic"] == sub and r["subtopicModel"]["level"] == "high"
    assert r["riskScore"] >= 71 and A.SUBTOPIC_INFO[sub][0] in r["analysisEngine"]
    assert "modelAssessment" not in r                     # the general RBA model is not mixed in


def test_medium_and_low_levels(model_dir):
    joblib.dump(_bundle("unusual-location", 0.6), model_dir / "cred_unusual-location.joblib")
    r = A.analyze_event({}, "x", text=LOG, subtopic_id="unusual-location")
    assert r["subtopicModel"]["level"] == "medium" and 51 <= r["riskScore"] <= 70
    joblib.dump(_bundle("unusual-location", 0.1), model_dir / "cred_unusual-location.joblib")
    os.utime(model_dir / "cred_unusual-location.joblib", (1, 1))       # force reload
    r = A.analyze_event({}, "x", text=LOG, subtopic_id="unusual-location")
    assert r["subtopicModel"]["level"] == "low" and r["riskScore"] < 26


def test_model_never_lowers_what_the_rules_found(model_dir):
    joblib.dump(_bundle("failed-logins", 0.01), model_dir / "cred_failed-logins.joblib")
    brute = "\n".join(f"Oct 13 02:11:{i:02d} srv sshd[1]: Failed password for root from 45.155.205.233 port 22 ssh2"
                      for i in range(20)) + "\nOct 13 02:12:00 srv sshd[1]: Accepted password for root from 45.155.205.233 port 22 ssh2"
    r = A.analyze_event({}, "x", text=brute, subtopic_id="failed-logins")
    assert r["riskScore"] >= 90 and r["subtopicModel"]["level"] == "low"


def test_missing_or_mismatched_model_falls_back_safely(model_dir):
    r = A.analyze_event({}, "x", text=LOG, subtopic_id="unknown-device")
    assert "subtopicModel" not in r                       # no file -> rules (+ general model) as before
    joblib.dump(_bundle("unknown-device", 0.99, features=["something", "else"]), model_dir / "cred_unknown-device.joblib")
    r = A.analyze_event({}, "x", text=LOG, subtopic_id="unknown-device")
    assert "subtopicModel" not in r                       # features from another code version -> refused


# ---- training end to end on a small made-up file (the real data is far too big for tests) --------
def _write_subsets(tmp_path):
    rnd = random.Random(1)
    acc = ["ts,user,ip,country,region,city,asn,ua,browser,os,device,success,attack,ato"]
    ipr = ["ts,user,ip,success,attack,ua,device"]
    t0 = 1_580_000_000
    for u in range(300):
        home = f"10.{u % 20}.0.1"                 # ~15 accounts share each office / mobile IP
        for k in range(24):                       # two logins a day, ~30 min apart (sessions)
            t = t0 + u * 37 + (k // 2) * 86400 + (k % 2) * 1800 + rnd.randint(0, 600)
            attack = rnd.random() < 0.15
            ip = f"45.{rnd.randint(0, 9)}.1.1" if attack else home     # attackers reuse a few IPs
            c = "US" if attack else "NO"
            ua = "python-requests/2.31" if attack else UA_WIN
            ok = rnd.random() < (0.3 if attack else 0.95)
            ts = datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            row = [ts, f"u{u}", ip, c, "-", "-", "64500" if attack else "29695", f'"{ua}"', "x", "x", "x",
                   str(ok), str(attack), "False"]
            acc.append(",".join(row))
            ipr.append(",".join([ts, f"u{u}", ip, str(ok), str(attack), f'"{ua}"', "x"]))
    for name, lines in (("acc.csv.gz", acc), ("ip.csv.gz", ipr)):
        with gzip.open(tmp_path / name, "wt") as f:
            f.write("\n".join(lines) + "\n")
    return tmp_path / "acc.csv.gz", tmp_path / "ip.csv.gz"


def test_training_writes_six_separate_models(tmp_path, monkeypatch):
    import sys
    from app.ml.training import train_credential_subtopics as T
    acc, ipf = _write_subsets(tmp_path)
    out = tmp_path / "models"
    monkeypatch.setattr(sys, "argv", ["x", "--accounts", str(acc), "--ips", str(ipf), "--out", str(out), "--quick"])
    T.main()
    for sub in F.SUBTOPICS:
        b = joblib.load(out / f"cred_{sub}.joblib")
        assert b["subtopic"] == sub and b["features"] == F.SUBTOPICS[sub][0] and 0 < b["thr_verify"] <= b["thr_alert"] <= 1
        assert (out / f"cred_{sub}.metrics.json").exists()
