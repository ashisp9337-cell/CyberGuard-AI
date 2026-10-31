"""Upgrade #7 (31 Oct): the credential trainer saves a model only if it beats the installed one on the same test accounts;
otherwise no model file changes. Real attacker logins are judged by kind (first / same attacker again / takeover)."""
import hashlib
import sys

import numpy as np

from app.ml.training import train_credential_subtopics as T
from test_credential_subtopics import _write_subsets  # noqa: E402


def _digest(folder):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.glob("*.joblib"))}


def test_retraining_on_the_same_data_changes_no_model(tmp_path, monkeypatch):
    acc, ipf = _write_subsets(tmp_path)
    out = tmp_path / "models"
    argv = ["x", "--accounts", str(acc), "--ips", str(ipf), "--out", str(out), "--quick"]
    monkeypatch.setattr(sys, "argv", argv)
    T.main()                                              # first run: nothing installed -> saved
    before = _digest(out)
    assert before
    T.main()                                              # same data again: not better -> nothing replaced
    assert _digest(out) == before
    assert list(out.glob("*.rejected.metrics.json"))      # the reason is written next to them


def test_keep_rule():
    old = {"test": {"roc_auc": 0.90, "false_alarm_at_alert": 0.010},
           "real_attacker_logins_by_kind": {"first": {"roc_auc": 0.50}}}
    good = {"test": {"roc_auc": 0.895, "false_alarm_at_alert": 0.011},
            "real_attacker_logins_by_kind": {"first": {"roc_auc": 0.70}}}
    assert T.better(good, old, sim=True)[0]
    more_alarms = {**good, "test": {"roc_auc": 0.95, "false_alarm_at_alert": 0.02}}
    assert not T.better(more_alarms, old, sim=True)[0]
    sim_drop = {**good, "test": {"roc_auc": 0.85, "false_alarm_at_alert": 0.010}}
    assert not T.better(sim_drop, old, sim=True)[0]
    assert T.better(good, None, sim=True)[0]              # nothing installed yet


def test_real_logins_are_split_by_kind():
    c = np.array(["normal"] * 4 + ["first", "repeat", "ato"])
    p = np.array([0.1, 0.2, 0.3, 0.4, 0.9, 0.15, 0.8])
    k = T.real_kinds(None, p, c, 0.5, 0.35)
    assert k["first"]["roc_auc"] == 1.0 and k["repeat"]["roc_auc"] == 0.25 and k["ato"]["caught_at_alert"] == 1.0
