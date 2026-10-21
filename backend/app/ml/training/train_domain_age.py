"""
Train the domain REGISTRATION model (SSL & Domain Analysis) from data/domain_facts.jsonl
(collected on your PC by collect_domain_facts.py).

Model: HistGradientBoosting (scikit-learn) on registry facts: domain age, registration term, days to expiry,
registrar and TLD history (smoothed, learned from the training part only), name-server provider, DNSSEC,
registry / registrar locks. See app/detectors/domain_age.py.

Honest test: 25% of domains (fixed hash of the name) are never trained on. Alert level = only 1% of REAL test-
calibration domains reach it, verify level = 5% (chosen on a separate calibration part, reported on the rest).

v2 (21 Oct 2026) - FRESH phishing only:
  * phishing side = domains looked up while the phishing was live: OpenPhish feed runs and urlscan.io scans
    (collect_domain_facts --openphish / --input urlscan_phish_domains.csv). The old Phishing.Database list is left
    out by default (--include-old to use it): those domains were looked up months after the attack, so their
    "age" is not the age a victim would have seen.
  * urlscan domains: age measured ON THE DAY THEY WERE SCANNED (the date is in the "source" field), not today.
  * a fresh phishing domain that a registrar took down AFTER the scan is kept (it was live when it mattered); only
    its takedown status is removed. Real sites that are taken down are still skipped.
  Measured on 5 different splits (mean): AUC 0.915, alert catches 56% of fresh phishing domains at 1.0% false
  alarms on real sites, verify catches 68% at 5.2% (v1: 8% / 35%).

Run from backend/:   python -m app.ml.training.train_domain_age
Output: app/ml/models/domain_age.joblib + domain_age.metrics.json
"""
import argparse
import hashlib
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score

from app.detectors import domain_age as DA
from app.detectors import domain_facts

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
MODELS = os.path.join(HERE, "..", "models")


def part(domain):          # 0-99, stable
    return int(hashlib.sha1(domain.encode()).hexdigest(), 16) % 100


def rates(rows, key, m=20.0):
    tot, bad = defaultdict(int), defaultdict(int)
    for r in rows:
        k = key(r)
        tot[k] += 1
        bad[k] += r["label"]
    prior = sum(r["label"] for r in rows) / max(len(rows), 1)
    return {k: (bad[k] + m * prior) / (tot[k] + m) for k in tot if k}, prior


def kind(r):
    src = str(r.get("source") or "")
    if src.startswith("urlscan"):
        return "urlscan"
    if "openphish" in src.lower():
        return "openphish"
    return "old_phishing" if int(r.get("label", 0)) == 1 else "real"


def at_scan_time(r):
    """urlscan rows: measure the domain as it was on the day it was scanned (age, days to expiry)."""
    m = re.search(r"scanned (\d{4}-\d{2}-\d{2})", str(r.get("source") or ""))
    if m:
        r = dict(r, checked_at=m.group(1) + "T12:00:00+00:00")
    return r


def report(p, y, ta, tv):
    out = {"n": int(len(y)), "phishing": int(y.sum()), "real": int((1 - y).sum())}
    if 0 < y.sum() < len(y):
        out["auc"] = round(float(roc_auc_score(y, p)), 4)
    out.update(caught_at_alert=round(float((p[y == 1] >= ta).mean()), 4),
               false_alarms_at_alert=round(float((p[y == 0] >= ta).mean()), 4),
               caught_at_verify=round(float((p[y == 1] >= tv).mean()), 4),
               false_alarms_at_verify=round(float((p[y == 0] >= tv).mean()), 4))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(DATA, "domain_facts.jsonl"))
    ap.add_argument("--out", default=MODELS)
    ap.add_argument("--include-old", action="store_true",
                    help="also use the old Phishing.Database domains (looked up long after the attack)")
    a = ap.parse_args()
    rows, seen = [], set()
    skipped, used = defaultdict(int), defaultdict(int)
    for line in open(a.data, encoding="utf-8"):
        r = json.loads(line)
        if r["domain"] in seen:
            continue
        seen.add(r["domain"])
        r["label"] = int(r["label"])
        k = kind(r)
        fresh = k in ("urlscan", "openphish")
        if k == "old_phishing" and not a.include_old:
            skipped["old phishing list (age measured long after the attack) - use --include-old"] += 1
            continue
        if not r.get("ok"):
            skipped["no registry record (deleted / no RDAP)"] += 1
            continue
        r = at_scan_time(r)
        if DA.taken_down(r):
            if not fresh:
                skipped["already taken down (hold / redemption / pending delete)"] += 1
                continue
            r["status"] = [x for x in (r.get("status") or []) if not any(t in x for t in DA.TAKEDOWN_STATUS)]
        if domain_facts.age_days(r) is None:
            skipped["no registration date"] += 1
            continue
        rows.append(r)
        used[k] += 1
    train = [r for r in rows if part(r["domain"]) >= 25]
    calib = [r for r in rows if part(r["domain"]) < 12]
    test = [r for r in rows if 12 <= part(r["domain"]) < 25]
    reg_rates, prior = rates(train, lambda r: (r.get("registrar") or "").strip().lower())
    tld_rates, _ = rates(train, lambda r: r["domain"].rsplit(".", 1)[-1].lower())

    def xy(rs):
        return (np.array([DA.features(r, reg_rates, tld_rates, prior) for r in rs], dtype=float),
                np.array([r["label"] for r in rs]))
    Xtr, ytr = xy(train)
    Xc, yc = xy(calib)
    Xt, yt = xy(test)
    model = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.05, max_leaf_nodes=15, l2_regularization=1.0,
                                           class_weight="balanced", random_state=42).fit(Xtr, ytr)
    pc, pt = model.predict_proba(Xc)[:, 1], model.predict_proba(Xt)[:, 1]
    ta = float(np.quantile(pc[yc == 0], 0.99))
    tv = float(min(np.quantile(pc[yc == 0], 0.95), ta))
    # age alone, for comparison (younger = more suspicious)
    age_only = -Xt[:, 0]
    results = {"calibration": report(pc, yc, ta, tv), "test": report(pt, yt, ta, tv),
               "age_only_auc_test": round(float(roc_auc_score(yt, age_only)), 4)}
    young = Xt[:, 2] == 1
    if young.any():
        results["test_domains_under_1_year"] = report(pt[young], yt[young], ta, tv)
    bundle = {"kind": DA.KIND, "version": 2, "features": DA.FEATURES, "model": model, "registrar_rates": reg_rates,
              "tld_rates": tld_rates, "prior": prior, "thr_alert": ta, "thr_verify": tv,
              "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    os.makedirs(a.out, exist_ok=True)
    joblib.dump(bundle, os.path.join(a.out, "domain_age.joblib"), compress=3)
    info = {"model": "HistGradientBoosting on RDAP registry facts", "features": DA.FEATURES,
            "rows": {"train": len(train), "calibration": len(calib), "test": len(test)}, "used": dict(used),
            "skipped": dict(skipped),
            "thr_alert": ta, "thr_verify": tv, "results": results, "trained_at": bundle["trained_at"],
            "data": "registry records (RDAP): FRESH phishing domains (OpenPhish feed, urlscan.io scans; age at scan "
                    "time) vs Tranco top-1M real sites" + (" + old Phishing.Database list" if a.include_old else "")}
    with open(os.path.join(a.out, "domain_age.metrics.json"), "w") as f:
        json.dump(info, f, indent=2)
    print(json.dumps(info, indent=2))
    return info


if __name__ == "__main__":
    main()
