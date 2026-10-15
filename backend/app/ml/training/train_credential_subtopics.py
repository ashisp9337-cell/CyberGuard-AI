"""
Train one model per Credential Theft & Account Takeover subtopic (six separate models).

Data: the two subsets of the RBA login dataset made by extract_rba_subsets.py
      ("Login Data Set for Risk-Based Authentication", Wiefling et al., CC BY 4.0 -- 31M real-world logins)
  * rba_accounts_subset.csv.gz -- complete login histories of ~10% of accounts
  * rba_ip_subset.csv.gz       -- complete activity of ~10% of IP addresses

Model for every subtopic: HistGradientBoostingClassifier (gradient-boosted decision trees, scikit-learn).
Features: app/detectors/credential_features.py (the scanner uses the very same code).

What each model learns to recognise ("positive") and how the examples are made:
  failed-logins      attempts that came from attacker IPs (real label "Is Attack IP")
  password-spraying  attempts from attacker IPs, seen from the IP side (real label)
  unusual-location   a login of a real account from a real attacker's IP / country / network, compared
                     with the account's real history  ("simulated attacker" -- the evaluation method of the
                     RBA papers, Freeman et al. 2016 / Wiefling et al. 2019, because confirmed takeovers are rare)
  unknown-device     the same, with a real attacker's browser / OS / device
  session-activity   a real attacker login placed 2-110 minutes after a real login of the account
                     (a second, parallel session from somewhere else)
  behavior-changes   a real attacker login at the attacker's real time of day
  Negatives: the accounts' real, normal logins.
Accounts and IPs are split 70% train / 10% calibration (alert levels) / 20% test -- a model is always
tested on accounts and IPs it has never seen. Logs pasted by users often lack country/ASN/user agent,
so some accounts are trained with those fields blanked out.

Run from backend/ (about 10-20 minutes):
    python -m app.ml.training.train_credential_subtopics

Output: app/ml/models/cred_<subtopic>.joblib  +  cred_<subtopic>.metrics.json
"""
import argparse
import json
import math
import os
import random
import sys
import time
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

from app.detectors import credential_features as F

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
MODELS_DIR = os.path.join(HERE, "..", "models")
SEED = 42
MAX_UNITS = 600_000          # per subtopic and split (keeps training to minutes on a laptop)
TABLE_FIELDS = ["country", "asn", "bfam", "bver", "ofam", "over", "dtype", "ua"]


class Ev:
    __slots__ = ("ts", "user", "ip", "success", "country", "region", "city", "asn", "ua", "user_unknown", "attack", "ato")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    def copy(self, **changes):
        e = Ev(**{k: getattr(self, k) for k in self.__slots__})
        for k, v in changes.items():
            setattr(e, k, v)
        return e


def _clean(v):
    v = str(v).strip() if v is not None else ""
    return None if v in ("", "-", "nan", "None", "NaN") else v


def _split(key: str) -> str:
    """Stable 70/10/20 split by account or IP."""
    b = int(pd.util.hash_array(np.array([key], dtype=object), categorize=False)[0] % 100)
    return "train" if b < 70 else "calib" if b < 80 else "test"


def load(path, ip_file=False):
    t0 = time.time()
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    ts = pd.to_datetime(df["ts"], format="mixed", utc=True)
    df["t"] = (ts.astype("int64") // 10**6) / 1000.0
    df = df.sort_values("t", kind="stable")
    out = []
    unknown_id = "-4324475583306591935"
    cols = df.columns
    for r in df.itertuples(index=False):
        d = r._asdict()
        out.append(Ev(ts=d["t"], user=d["user"], ip=_clean(d["ip"]), success=d["success"].lower() == "true",
                      country=_clean(d.get("country")) if "country" in cols else None,
                      region=_clean(d.get("region")) if "region" in cols else None,
                      city=_clean(d.get("city")) if "city" in cols else None,
                      asn=_clean(d.get("asn")) if "asn" in cols else None, ua=_clean(d.get("ua")),
                      user_unknown=d["user"] == unknown_id, attack=d["attack"].lower() == "true",
                      ato=(d.get("ato", "False") or "False").lower() == "true"))
    print(f"  {os.path.basename(path)}: {len(out):,} rows ({time.time() - t0:.0f}s)")
    return out


def mask_mode(user: str) -> int:
    """0 = all fields, 1 = no country/region/city/ASN, 2 = no user agent, 3 = neither (IP + time only)."""
    b = int(pd.util.hash_array(np.array([user + "#mask"], dtype=object), categorize=False)[0] % 10)
    return 0 if b < 5 else 1 if b < 7 else 2 if b < 9 else 3


def apply_mask(e, mode):
    if mode in (1, 3):
        e = e.copy(country=None, region=None, city=None, asn=None)
    if mode in (2, 3):
        e = e.copy(ua=None)
    return e


def metrics(y, p, thr_alert, thr_verify):
    y, p = np.asarray(y), np.asarray(p)
    neg, pos = p[y == 0], p[y == 1]
    res = {"n": int(len(y)), "positives": int(y.sum())}
    if len(neg) and len(pos):
        res.update(roc_auc=round(float(roc_auc_score(y, p)), 4), pr_auc=round(float(average_precision_score(y, p)), 4))
    res.update(caught_at_alert=round(float((pos >= thr_alert).mean()), 4) if len(pos) else None,
               false_alarm_at_alert=round(float((neg >= thr_alert).mean()), 4) if len(neg) else None,
               caught_at_verify=round(float((pos >= thr_verify).mean()), 4) if len(pos) else None,
               false_alarm_at_verify=round(float((neg >= thr_verify).mean()), 4) if len(neg) else None)
    return res


def build_units(subtopic, events_by_key, tables, pools, rng, split):
    """Return X, y, extra-eval dict for one split."""
    names, fn, kind = F.SUBTOPICS[subtopic]
    X, y = [], []
    real_x, real_y = [], []              # real-label check for the simulated-attacker subtopics
    pool = pools[split] or pools["train"]
    sim = subtopic in F.SCORES_SUCCESS_ONLY
    for key, evs in events_by_key.items():
        mode = mask_mode(key) if kind == "account" else (0 if mask_mode(key) in (0, 1) else 2)
        h = F.IPHistory() if kind == "ip" else F.AccountHistory()
        for e0 in evs:
            e = apply_mask(e0, mode)
            if not sim:
                if F.eligible(subtopic, h, e):            # the same rule the scanner uses
                    X.append(fn(h, e, tables))
                    y.append(int(e0.attack))
            elif e.success and h.ok >= F.MIN_HISTORY[subtopic]:
                real_ok = F.eligible(subtopic, h, e)      # the same rule the scanner uses
                if e0.attack or e0.ato:
                    if real_ok:
                        real_x.append(fn(h, e, tables))
                        real_y.append(1)
                else:
                    if real_ok:
                        X.append(fn(h, e, tables))
                        y.append(0)
                        if rng.random() < 0.25:
                            real_x.append(X[-1])
                            real_y.append(0)
                    a = apply_mask(pool[rng.randrange(len(pool))], mode)
                    if subtopic == "unusual-location":
                        fake = e.copy(ip=a.ip, country=a.country, region=a.region, city=a.city, asn=a.asn)
                    elif subtopic == "unknown-device":
                        fake = e.copy(ua=a.ua)
                    elif subtopic == "session-activity":
                        fake = e.copy(ts=h.last_ok[0].ts + rng.uniform(120, 6600), ip=a.ip, country=a.country,
                                      region=a.region, city=a.city, asn=a.asn, ua=a.ua)
                    else:   # behavior-changes: attacker context at the attacker's own time of day
                        day = math.floor(e.ts / F.DAY) * F.DAY
                        t = day + (a.ts % F.DAY)
                        if t <= h.last_ok[0].ts:
                            t += F.DAY
                        fake = e.copy(ts=t, ip=a.ip, country=a.country, region=a.region, city=a.city,
                                      asn=a.asn, ua=a.ua)
                    X.append(fn(h, fake, tables))
                    y.append(1)
            h.add(e)
    return X, y, real_x, real_y


def predict(model, X):
    if not len(X):
        return np.zeros(0)
    return model.predict_proba(np.array(X, dtype=float))[:, 1]


def cap(X, y, n, rng):
    if len(X) <= n:
        return X, y
    idx = rng.sample(range(len(X)), n)
    return [X[i] for i in idx], [y[i] for i in idx]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--accounts", default=os.path.join(DATA_DIR, "rba_accounts_subset.csv.gz"))
    ap.add_argument("--ips", default=os.path.join(DATA_DIR, "rba_ip_subset.csv.gz"))
    ap.add_argument("--out", default=MODELS_DIR)
    ap.add_argument("--only", default="", help="comma-separated subtopics")
    ap.add_argument("--quick", action="store_true", help="few trees (automated tests only)")
    a = ap.parse_args()
    for p in (a.accounts, a.ips):
        if not os.path.exists(p):
            sys.exit(f"Missing {p} -- run: python -m app.ml.training.extract_rba_subsets")
    rng = random.Random(SEED)
    print("Loading data")
    acc = load(a.accounts)
    ips = load(a.ips, ip_file=True)

    # group events, and decide train/calib/test per account / IP
    by = {"account": {"train": {}, "calib": {}, "test": {}}, "ip": {"train": {}, "calib": {}, "test": {}}}
    for e in acc:
        by["account"][_split(e.user)].setdefault(e.user, []).append(e)
    for e in ips:
        by["ip"][_split(e.ip or "?")].setdefault(e.ip or "?", []).append(e)

    # attack-rate / frequency tables from TRAINING accounts only
    def rows():
        for evs in by["account"]["train"].values():
            for e in evs:
                b, bv, o, ov, d, _ = F.parse_ua(e.ua)
                yield {"country": e.country, "asn": e.asn, "bfam": b, "bver": bv, "ofam": o, "over": ov, "dtype": d,
                       "ua": e.ua}, e.attack
    tables = F.Tables.build(rows(), TABLE_FIELDS)
    for f in tables.data.values():           # keep the tables small: drop values seen fewer than 5 times
        keep = {v for v, c in f["count"].items() if c >= 5}
        f["count"] = {v: c for v, c in f["count"].items() if v in keep}
        f["rate"] = {v: r for v, r in f["rate"].items() if v in keep}

    # real attacker logins (context donors for the simulated attackers), per split
    pools = {s: [e for evs in by["account"][s].values() for e in evs if e.attack] for s in ("train", "calib", "test")}
    print("  attacker contexts:", {s: len(v) for s, v in pools.items()})

    todo = [s for s in F.SUBTOPICS if not a.only or s in a.only.split(",")]
    os.makedirs(a.out, exist_ok=True)
    summary = {}
    for sub in todo:
        t0 = time.time()
        names, fn, kind = F.SUBTOPICS[sub]
        parts = {}
        for split in ("train", "calib", "test"):
            parts[split] = build_units(sub, by[kind][split], tables, pools, random.Random(SEED + {"train": 1, "calib": 2, "test": 3}[split]), split)
        Xtr, ytr = cap(parts["train"][0], parts["train"][1], MAX_UNITS, rng)
        if sum(ytr) < 50 or sum(ytr) == len(ytr):
            print(f"[{sub}] not enough examples ({len(ytr)} rows, {sum(ytr)} positive) -- skipped")
            continue
        model = HistGradientBoostingClassifier(max_iter=20 if a.quick else 400, learning_rate=0.06, max_leaf_nodes=31,
                                               l2_regularization=1.0, early_stopping=True, validation_fraction=0.1,
                                               class_weight="balanced", random_state=SEED,
                                               monotonic_cst=[F.MONOTONIC.get(sub, {}).get(n, 0) for n in names])
        model.fit(np.array(Xtr, dtype=float), np.array(ytr))
        Xc, yc = parts["calib"][0], np.array(parts["calib"][1])
        pc = predict(model, Xc)
        neg_c = pc[yc == 0]
        thr_alert = float(np.quantile(neg_c, 0.99)) if len(neg_c) else 0.9      # 1% false alarms on normal logins
        thr_verify = float(np.quantile(neg_c, 0.95)) if len(neg_c) else 0.7     # 5% -> "verify the user"
        Xt, yt = parts["test"][0], parts["test"][1]
        pt = predict(model, Xt)
        m = {"test": metrics(yt, pt, thr_alert, thr_verify)}
        if parts["test"][2] and sum(parts["test"][3]) and sum(parts["test"][3]) < len(parts["test"][3]):
            pr = predict(model, parts["test"][2])
            m["real_attacker_logins_vs_normal"] = metrics(parts["test"][3], pr, thr_alert, thr_verify)
        bundle = {"kind": "cyberguard-credential-subtopic", "version": 1, "subtopic": sub, "features": names,
                  "model": model, "tables": tables.data, "thr_alert": thr_alert, "thr_verify": thr_verify,
                  "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        out = os.path.join(a.out, f"cred_{sub}.joblib")
        joblib.dump(bundle, out, compress=3)
        info = {"subtopic": sub, "model": "HistGradientBoostingClassifier (scikit-learn)", "features": names,
                "dataset": "RBA login dataset (Wiefling et al., CC BY 4.0), subsets from extract_rba_subsets.py",
                "label": {"failed-logins": "real: login attempt from an attacker IP ('Is Attack IP')",
                          "password-spraying": "real: attempt from an attacker IP, judged from the IP's activity",
                          "unusual-location": "simulated attacker: real attacker IP/country/network on a real account",
                          "unknown-device": "simulated attacker: real attacker user agent on a real account",
                          "session-activity": "simulated attacker: real attacker login 2-110 min after a real login",
                          "behavior-changes": "simulated attacker: real attacker login at the attacker's real time of day"}[sub],
                "train_rows": len(ytr), "train_positives": int(sum(ytr)),
                "alert_threshold": round(thr_alert, 4), "verify_threshold": round(thr_verify, 4),
                "metrics": m, "trained_at": bundle["trained_at"], "seconds": round(time.time() - t0)}
        with open(os.path.join(a.out, f"cred_{sub}.metrics.json"), "w") as f:
            json.dump(info, f, indent=2)
        summary[sub] = m
        print(f"[{sub}] {json.dumps(m)}  ({time.time() - t0:.0f}s)")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
