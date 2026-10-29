r"""Insider-risk training, step 3: train and HONESTLY test the Insider Risk engine on CERT r4.2.

Reads the files prepare_insider_data.py wrote (data\insider\) and writes:
  * app\ml\models\insider_risk.joblib - the "known insider playbook" model (HistGradientBoosting on user-day features)
  * app\ml\models\insider_risk.json   - feature list, score cut points (from normal days), review/alert levels and
                                         the test results printed below
Final risk = the higher of two percentiles of NORMAL working days: the model's score, and a label-free
"unlike themselves" score (own + peer baselines, novelties). See app\detectors\insider_risk.py.

Tests (nothing tested is ever trained on):
  1. TIME SPLIT  - train on days before 1 Oct 2010, test on later days: 35 insiders who start after the split are new
                   people the model never saw. A SOC analyst reviews the 10 riskiest user-days per day (1% of 1,000
                   staff); an insider is "caught" when one of their malicious days is in that day's top 10.
  2. UNSEEN PATTERN - leave one CERT scenario out: train on the other two scenarios (+ half the normal staff), test on
                   the left-out scenario's insiders (+ the other half): how well does it catch a NEW kind of insider?
  3. NO WEB      - test 1 again without any web-site signal (CERT's simulated sites make web signals look too easy).
Random picking with the same budget is shown next to every result. Run from the backend folder (2-5 minutes):
    python -I app\ml\training\train_insider_risk.py
"""
import json
import os
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "..")))   # the backend folder (python -I ignores cwd)

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.ensemble import HistGradientBoostingClassifier  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402

from app.detectors import insider_risk as R  # noqa: E402

DATA = os.path.join(HERE, "data", "insider")
MODELS = os.path.join(HERE, "..", "models")
SPLIT = "2010-10-01"
BUDGET = 10                    # user-days an analyst reviews per day (1% of 1,000 staff)
REVIEW, ALERT = 99.0, 99.9     # risk levels: riskier than 99% / 99.9% of ordinary working days
GB = dict(max_iter=300, learning_rate=0.05, max_leaf_nodes=15, l2_regularization=1.0, class_weight="balanced",
          random_state=0)


def load():
    need = ["insider_userdays.csv.gz", "insider_users.csv", "insider_labels.csv", "insider_rareweb.csv.gz"]
    for f in need:
        if not os.path.exists(os.path.join(DATA, f)):
            sys.exit(f"{f} is missing - run prepare_insider_data.py first.")
    ud = pd.read_csv(os.path.join(DATA, need[0]))
    users = pd.read_csv(os.path.join(DATA, need[1]))
    lab = pd.read_csv(os.path.join(DATA, need[2]), dtype={"scenario": str})
    rw = pd.read_csv(os.path.join(DATA, need[3]))
    return ud, dict(zip(users["user"], users["role"])), lab, rw


def label(X, lab):
    mal = {(u, d) for u, ds in zip(lab["user"], lab["malicious_days"]) for d in str(ds).split(";")}
    X["y"] = [(u, d) in mal for u, d in zip(X["user"], X["date"])]
    return X


def cut_points(values):
    return np.quantile(np.asarray(values, dtype=float), np.linspace(0, 1, 1001)).tolist()


def fit(train, cols):
    m = HistGradientBoostingClassifier(**GB).fit(train[cols], train["y"])
    normal = train[~train["y"]]
    cfg = {"model_quantiles": cut_points(m.predict_proba(normal[cols])[:, 1]),
           "baseline_quantiles": cut_points(R.baseline_score(normal, with_web="web_leak" in cols))}
    return m, cfg


def risk(m, cfg, d, cols):
    p = m.predict_proba(d[cols])[:, 1]
    return R.combined_risk(p, R.baseline_score(d, with_web="web_leak" in cols), cfg) + 1e-6 * p    # p breaks ties


def caught(test, score, users, budget):
    t = test.assign(s=score)
    t["rank"] = t.groupby("date")["s"].rank(ascending=False, method="first")
    hit = set(t[(t["rank"] <= budget) & t["y"]]["user"]) & users
    per_day = t.groupby("date").size()
    mal = t[t["y"] & t["user"].isin(users)]
    p = mal["date"].map(lambda d: min(1.0, budget / per_day[d])).to_numpy()
    rnd = mal.assign(p=p).groupby("user")["p"].apply(lambda s: 1 - np.prod(1 - s)).sum()
    alerts = t[t["rank"] <= budget]
    return len(hit), float(rnd), float(alerts["y"].mean())


def main():
    t0 = time.time()
    ud, roles, lab, rw = load()
    print(f"{len(ud):,} user-days, {ud['user'].nunique():,} people, {len(lab)} insiders "
          f"(scenario counts {lab['scenario'].value_counts().sort_index().to_dict()})")
    results = {}

    # ---- 1 + 3: time split (rarity of sites judged from the training period only) ----
    ref = rw[rw["date"] < SPLIT].groupby("domain")["user"].nunique().to_dict()
    X = label(R.add_features(ud, roles, rw, ref), lab)
    train, test = X[X["date"] < SPLIT], X[X["date"] >= SPLIT]
    new_people = set(lab["user"][lab["malicious_days"].str[:10] >= SPLIT])
    print(f"features ready ({time.time() - t0:.0f}s). Time split: train {len(train):,} user-days "
          f"({int(train['y'].sum())} malicious), test {len(test):,} ({int(test['y'].sum())} malicious), "
          f"{len(new_people)} test insiders never seen in training")
    print(f"\n1/3  TIME SPLIT - analyst reviews the {BUDGET} riskiest user-days per day")
    for web in (True, False):
        cols = R.feature_columns(web)
        m, cfg = fit(train, cols)
        s = risk(m, cfg, test, cols)
        n, rnd, prec = caught(test, s, new_people, BUDGET)
        normal_test = s[~test["y"].to_numpy()]
        days = test["date"].nunique()
        row = {"caught": n, "of": len(new_people), "random": round(rnd, 1), "auc": round(roc_auc_score(test["y"], s), 4),
               "top10_precision": round(prec, 3),
               "false_review_per_day": round(float((normal_test >= REVIEW).sum()) / days, 1),
               "false_alert_per_day": round(float((normal_test >= ALERT).sum()) / days, 1),
               "malicious_days_at_review": round(float((s[test["y"].to_numpy()] >= REVIEW).mean()), 3)}
        results["time_split" + ("" if web else "_no_web")] = row
        print(f"  {'with' if web else 'NO  '} web signals: caught {n}/{len(new_people)} new insiders "
              f"(random picking: {rnd:.1f}); AUC {row['auc']}; {prec:.1%} of the top-{BUDGET} are malicious days; "
              f"false 'review' {row['false_review_per_day']}/day, false 'alert' {row['false_alert_per_day']}/day "
              f"(of ~{len(test) / days:.0f} people-days); {row['malicious_days_at_review']:.0%} of malicious days "
              f"reach 'review'")

    # ---- 2: unseen pattern (leave one scenario out; normal staff split in two halves) ----
    print(f"\n2/3  UNSEEN PATTERN - trained without that scenario; budget {BUDGET // 2}/day (half the staff)")
    ref_all = rw.groupby("domain")["user"].nunique().to_dict()
    XA = label(R.add_features(ud, roles, rw, ref_all), lab)
    normal_users = sorted(set(XA["user"]) - set(lab["user"]))
    half = set(np.random.RandomState(0).choice(normal_users, len(normal_users) // 2, replace=False))
    cols = R.feature_columns(True)
    tot, tot_n, tot_rnd = 0, 0, 0.0
    for sc in sorted(lab["scenario"].unique()):
        held = set(lab["user"][lab["scenario"] == sc])
        tr = XA[XA["user"].isin((set(lab["user"]) - held) | half)]
        te = XA[XA["user"].isin(held | (set(normal_users) - half))]
        m, cfg = fit(tr, cols)
        n, rnd, _ = caught(te, risk(m, cfg, te, cols), held, BUDGET // 2)
        tot, tot_n, tot_rnd = tot + n, tot_n + len(held), tot_rnd + rnd
        results[f"unseen_scenario_{sc}"] = {"caught": n, "of": len(held), "random": round(rnd, 1)}
        print(f"  scenario {sc} never seen: caught {n}/{len(held)} (random picking: {rnd:.1f})")
    results["unseen_total"] = {"caught": tot, "of": tot_n, "random": round(tot_rnd, 1)}
    print(f"  all three: {tot}/{tot_n} (random picking: {tot_rnd:.1f})")

    # ---- final model: every user-day, all 70 insiders ----
    m, cfg = fit(XA, cols)
    os.makedirs(MODELS, exist_ok=True)
    joblib.dump({"model": m, "columns": cols}, os.path.join(MODELS, "insider_risk.joblib"))
    meta = {"version": 1, "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "dataset": "CERT Insider Threat Test Dataset r4.2 (CMU SEI, synthetic), doi:10.1184/R1/12841247",
            "columns": cols, "review_level": REVIEW, "alert_level": ALERT, "rare_share": R.RARE_SHARE,
            "window_days": R.WINDOW, "min_history": R.MIN_HISTORY, **cfg, "results": results}
    with open(os.path.join(MODELS, "insider_risk.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=1)
    print(f"\n3/3  saved insider_risk.joblib + insider_risk.json (trained on all {len(XA):,} user-days) "
          f"in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
