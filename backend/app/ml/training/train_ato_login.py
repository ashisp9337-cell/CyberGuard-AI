"""
Train the Credential Theft & Account Takeover risk model (Risk-Based Authentication) on the RBA dataset.

Dataset: "Login Data Set for Risk-Based Authentication" (Wiefling et al., CC BY 4.0)
  Kaggle : https://www.kaggle.com/datasets/dasgroup/rba-dataset
  Zenodo : https://zenodo.org/records/6782156
  >33M login attempts of >3.3M users (synthesized from a real Norwegian SSO service, Feb 2020 - Feb 2021).
  Labels: "Is Attack IP" (IP on a known-attacker list) and "Is Account Takeover" (confirmed takeovers).

Put the downloaded file (the .zip is fine, no need to unzip) at:
    backend/app/ml/training/data/rba-dataset.zip      (or rba-dataset.csv)

Run from backend/ :
    python -m app.ml.training.train_ato_login --max-rows 3000000     # quick first run (~3-5 min)
    python -m app.ml.training.train_ato_login                         # full dataset (~20-40 min)

Output:
    app/ml/models/ato_rba_model.joblib        (tables + risk distributions + alert level)
    app/ml/models/ato_rba_model.metrics.json  (what it was trained on and how well it did)

The model (see app/detectors/rba_risk.py -- the same code the scanner uses):
  * ACCOUNT side  -- "is this login unusual for THIS account?"  Country -> ASN -> IP and
    device type -> OS -> browser -> User-Agent are compared with the account's own past logins
    (Freeman et al. 2016, the method the RBA dataset was published to evaluate).
    Covers: unusual location, new/unknown device, sudden behaviour change, suspicious session.
  * ATTACKER side -- "do known attackers log in from here?"  Country / ASN / device-type
    frequencies among logins from IPs on the attacker list ("Is Attack IP"), smoothed.
  * Failed logins / password spraying stay as rules in account_takeover.py; this script measures
    how those patterns look in the data and reports it (the "rule_check" section).

Passes over the file:
  0. count rows, find the account-takeover users, find the 80% time cut (train = first 80%, test = last 20%)
  1. training period: build global and attacker frequency tables, measure failed-login patterns
  2. all rows: attacker-side score for every login; account-side score for a sample of accounts
     (--user-sample, default 10%) + every takeover account, plus simulated attackers (an attacker
     who has the password but logs in from his own network/device), as in the RBA papers.
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

from app.detectors import rba_risk as R
from app.detectors.rba_risk import GlobalTables, LoginEvent, RiskState

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
MODELS_DIR = os.path.join(HERE, "..", "models")
OUT_NAME = "ato_rba_model.joblib"
# In the RBA data, logins to accounts that do not exist are all filed under this one placeholder ID
# (143k+ attempts, never successful, from 60k+ IPs). They are treated as "invalid user" attempts.
UNKNOWN_ACCOUNT_ID = "-4324475583306591935"
ALERT_PERCENTILE = 99.0
CHUNK = 500_000

# Column names in the RBA CSV can differ slightly between copies; match them loosely.
COLUMN_KEYS = {
    "ts": ("login timestamp", "timestamp"),
    "user": ("user id", "userid", "user"),
    "ip": ("ip address", "ip"),
    "country": ("country",),
    "region": ("region",),
    "city": ("city",),
    "asn": ("asn",),
    "ua": ("user agent string", "user agent"),
    "browser": ("browser name and version", "browser"),
    "os": ("os name and version", "os"),
    "device_type": ("device type",),
    "success": ("login successful", "success"),
    "attack_ip": ("is attack ip",),
    "ato": ("is account takeover",),
}
# Round-Trip Time is deliberately NOT used: in this dataset it is missing for almost every attack
# row, so a model would learn "no RTT = attacker" -- a data artefact, not real-world behaviour.
VALUE_COLS = ("country", "asn", "device_type", "os", "browser")


def find_dataset(path: str | None) -> str:
    if path:
        return path
    for name in ("rba-dataset.zip", "rba-dataset.csv", "rba-dataset.csv.zip", "rba-dataset.csv.gz"):
        p = os.path.join(DATA_DIR, name)
        if os.path.exists(p):
            return p
    sys.exit(f"Dataset not found. Download it and put it in {DATA_DIR} as rba-dataset.zip (or .csv).")


def map_columns(header: list[str]) -> dict[str, str]:
    norm = {h.strip().lower().replace("[ms]", "").strip(): h for h in header}
    out = {}
    for key, options in COLUMN_KEYS.items():
        for opt in options:
            if opt in norm:
                out[key] = norm[opt]
                break
    missing = [k for k in ("ts", "user", "ip", "success", "attack_ip", "ato") if k not in out]
    if missing:
        sys.exit(f"Could not find columns {missing} in the file. Header was: {header}")
    return out


def truthy(series: pd.Series) -> np.ndarray:
    return series.astype(str).str.strip().str.lower().isin(("true", "1", "yes")).to_numpy()


def chunks(path, cols, keys, max_rows):
    """Yield (row_offset, DataFrame) in file order, stopping at max_rows."""
    use = [cols[k] for k in keys if k in cols]
    seen = 0
    for chunk in pd.read_csv(path, usecols=use, dtype=str, chunksize=CHUNK, keep_default_na=False):
        if max_rows and seen + len(chunk) > max_rows:
            chunk = chunk.iloc[: max_rows - seen]
        yield seen, chunk
        seen += len(chunk)
        if max_rows and seen >= max_rows:
            return


def col(chunk, cols, key):
    return chunk[cols[key]] if key in cols else pd.Series([""] * len(chunk), index=chunk.index)


class ValueCache:
    """Normalised hierarchy values for each distinct (country, asn, device, os, browser) combination."""

    def __init__(self):
        self.cache: dict = {}

    def keys(self, chunk, cols):
        return list(zip(*(col(chunk, cols, k).to_numpy() for k in VALUE_COLS)))

    def get(self, key):
        v = self.cache.get(key)
        if v is None:
            if len(self.cache) > 2_000_000:
                self.cache.clear()
            v = self.cache[key] = R.values_from_fields(country=key[0], asn=key[1], device_type=key[2],
                                                       os=key[3], browser=key[4])
        return v


def hist_counts(values: np.ndarray, ks) -> dict:
    return {k: int((values >= k).sum()) for k in ks}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=None, help="path to rba-dataset.zip / .csv")
    ap.add_argument("--max-rows", type=int, default=0, help="only use the first N logins (0 = all)")
    ap.add_argument("--user-sample", type=float, default=0.10, help="share of accounts replayed for the account-side score")
    ap.add_argument("--simulate-every", type=int, default=3, help="simulate an attacker for every Nth normal test login")
    ap.add_argument("--unknown-account-id", default=UNKNOWN_ACCOUNT_ID)
    ap.add_argument("--out", default=OUT_NAME)
    args = ap.parse_args()

    path = find_dataset(args.data)
    cols = map_columns(list(pd.read_csv(path, nrows=0).columns))
    print(f"Dataset: {path}\nColumns used: {cols}\n(Round-Trip Time is ignored on purpose -- see the script header.)")
    t0 = time.time()

    # ---- pass 0: size, takeover accounts, time cut --------------------------------------------
    n_rows, ato_users, first_ts, last_ts = 0, set(), None, None
    for off, ch in chunks(path, cols, ("ts", "user", "ato"), args.max_rows):
        m = truthy(ch[cols["ato"]])
        ato_users.update(ch.loc[m, cols["user"]].tolist())
        first_ts = first_ts or ch[cols["ts"]].iloc[0]
        last_ts = ch[cols["ts"]].iloc[-1]
        n_rows = off + len(ch)
    cut = int(n_rows * 0.8)
    print(f"Pass 0: {n_rows:,} logins ({first_ts} -> {last_ts}), {len(ato_users)} takeover accounts "
          f"({time.time() - t0:.0f}s)")

    # ---- pass 1: training-period tables + failed-login pattern check ---------------------------
    tables, attack = GlobalTables(), GlobalTables()
    vc = ValueCache()
    ks = (1, 2, 3, 5, 10, 20, 50)
    rule = {"ip_fails": {"attack": dict.fromkeys(ks, 0), "normal": dict.fromkeys(ks, 0)},
            "ip_accounts": {"attack": dict.fromkeys(ks, 0), "normal": dict.fromkeys(ks, 0)},
            "account_fails": {"attack": dict.fromkeys(ks, 0), "normal": dict.fromkeys(ks, 0)},
            "unknown_account": {"attempts": 0, "attack": 0}, "known_account": {"attempts": 0, "attack": 0}}
    train_attack_ips, users_seen, train_logins = [], set(), 0
    for off, ch in chunks(path, cols, ("ts", "user", "ip") + VALUE_COLS + ("success", "attack_ip"), cut):
        att = truthy(ch[cols["attack_ip"]])
        succ = truthy(ch[cols["success"]])
        user = ch[cols["user"]].to_numpy()
        unknown = user == args.unknown_account_id
        keys = vc.keys(ch, cols)
        df = pd.DataFrame({"k": keys, "a": att})
        for (k, a), n in df.groupby(["k", "a"]).size().items():
            v = vc.get(k)
            tables.add(v, int(n))
            if a:
                attack.add(v, int(n))
        train_attack_ips.append(pd.util.hash_array(ch.loc[att, cols["ip"]].to_numpy()))
        users_seen.update(user[~unknown].tolist()) if len(users_seen) < 5_000_000 else None
        train_logins += int((~unknown).sum())
        # failed-login patterns per IP-hour and per account-hour
        hour = pd.to_datetime(ch[cols["ts"]], errors="coerce").astype("int64") // 3_600_000_000_000
        f = pd.DataFrame({"ip": ch[cols["ip"]].to_numpy(), "u": user, "h": hour.to_numpy(), "fail": ~succ, "a": att, "unk": unknown})
        g = f.groupby(["ip", "h"]).agg(fails=("fail", "sum"), accts=("u", "nunique"), a=("a", "max"))
        for name, series in (("ip_fails", g["fails"]), ("ip_accounts", g["accts"])):
            for lab, mask in (("attack", g["a"].to_numpy()), ("normal", ~g["a"].to_numpy())):
                for k, c in hist_counts(series.to_numpy()[mask], ks).items():
                    rule[name][lab][k] += c
        ga = f[~f["unk"]].groupby(["u", "h"]).agg(fails=("fail", "sum"), a=("a", "max"))
        for lab, mask in (("attack", ga["a"].to_numpy()), ("normal", ~ga["a"].to_numpy())):
            for k, c in hist_counts(ga["fails"].to_numpy()[mask], ks).items():
                rule["account_fails"][lab][k] += c
        rule["unknown_account"]["attempts"] += int(unknown.sum())
        rule["unknown_account"]["attack"] += int((unknown & att).sum())
        rule["known_account"]["attempts"] += int((~unknown).sum())
        rule["known_account"]["attack"] += int((~unknown & att).sum())
        print(f"  pass 1: {off + len(ch):,} / {cut:,} training logins ({time.time() - t0:.0f}s)", flush=True)
    train_attack_ips = np.unique(np.concatenate(train_attack_ips)) if train_attack_ips else np.array([], dtype=np.uint64)
    print(f"Pass 1 done: {len(tables.counts):,} value paths, {attack.total:,} attacker logins in training period")

    # ---- pass 2: score every login ----------------------------------------------------------
    rng = random.Random(42)
    state = RiskState(tables)
    rep_cache: dict = {}
    hist_train, rep_train = [], []                        # normal successful training logins
    test = {"rep": [], "att": [], "succ": [], "new_ip": []}
    hist_test = {"risk": [], "att": []}                   # sampled accounts with history, successful test logins
    legit_sim, sims = [], {"naive": [], "same_country": []}
    ato_rows = []
    attacker_pool, by_country = [], {}                    # attacker login values seen in the training period
    sample_cut = int(args.user_sample * 10_000)
    n_sim = 0

    def rep_of(key):
        r = rep_cache.get(key)
        if r is None:
            if len(rep_cache) > 2_000_000:
                rep_cache.clear()
            r = rep_cache[key] = R.reputation(vc.get(key), tables, attack)[0]
        return r

    for off, ch in chunks(path, cols, ("ts", "user", "ip", "ua") + VALUE_COLS + ("success", "attack_ip", "ato"), args.max_rows):
        idx = np.arange(off, off + len(ch))
        is_test = idx >= cut
        att, succ, ato = truthy(ch[cols["attack_ip"]]), truthy(ch[cols["success"]]), truthy(ch[cols["ato"]])
        user = ch[cols["user"]].to_numpy()
        unknown = user == args.unknown_account_id
        keys = vc.keys(ch, cols)
        rep = np.fromiter((rep_of(k) for k in keys), dtype=np.float64, count=len(keys))
        m = ~is_test & succ & ~att & ~unknown
        rep_train.append(rep[m].astype(np.float32))
        mt = is_test & ~unknown
        if mt.any():
            ip_hash = pd.util.hash_array(ch[cols["ip"]].to_numpy()[mt])
            test["rep"].append(rep[mt].astype(np.float32))
            test["att"].append(att[mt])
            test["succ"].append(succ[mt])
            test["new_ip"].append(~np.isin(ip_hash, train_attack_ips))

        # account side: replay sampled accounts (+ every takeover account) in time order
        uh = pd.util.hash_array(user) % np.uint64(10_000)
        replay = ((uh < sample_cut) | pd.Series(user).isin(list(ato_users)).to_numpy()) & ~unknown
        tsec = (pd.to_datetime(ch[cols["ts"]], errors="coerce").astype("int64") // 10**9).to_numpy()
        ips, uas = ch[cols["ip"]].to_numpy(), col(ch, cols, "ua").to_numpy()
        for i in np.flatnonzero(replay | (att & ~is_test & ~unknown)):
            key = keys[i]
            if att[i] and not is_test[i]:                 # remember how attackers' logins look
                v = {**vc.get(key), "ip": R._clean(ips[i]), "ua": R._clean(uas[i])}
                if len(attacker_pool) < 50_000:
                    attacker_pool.append(v)
                elif rng.random() < 0.05:
                    attacker_pool[rng.randrange(50_000)] = v
                lst = by_country.setdefault(v["country"], [])
                if len(lst) < 2_000:
                    lst.append(v)
            if not replay[i]:
                continue
            e = LoginEvent(ts=float(tsec[i]), user=user[i], ip=ips[i] or None, success=bool(succ[i]))
            v = {**vc.get(key), "ip": R._clean(ips[i]), "ua": R._clean(uas[i])}
            had = state.has_history(e.user)
            risk = state.score(e, v)[0] if had else None
            if ato[i]:
                ato_rows.append({"history": risk, "rep": float(rep[i]), "test": bool(is_test[i])})
            if had and succ[i]:
                if not is_test[i] and not att[i]:
                    hist_train.append(risk)
                elif is_test[i]:
                    hist_test["risk"].append(risk)
                    hist_test["att"].append(bool(att[i]))
                    if not att[i] and not ato[i]:
                        n_sim += 1
                        if n_sim % args.simulate_every == 0 and attacker_pool:
                            legit_sim.append(risk)
                            fake = rng.choice(attacker_pool)
                            sims["naive"].append(state.score(e, {**fake})[0])
                            pool = by_country.get(v["country"])
                            if pool:
                                sims["same_country"].append((len(legit_sim) - 1, state.score(e, {**rng.choice(pool)})[0]))
            state.update(e, v)
        print(f"  pass 2: {off + len(ch):,} / {n_rows:,} logins scored ({time.time() - t0:.0f}s)", flush=True)

    # ---- risk distributions of NORMAL logins -> percentiles ------------------------------------
    qs = np.linspace(0, 1, 1001)
    hist_train = np.asarray(hist_train, dtype=np.float64)
    rep_train = np.concatenate(rep_train).astype(np.float64) if rep_train else np.zeros(1)
    if len(hist_train) < 100:
        sys.exit("Too few repeat logins to learn what 'normal' looks like -- use more rows (--max-rows 0).")
    history_q = np.quantile(hist_train, qs).tolist()
    reputation_q = np.quantile(rep_train, qs).tolist()
    pct = lambda q, x: np.searchsorted(np.asarray(q), np.asarray(x, dtype=np.float64), side="left") / len(q) * 100

    from sklearn.metrics import average_precision_score, roc_auc_score

    def tpr_at(neg, pos, rates=(0.01, 0.05)):
        if len(neg) == 0 or len(pos) == 0:
            return None
        return {f"caught_when_challenging_{int(r * 100)}pct_of_normal_logins": round(float((np.asarray(pos) > np.quantile(neg, 1 - r)).mean()), 4) for r in rates}

    def auc(y, s):
        y = np.asarray(y)
        return round(float(roc_auc_score(y, s)), 4) if 0 < y.sum() < len(y) else None

    # account side
    legit_sim = np.asarray(legit_sim)
    naive = np.asarray(sims["naive"])
    sc_idx = np.asarray([i for i, _ in sims["same_country"]], dtype=int)
    sc = np.asarray([s for _, s in sims["same_country"]])
    account_side = {
        "what": "risk of a login compared with the account's own earlier logins (country/ASN/IP + device/OS/browser/UA)",
        "normal_repeat_logins_used_for_calibration": int(len(hist_train)),
        "simulated_attacker_naive": {
            "description": "attacker has the password, logs in from a real attacker login's country/ASN/IP/device",
            "pairs": int(len(naive)), "roc_auc": auc(np.r_[np.zeros(len(legit_sim)), np.ones(len(naive))], np.r_[legit_sim, naive]) if len(naive) else None,
            **(tpr_at(hist_train, naive) or {})},
        "simulated_attacker_same_country": {
            "description": "as above but the attacker uses the victim's own country (e.g. a local VPN)",
            "pairs": int(len(sc)), "roc_auc": auc(np.r_[np.zeros(len(sc_idx)), np.ones(len(sc))], np.r_[legit_sim[sc_idx], sc]) if len(sc) else None,
            **(tpr_at(hist_train, sc) or {})},
        "real_attack_ip_successful_logins_vs_normal": {
            "note": "accounts with history, test period; attacker-list IPs that log in successfully often keep "
                    "coming back, so they become part of the account's 'normal' history -- expect a weak result",
            "roc_auc": auc(hist_test["att"], hist_test["risk"]) if hist_test["risk"] else None},
    }
    ato_hist = [r["history"] for r in ato_rows if r["history"] is not None]
    ato_rep = [r["rep"] for r in ato_rows]
    takeovers = {
        "rows": len(ato_rows), "rows_in_test_period": sum(r["test"] for r in ato_rows),
        "rows_with_account_history": len(ato_hist),
        "account_side_percentiles": [round(float(p), 1) for p in pct(history_q, ato_hist)] if ato_hist else [],
        "attacker_side_percentiles": [round(float(p), 1) for p in pct(reputation_q, ato_rep)] if ato_rep else [],
        "share_flagged_at_alert_level": round(float(np.mean([max(pct(history_q, [r["history"]])[0] if r["history"] is not None else 0,
                                                                  pct(reputation_q, [r["rep"]])[0]) >= ALERT_PERCENTILE for r in ato_rows])), 4) if ato_rows else None,
        "note": "tables were built from the training period; takeover rows are too few to tune on, so all are reported",
    }

    # attacker side (test period, every account)
    if test["rep"]:
        trep = np.concatenate(test["rep"]).astype(np.float64)
        tatt, tsucc, tnew = (np.concatenate(test[k]) for k in ("att", "succ", "new_ip"))
        tp = pct(reputation_q, trep)
        flag = tp >= ALERT_PERCENTILE
        attacker_side = {
            "what": "how much more common the login's country / ASN / device type is among attacker-list logins",
            "test_logins": int(len(trep)), "attack_share": round(float(tatt.mean()), 4),
            "roc_auc_all_logins": auc(tatt, trep),
            "pr_auc_all_logins": round(float(average_precision_score(tatt, trep)), 4) if tatt.any() else None,
            "roc_auc_successful_logins": auc(tatt[tsucc], trep[tsucc]),
            f"at_alert_level_{ALERT_PERCENTILE:g}th_percentile": {
                "precision": round(float(tatt[flag].mean()), 4) if flag.any() else None,
                "recall": round(float(flag[tatt].mean()), 4) if tatt.any() else None,
                "normal_logins_alerted": round(float(flag[~tatt].mean()), 4)},
            "roc_auc_attack_ips_never_seen_in_training": auc(np.r_[np.zeros((~tatt).sum()), np.ones((tatt & tnew).sum())],
                                                              np.r_[trep[~tatt], trep[tatt & tnew]]) if (tatt & tnew).any() else None,
        }
    else:
        attacker_side = {"note": "no test rows"}

    def precision_table(name):
        out = {}
        for k in ks:
            a, n = rule[name]["attack"][k], rule[name]["normal"][k]
            out[f">={k}"] = {"windows": a + n, "attack_share": round(a / (a + n), 4) if a + n else None}
        return out
    ua, ka = rule["unknown_account"], rule["known_account"]
    rule_check = {
        "note": "share of 1-hour windows that involve an attacker-list IP, per threshold. If the share does not rise "
                "with the threshold, the data contains no burst pattern to tune on and the rules keep standard values.",
        "failed_logins_from_one_ip_per_hour": precision_table("ip_fails"),
        "accounts_tried_from_one_ip_per_hour (spraying)": precision_table("ip_accounts"),
        "failed_logins_on_one_account_per_hour (brute force)": precision_table("account_fails"),
        "attempts_on_non_existent_accounts": {
            "attempts": ua["attempts"], "attack_share": round(ua["attack"] / ua["attempts"], 4) if ua["attempts"] else None,
            "attack_share_on_real_accounts": round(ka["attack"] / ka["attempts"], 4) if ka["attempts"] else None},
    }

    metrics = {"account_side": account_side, "attacker_side": attacker_side,
               "account_takeover_rows": takeovers, "rule_check": rule_check}
    print("\n=== Results (calibrated on the first 80% of time, tested on the last 20%) ===")
    print(json.dumps(metrics, indent=2))

    bundle = {"kind": R.BUNDLE_KIND, "version": R.BUNDLE_VERSION, "tables": tables.to_dict(),
              "attack_tables": attack.to_dict(), "beta": R.BETA, "history_quantiles": history_q,
              "reputation_quantiles": reputation_q, "alert_percentile": ALERT_PERCENTILE}

    print("\n=== Hand-made scenarios ===")
    scen = scenario_checks(R.RBAModel(bundle))

    card = {
        "model": "Risk-Based Authentication risk score (Freeman et al. 2016 / Wiefling et al.) + attacker-source reputation",
        "dataset": os.path.basename(path),
        "dataset_source": "https://www.kaggle.com/datasets/dasgroup/rba-dataset (CC BY 4.0, Wiefling et al.)",
        "logins": n_rows, "training_logins": cut, "period": [str(first_ts), str(last_ts)],
        "accounts_in_training": len(users_seen), "user_sample": args.user_sample,
        "alert_rule": f"alert when a login is riskier than {ALERT_PERCENTILE:g}% of normal logins on either side",
        "not_used": "Round-Trip Time (missing for attack rows = label leak)",
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "metrics": metrics, "scenarios": scen,
    }
    bundle["card"] = card
    os.makedirs(MODELS_DIR, exist_ok=True)
    out_path = args.out if os.path.isabs(args.out) else os.path.join(MODELS_DIR, args.out)
    joblib.dump(bundle, out_path, compress=3)
    with open(out_path.replace(".joblib", ".metrics.json"), "w") as f:
        json.dump(card, f, indent=2)
    print(f"\nSaved -> {out_path}\nReport -> {out_path.replace('.joblib', '.metrics.json')}  ({time.time() - t0:.0f}s total)")
    return 0


def scenario_checks(model: "R.RBAModel") -> dict:
    """Situations from the module's subtopics, scored by the trained model."""
    base = 1_700_000_000
    def ev(day, hour, user="asha", ip="10.0.0.5", country="NO", asn="29695", dev="desktop", os_="Windows 10", br="Chrome 120", ok=True):
        return LoginEvent(base + day * 86400 + hour * 3600, user, ip, ok, country, None, None, asn, None, dev, os_, br)
    normal = [ev(d, 9) for d in range(20)]
    cases = {
        "usual place, device and time (should be LOW)": normal + [ev(21, 9)],
        "same account, new IP from the same provider (should stay LOW/MEDIUM)": normal + [ev(21, 9, ip="10.0.0.77")],
        "same account, new browser on the same computer (LOW/MEDIUM)": normal + [ev(21, 9, br="Firefox 115")],
        "same account, new country + network + device (should be HIGH)":
            normal + [ev(21, 3, ip="91.240.118.2", country="RU", asn="48693", dev="mobile", os_="Android 9", br="Chrome Mobile 80")],
    }
    out = {}
    for name, events in cases.items():
        r = model.assess(events)[-1]
        out[name] = {"percentile": round(r["percentile"], 1), "flagged": r["flagged"], "reasons": r["reasons"]}
        print(f"   {'ALERT' if r['flagged'] else 'ok   '}  riskier than {r['percentile']:5.1f}% of normal logins  {name}")
    return out


if __name__ == "__main__":
    sys.exit(main())
