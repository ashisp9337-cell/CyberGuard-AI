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
tested on accounts and IPs it has never seen.
31 Oct: real attacker logins are judged by kind - "first" (an attacker's first successful login to an account),
"repeat" (the same attacker again: the account's history already contains it, so a new-device / new-place check
cannot see it) and "ato" (confirmed takeovers). The four account models also learn from the real first attacker logins
of TRAINING accounts; their weight (0 / 5 / 10 / 20) is chosen on the calibration accounts only. A model is saved only
if, on the same test accounts, it beats the installed one (real first attacker logins AUC higher, at most 0.2 points
more false alarms, simulated-attacker AUC at most 0.01 lower); otherwise nothing changes and the result goes to
cred_<subtopic>.rejected.metrics.json. The installed model is kept as cred_<subtopic>.previous.joblib. Logs pasted by users often lack country/ASN/user agent,
so some accounts are trained with those fields blanked out.

Run from backend/ (about 20-40 minutes):
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
REAL_WEIGHTS = (0, 5, 10, 20)  # weights tried for real attacker logins (chosen on calibration accounts)
NOISE = 0.002                  # 0.2 points: allowed extra false alarms against the installed model
SIM_DROP = 0.01                # allowed drop of the simulated-attacker AUC against the installed model


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
    """Return X, y (training units) and the real-label check: real_x, real_y, real_c. real_c says what each real login
    is: "normal", "first" (an attacker's first successful login to this account), "repeat" (the same attacker again -
    the account's history already contains it) or "ato" (a confirmed account takeover)."""
    names, fn, kind = F.SUBTOPICS[subtopic]
    X, y = [], []
    real_x, real_y, real_c = [], [], []  # real-label check for the simulated-attacker subtopics
    pool = pools[split] or pools["train"]
    sim = subtopic in F.SCORES_SUCCESS_ONLY
    for key, evs in events_by_key.items():
        mode = mask_mode(key) if kind == "account" else (0 if mask_mode(key) in (0, 1) else 2)
        h = F.IPHistory() if kind == "ip" else F.AccountHistory()
        attacker_before = 0                   # successful attacker logins to this account so far
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
                        real_c.append("ato" if e0.ato else "first" if attacker_before == 0 else "repeat")
                else:
                    if real_ok:
                        X.append(fn(h, e, tables))
                        y.append(0)
                        if rng.random() < 0.25:
                            real_x.append(X[-1])
                            real_y.append(0)
                            real_c.append("normal")
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
            if e0.success and e0.attack:
                attacker_before += 1
            h.add(e)
    return X, y, real_x, real_y, real_c


def real_kinds(y, p, c, thr_alert, thr_verify):
    """Real attacker logins against real normal logins, per kind (first / repeat / confirmed takeover)."""
    c, p = np.asarray(c), np.asarray(p)
    neg = p[c == "normal"]
    out = {}
    for kind in ("first", "repeat", "ato"):
        pos = p[c == kind]
        if len(pos) and len(neg):
            out[kind] = metrics(np.r_[np.zeros(len(neg)), np.ones(len(pos))], np.r_[neg, pos], thr_alert, thr_verify)
    return out


def better(new, old, sim):
    """-> (keep?, reason). The new model must beat the installed one on the same test accounts."""
    if old is None:
        return True, "no readable installed model"
    nt, ot = new["test"], old["test"]
    if nt.get("false_alarm_at_alert", 1) > ot.get("false_alarm_at_alert", 0) + NOISE:
        return False, "more false alarms on normal logins than the installed model"
    if not sim:
        if nt.get("roc_auc", 0) > ot.get("roc_auc", 0):
            return True, "higher AUC than the installed model"
        return False, "AUC not higher than the installed model"
    nf = new.get("real_attacker_logins_by_kind", {}).get("first", {}).get("roc_auc")
    of = old.get("real_attacker_logins_by_kind", {}).get("first", {}).get("roc_auc")
    if nf is None or of is None or nf <= of:
        return False, "not better on real first attacker logins"
    if nt.get("roc_auc", 0) < ot.get("roc_auc", 0) - SIM_DROP:
        return False, "simulated-attacker AUC dropped too much"
    return True, f"real first attacker logins AUC {of} -> {nf}, false alarms and simulated AUC held"


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
        sim = sub in F.SCORES_SUCCESS_ONLY
        # real attacker logins of TRAINING accounts (first logins + confirmed takeovers; repeats are left out - by then
        # the attacker is already in the account's history, so they would teach the model to distrust known devices)
        rx, rc = parts["train"][2], np.asarray(parts["train"][4])
        real_pos = [rx[i] for i in np.where(np.isin(rc, ["first", "ato"]))[0]] if sim else []
        Xc, yc = parts["calib"][0], np.array(parts["calib"][1])
        cx, cy, cc = parts["calib"][2], parts["calib"][3], parts["calib"][4]

        def fit(weight):
            Xf, yf = list(Xtr), list(ytr)
            sw = [1.0] * len(yf)
            if weight > 0 and real_pos:
                Xf += real_pos
                yf += [1] * len(real_pos)
                sw += [weight] * len(real_pos)
            mdl = HistGradientBoostingClassifier(max_iter=20 if a.quick else 400, learning_rate=0.06, max_leaf_nodes=31,
                                                 l2_regularization=1.0, early_stopping=True, validation_fraction=0.1,
                                                 class_weight="balanced", random_state=SEED,
                                                 monotonic_cst=[F.MONOTONIC.get(sub, {}).get(n, 0) for n in names])
            mdl.fit(np.array(Xf, dtype=float), np.array(yf), sample_weight=np.array(sw))
            pc = predict(mdl, Xc)
            neg_c = pc[yc == 0]
            ta = float(np.quantile(neg_c, 0.99)) if len(neg_c) else 0.9      # 1% false alarms on normal logins
            tv = float(np.quantile(neg_c, 0.95)) if len(neg_c) else 0.7      # 5% -> "verify the user"
            sim_auc = roc_auc_score(yc, pc) if 0 < yc.sum() < len(yc) else 0.0
            first = real_kinds(cy, predict(mdl, cx), cc, ta, tv).get("first", {}).get("roc_auc") if cx else None
            return mdl, ta, tv, sim_auc, first

        # the weight of the real attacker logins is chosen on the CALIBRATION accounts only (never on the test ones):
        # the best AUC on real first attacker logins, as long as the simulated-attacker AUC drops at most SIM_DROP
        cands = {}
        for w in (REAL_WEIGHTS if sim and len(real_pos) >= 50 else (0,)):
            cands[w] = fit(w)
            print(f"[{sub}] weight {w:>2} for real attacker logins: calibration simulated AUC {cands[w][3]:.4f}, "
                  f"real first logins AUC {cands[w][4] if cands[w][4] is not None else '-'}", flush=True)
        base_sim = cands[0][3]
        ok_w = [w for w, c in cands.items() if c[3] >= base_sim - SIM_DROP and c[4] is not None]
        weight = max(ok_w, key=lambda w: (cands[w][4], -w)) if ok_w else 0
        model, thr_alert, thr_verify = cands[weight][:3]
        Xt, yt = parts["test"][0], parts["test"][1]
        pt = predict(model, Xt)
        m = {"test": metrics(yt, pt, thr_alert, thr_verify)}
        if parts["test"][2] and sum(parts["test"][3]) and sum(parts["test"][3]) < len(parts["test"][3]):
            pr = predict(model, parts["test"][2])
            m["real_attacker_logins_vs_normal"] = metrics(parts["test"][3], pr, thr_alert, thr_verify)
            m["real_attacker_logins_by_kind"] = real_kinds(parts["test"][3], pr, parts["test"][4], thr_alert, thr_verify)
        bundle = {"kind": "cyberguard-credential-subtopic", "version": 1, "subtopic": sub, "features": names,
                  "model": model, "tables": tables.data, "thr_alert": thr_alert, "thr_verify": thr_verify,
                  "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        out = os.path.join(a.out, f"cred_{sub}.joblib")
        # the installed model on the SAME test accounts (its own alert level) - the new one must beat it
        old = None
        if os.path.exists(out):
            try:
                ob = joblib.load(out)
                om = {"test": metrics(yt, predict(ob["model"], Xt), ob["thr_alert"], ob["thr_verify"])}
                if "real_attacker_logins_vs_normal" in m:
                    opr = predict(ob["model"], parts["test"][2])
                    om["real_attacker_logins_vs_normal"] = metrics(parts["test"][3], opr, ob["thr_alert"], ob["thr_verify"])
                    om["real_attacker_logins_by_kind"] = real_kinds(parts["test"][3], opr, parts["test"][4],
                                                                    ob["thr_alert"], ob["thr_verify"])
                old = om
            except Exception as ex:                       # unreadable installed model: the new one replaces it
                print(f"[{sub}] installed model could not be read ({type(ex).__name__}) - it will be replaced")
        keep, why = better(m, old, sim)
        info = {"subtopic": sub, "model": "HistGradientBoostingClassifier (scikit-learn)", "features": names,
                "dataset": "RBA login dataset (Wiefling et al., CC BY 4.0), subsets from extract_rba_subsets.py",
                "label": {"failed-logins": "real: login attempt from an attacker IP ('Is Attack IP')",
                          "password-spraying": "real: attempt from an attacker IP, judged from the IP's activity",
                          "unusual-location": "simulated attacker: real attacker IP/country/network on a real account",
                          "unknown-device": "simulated attacker: real attacker user agent on a real account",
                          "session-activity": "simulated attacker: real attacker login 2-110 min after a real login",
                          "behavior-changes": "simulated attacker: real attacker login at the attacker's real time of day"}[sub]
                         + (f"; plus the real first attacker logins of training accounts (weight {weight}, chosen on "
                            f"calibration accounts)" if weight else ""),
                "real_attacker_weight": weight,
                "train_rows": len(ytr) + (len(real_pos) if weight else 0), "train_positives": int(sum(ytr)) + (len(real_pos) if weight else 0),
                "alert_threshold": round(thr_alert, 4), "verify_threshold": round(thr_verify, 4),
                "metrics": m, "installed_model_same_test": old, "kept": keep, "keep_reason": why,
                "trained_at": bundle["trained_at"], "seconds": round(time.time() - t0)}
        if keep:
            tmp = out + ".tmp"
            joblib.dump(bundle, tmp, compress=3)
            if os.path.exists(out):
                import shutil
                shutil.copy2(out, os.path.join(a.out, f"cred_{sub}.previous.joblib"))
            os.replace(tmp, out)
            mpath = os.path.join(a.out, f"cred_{sub}.metrics.json")
        else:
            mpath = os.path.join(a.out, f"cred_{sub}.rejected.metrics.json")
        with open(mpath, "w") as f:
            json.dump(info, f, indent=2)
        kinds = m.get("real_attacker_logins_by_kind", {})
        okinds = (old or {}).get("real_attacker_logins_by_kind", {})
        print(f"[{sub}] test accounts: simulated AUC {m['test'].get('roc_auc')} (installed "
              f"{(old or {}).get('test', {}).get('roc_auc', '-')}), false alarms at alert "
              f"{m['test'].get('false_alarm_at_alert')} (installed {(old or {}).get('test', {}).get('false_alarm_at_alert', '-')})")
        for k in ("first", "repeat", "ato"):
            if k in kinds:
                print(f"      real attacker logins, {k:6s}: AUC {kinds[k].get('roc_auc')} caught at alert "
                      f"{kinds[k]['caught_at_alert']} (installed: AUC {okinds.get(k, {}).get('roc_auc', '-')} caught "
                      f"{okinds.get(k, {}).get('caught_at_alert', '-')})")
        print(f"[{sub}] {'KEPT' if keep else 'NOT KEPT'} - {why}  ({time.time() - t0:.0f}s)", flush=True)
        summary[sub] = {"kept": keep, "real_attacker_weight": weight, **m}
    with open(os.path.join(a.out, "cred_training_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)


if __name__ == "__main__":
    main()
