r"""Train / evaluate the network-traffic detector on the corrected CIC-IDS2017 flows (step 4).

Needs data\network\network_flows.csv.gz (made by prepare_network_data.py). Writes:
  * app\ml\models\network_traffic.json  - alert levels + every evaluation number
  * app\ml\models\network_flow.joblib   - the SUPPORTING per-connection model (never raises an alert alone)

Alert levels = the busiest any NORMAL source ever was (+1), measured with the detector's own measure() function.
Honest evaluation, "leave one day out": for each attack day, the levels and the model are learned WITHOUT that day,
then that day is scanned: is each attack type caught on its own among the day's normal traffic, and does the day's
normal traffic alone raise anything (false alarms)? Every attack day has attack types the other days do not have.

Two labelling gaps in the dataset are handled (both documented by CIC / KU Leuven):
  * 172.16.0.1 is the gateway every attack enters through: its few "BENIGN" connections are attack-side traffic
    (e.g. a port scan of 192.168.10.51 on Thursday), so they are never used as normal traffic.
  * Thursday 19:25-20:55 UTC: the infected Vista machine 192.168.10.8 port-scans the internal network
    (CIC's infiltration scenario); the corrected labels leave that scan "BENIGN" - it is treated as an attack.
Run from the backend folder (about 5-10 minutes, about 1.5 GB RAM):
    python -m app.ml.training.train_network_traffic
"""
import json
import os
import sys
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from app.detectors import network_traffic as NT

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data", "network", "network_flows.csv.gz")
MODELS = os.path.join(HERE, "..", "models")
OUT_JSON = os.path.join(MODELS, "network_traffic.json")
OUT_MODEL = os.path.join(MODELS, "network_flow.joblib")
GATEWAY = "172.16.0.1"
VISTA = ("192.168.10.8", "Thursday", "2017-07-06 19:25:00", "2017-07-06 20:55:00")
ATTACK_DAYS = ["Tuesday", "Wednesday", "Thursday", "Friday"]
MIN_LEVEL = 5
FP_QUANTILE = 0.999        # model level: flags 0.1% of normal training connections


def load() -> pd.DataFrame:
    t0 = time.time()
    df = pd.read_csv(DATA, usecols=lambda c: c != "attempted",
                     dtype={"day": "category", "src_ip": "category", "dst_ip": "category", "label": "category"})
    df["ts"] = pd.to_datetime(df["timestamp"], format="%d/%m/%Y %I:%M:%S %p").astype("int64") // 10**9
    df.drop(columns=["timestamp"], inplace=True)
    for c in ("duration", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes", "syn_flags", "rst_flags", "fin_flags"):
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).clip(lower=0).astype("float32")
    lab = df["label"].astype(str).str.replace(" - Attempted", "", regex=False)
    gw = (df["src_ip"] == GATEWAY) | (df["dst_ip"] == GATEWAY)
    t_a = pd.Timestamp(VISTA[2]).value // 10**9
    t_b = pd.Timestamp(VISTA[3]).value // 10**9
    vista = (df["src_ip"] == VISTA[0]) & (df["day"] == VISTA[1]) & (df["ts"] >= t_a) & (df["ts"] < t_b)
    benign = lab == "BENIGN"
    lab = lab.where(~(benign & vista), "Infiltration - Portscan (unlabelled in the dataset)")
    df["attack"] = lab.where(~(benign & gw & ~vista), "attacker-gateway traffic (unlabelled)").astype("category")
    df["attempt"] = df["label"].astype(str).str.endswith("Attempted")
    print(f"Loaded {len(df):,} connections ({time.time() - t0:.0f}s)", flush=True)
    return df


def to_flows(d: pd.DataFrame) -> list:
    proto = d["protocol"].to_numpy()
    bpk, rst, fby, bby = (d[c].to_numpy() for c in ("bwd_packets", "rst_flags", "fwd_bytes", "bwd_bytes"))
    failed = (proto == 6) & ((bpk == 0) | ((rst > 0) & (fby == 0) & (bby == 0)))
    return [NT.Flow(float(t), s, int(sp), ds, int(dp), int(p), float(du), float(fp), float(bp), float(fb), float(bb),
                    float(sy), float(rs), float(fi), bool(fa), True)
            for t, s, sp, ds, dp, p, du, fp, bp, fb, bb, sy, rs, fi, fa in zip(
                d["ts"].to_numpy(), d["src_ip"].astype(str).to_numpy(), d["src_port"].to_numpy(),
                d["dst_ip"].astype(str).to_numpy(), d["dst_port"].to_numpy(), proto, d["duration"].to_numpy(),
                d["fwd_packets"].to_numpy(), bpk, fby, bby, d["syn_flags"].to_numpy(), rst,
                d["fin_flags"].to_numpy(), failed)]


def busiest_normal(df: pd.DataFrame, days) -> dict:
    """Largest burst of every behaviour among NORMAL traffic of these days (each day measured on its own)."""
    best = {k: 0 for k in NT.DEFAULTS}
    for day in days:
        d = df[(df["day"] == day) & (df["attack"] == "BENIGN")]
        for cat, by_key in NT.measure(to_flows(d)).items():
            if by_key:
                best[cat] = max(best[cat], max(v[0] for v in by_key.values()))
    return best


def levels(best: dict) -> dict:
    return {k: max(MIN_LEVEL, v + 1) for k, v in best.items()}


def evaluate_day(df, day, cfg) -> dict:
    d = df[df["day"] == day]
    normal = d[d["attack"] == "BENIGN"]
    normal_flows = to_flows(normal)
    false = NT.incidents(normal_flows, cfg)
    caught = {}
    for lab in sorted(set(d["attack"].astype(str)) - {"BENIGN", "attacker-gateway traffic (unlabelled)"}):
        att = d[d["attack"] == lab]
        inc = NT.incidents(normal_flows + to_flows(att), cfg)
        srcs = set(att["src_ip"].astype(str))
        hits = sorted({i["category"] for i in inc if i["source"] in srcs})
        caught[lab] = {"connections": len(att), "caught_by": hits}
    return {"false_incidents": [f"{i['category']}: {i['text']}" for i in false], "attacks": caught}


def feature_matrix(d: pd.DataFrame) -> np.ndarray:
    """Vectorised NT.features() (checked against it below)."""
    port = d["dst_port"].to_numpy()
    svc = np.full(len(d), 12, dtype=np.float32)
    svc[port < 49152] = 11
    svc[port < 1024] = 10
    for ports, c in reversed(NT._SVC):
        svc[np.isin(port, list(ports))] = c
    cols = [svc, d["protocol"].to_numpy(dtype=np.float32)]
    cols += [np.log1p(d[c].to_numpy(dtype=np.float64)) for c in
             ("duration", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes")]
    cols += [d[c].to_numpy(dtype=np.float32) for c in ("syn_flags", "rst_flags", "fin_flags")]
    return np.column_stack(cols).astype(np.float32)


def train_model(X, y):
    from sklearn.ensemble import HistGradientBoostingClassifier
    m = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1, categorical_features=[0, 1],
                                       class_weight="balanced", random_state=0)
    m.fit(X, y)
    return m


def main():
    if not os.path.exists(DATA):
        sys.exit(f"{DATA} is missing - run download_network_data.py and prepare_network_data.py first.")
    df = load()
    days = list(df["day"].cat.categories)
    report = {"data": "CIC-IDS2017, corrected by Engelen et al. (KU Leuven, WTMC 2021): "
                      f"{len(df):,} connections, Monday-Friday", "levels_rule": f"busiest normal source + 1, "
                      f"at least {MIN_LEVEL}", "window_seconds": NT.WINDOW_S, "held_out_days": {}}

    # 1) behaviour levels: leave one attack day out
    for day in ATTACK_DAYS:
        t0 = time.time()
        cfg = levels(busiest_normal(df, [d for d in days if d != day]))
        r = evaluate_day(df, day, cfg)
        report["held_out_days"][day] = {"levels": cfg, **r}
        caught = {k: (v["caught_by"] or "MISSED") for k, v in r["attacks"].items()}
        print(f"held-out {day}: levels {cfg}\n   caught {caught}\n   false incidents on normal traffic: "
              f"{len(r['false_incidents'])}  ({time.time() - t0:.0f}s)", flush=True)
        for f in r["false_incidents"][:5]:
            print(f"     - {f}")

    best = busiest_normal(df, days)
    cfg = levels(best)
    report["busiest_normal"] = best
    report["thresholds"] = cfg
    print(f"\nFinal levels from all normal traffic: {cfg}", flush=True)

    # 2) supporting per-connection model (attempts carry no payload: left out; unlabelled attack-side traffic too)
    use = df[~df["attempt"] & (df["attack"] != "attacker-gateway traffic (unlabelled)")]
    X = feature_matrix(use)
    sample = use.sample(2000, random_state=1)
    ref = np.asarray([NT.features(f) for f in to_flows(sample)], dtype=np.float32)
    if not np.allclose(feature_matrix(sample), ref, atol=1e-4):
        sys.exit("feature check failed: the training features differ from the detector's - not saving anything")
    y = (use["attack"] != "BENIGN").to_numpy().astype(int)
    dayv = use["day"].astype(str).to_numpy()
    labv = use["attack"].astype(str).to_numpy()
    from sklearn.metrics import roc_auc_score
    report["model_held_out_days"] = {}
    for day in ATTACK_DAYS:
        t0 = time.time()
        tr, te = dayv != day, dayv == day
        m = train_model(X[tr], y[tr])
        level = float(np.quantile(m.predict_proba(X[tr][y[tr] == 0][::10])[:, 1], FP_QUANTILE))
        p = m.predict_proba(X[te])[:, 1]
        r = {"auc": round(float(roc_auc_score(y[te], p)), 4),
             "normal_flagged": round(float((p[y[te] == 0] >= level).mean()), 4),
             "caught_share": {lab: round(float((p[labv[te] == lab] >= level).mean()), 3)
                              for lab in sorted(set(labv[te]) - {"BENIGN"})}}
        report["model_held_out_days"][day] = r
        print(f"model, held-out {day}: AUC {r['auc']}  normal connections flagged {r['normal_flagged']:.2%}  "
              f"caught {r['caught_share']}  ({time.time() - t0:.0f}s)", flush=True)
    m = train_model(X, y)
    level = float(np.quantile(m.predict_proba(X[y == 0][::10])[:, 1], FP_QUANTILE))
    trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    import joblib
    os.makedirs(MODELS, exist_ok=True)
    joblib.dump({"model": m, "threshold": level, "trained_at": trained_at,
                 "features": ["service", "protocol", "log duration", "log fwd packets", "log bwd packets",
                              "log fwd bytes", "log bwd bytes", "SYN", "RST", "FIN"],
                 "role": "supporting evidence only - never raises an alert alone"}, OUT_MODEL + ".part")
    os.replace(OUT_MODEL + ".part", OUT_MODEL)
    report["model_threshold"] = level
    report["trained_at"] = trained_at
    with open(OUT_JSON + ".part", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    os.replace(OUT_JSON + ".part", OUT_JSON)
    print(f"\nSaved {os.path.abspath(OUT_JSON)}\nSaved {os.path.abspath(OUT_MODEL)}")


if __name__ == "__main__":
    main()
