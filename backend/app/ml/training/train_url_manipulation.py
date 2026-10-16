"""
Train the URL Manipulation model (URL Security -> "URL manipulation").

Data (real links with full paths and queries on BOTH sides -- needed to learn link structure):
  * DEPHIDES (github.com/ebubekirbbr/dephides, MIT licence, IEEE 2023): 520k URLs -- phishing from PhishTank,
    legitimate pages crawled by CommonCrawl. Use the small_dataset/*.txt files.
  * "Malicious URLs dataset" (Kaggle: sid321axn/malicious-urls-dataset, 651k URLs -- benign, phishing,
    malware, defacement; from ISCX-URL-2016, PhishTank, PhishStorm, malware lists): adds malware downloads.
    Both sources contain both classes, so the model cannot tell "malicious" from "which dataset".
  * PhiUSIIL Phishing URL Dataset (UCI, already in data/) -- used ONLY as a third, independent test.

Known shortcut in these datasets, removed on purpose: the scheme and "www." differ by class (DEPHIDES: 67% of
legitimate links are https vs 2% of phishing; Kaggle: the reverse pattern for "www."), so a model could score the prefix instead of the link. Every link is
normalised (scheme and leading "www." dropped) before features are computed -- see
app/detectors/url_manipulation.py, which the scanner also uses.

Only links with a path or query are used (a bare domain has no structure to manipulate, and in this dataset
bare domains are almost all "malicious" -- another collection artefact). Joomla page links are left out
(on the malicious side they come from the dataset's defaced-website category). At most 30 links per website.
Split: by website (registered domain), 70% train / 10% calibration / 20% test, so the test only contains
links from sites the model has never seen. Alert level = 1% false alarms, verify level = 5%, on benign links.
Model: HistGradientBoostingClassifier; explicit tricks ('@' trick, disguised IP, double encoding, encoded
'../', link-inside-link, program download) are constrained so they can only RAISE the risk.

Run from backend/ (a few minutes):
    python -m app.ml.training.train_url_manipulation --data dephides/small_dataset/*.txt malicious_phish.csv

Output: app/ml/models/url_manipulation.joblib  +  url_manipulation.metrics.json
"""
import argparse
import glob
import hashlib
import io
import json
import os
import sys
import time
import zipfile
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

from app.detectors import url_manipulation as M
from app.detectors.lookalike_domain import split_domain

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
MODELS_DIR = os.path.join(HERE, "..", "models")
SEED = 42
PER_SITE = 30
MONOTONIC = {"userinfo_at": 1, "host_odd_ip": 1, "double_encoding": 1, "encoded_dot_segments": 1,
             "redirect_param_with_url": 1, "exec_download": 1}


def split_of(key: str) -> str:
    h = int(hashlib.md5(key.encode()).hexdigest(), 16) % 10
    return "train" if h < 7 else "cal" if h == 7 else "test"


def site_of(url: str) -> str:
    host = M.split(M.normalise(url))[1]
    if not host or host.replace(".", "").isdigit() or host.startswith("["):
        return host or "?"
    return split_domain(host)[0] or host


def metrics(y, p, thr_alert, thr_verify):
    y, p = np.asarray(y), np.asarray(p)
    pos, neg = y == 1, y == 0
    out = {"n": int(len(y)), "positives": int(pos.sum())}
    if pos.any() and neg.any():
        out.update(auc=round(float(roc_auc_score(y, p)), 4), avg_precision=round(float(average_precision_score(y, p)), 4))
    for name, t in (("alert", thr_alert), ("verify", thr_verify)):
        if pos.any():
            out[f"caught_at_{name}"] = round(float((p[pos] >= t).mean()), 4)
        if neg.any():
            out[f"false_alarms_at_{name}"] = round(float((p[neg] >= t).mean()), 4)
    return out


def load(path):
    """One dataset -> DataFrame(url, y, norm, source). Accepts the Kaggle CSV (url,type / url,label) or the
    DEPHIDES text files ("legitimate|phishing<TAB>url")."""
    if path.endswith(".txt"):
        d = pd.read_csv(path, sep="\t", header=None, names=["label", "url"], quoting=3, on_bad_lines="skip",
                        dtype=str)
        d = d[d["label"].isin(["legitimate", "phishing"])]
        d["y"] = (d["label"] == "phishing").astype(int)
        source = "dephides"
    else:
        d = pd.read_csv(path, dtype=str)
        if "type" in d.columns:                               # original Kaggle file
            d["y"] = (d["type"].astype(str).str.lower() != "benign").astype(int)
        else:
            d["y"] = d["label"].astype(str).str.lower().isin(["bad", "malicious", "phishing", "1"]).astype(int)
        source = "kaggle"
    d = d.dropna(subset=["url"])
    d["norm"] = [M.normalise(str(u)) for u in d["url"]]
    d["source"] = source
    return d[["url", "y", "norm", "source"]]


def load_all(paths):
    d = pd.concat([load(p) for p in paths], ignore_index=True)
    d = d[d["norm"].str.len() > 3]
    conflict = d.groupby("norm")["y"].nunique()
    return d[~d["norm"].isin(conflict[conflict > 1].index)].drop_duplicates("norm")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", nargs="+", default=sorted(glob.glob(os.path.join(DATA_DIR, "malicious_phish*.csv"))
                                                        + glob.glob(os.path.join(DATA_DIR, "dephides", "*.txt"))))
    ap.add_argument("--phiusiil", default=(glob.glob(os.path.join(DATA_DIR, "phiusiil*.zip")) or [""])[0])
    ap.add_argument("--out", default=MODELS_DIR)
    ap.add_argument("--quick", action="store_true", help="tiny run (automated tests only)")
    a = ap.parse_args()
    if not a.data or not all(os.path.exists(p) for p in a.data):
        sys.exit("Give the datasets with --data (DEPHIDES small_dataset/*.txt and/or the Kaggle malicious_phish.csv)")
    t0 = time.time()

    d = load_all(a.data)
    # only links with a path or query (a bare domain has no structure to manipulate -- and in this dataset
    # bare domains are mostly "malicious", a collection artefact the model must not learn)
    d = d[[M.has_structure(u) for u in d["url"]]]
    # Joomla page links (index.php?option=com_...) are almost all on the "malicious" side only because the
    # dataset's defaced-website category is full of them -- that is about the site, not the link, so they are
    # left out of training on both sides
    d = d[~d["url"].astype(str).str.contains("option=com_", regex=False)]
    # at most 30 links per website, so a few huge sites do not dominate training or the alert levels
    d["site"] = [site_of(u) for u in d["url"]]
    d = d.sample(frac=1.0, random_state=SEED).groupby("site", group_keys=False).head(PER_SITE)
    if a.quick:
        d = d.sample(min(len(d), 4000), random_state=SEED)
    feats = [M.manipulation_features(u)[0] for u in d["url"]]
    X = np.array(feats, dtype=float)
    y = d["y"].to_numpy()
    grp = np.array([split_of(x) for x in d["site"]])
    print(f"{len(y):,} unique links ({int(y.sum()):,} malicious) ({time.time() - t0:.0f}s)")
    for s_, g in d.groupby("source"):
        print(f"  source {s_}: {len(g):,} links, {int(g['y'].sum()):,} malicious")
    for s in ("train", "cal", "test"):
        m = grp == s
        print(f"  {s:5s}: {int(y[m].sum()):7,} malicious  {int((y[m] == 0).sum()):7,} benign")

    tr = grp == "train"
    w = np.where(y[tr] == 1, (y[tr] == 0).sum() / max((y[tr] == 1).sum(), 1), 1.0)
    cst = [MONOTONIC.get(n, 0) for n in M.FEATURES]
    model = HistGradientBoostingClassifier(max_iter=40 if a.quick else 400, learning_rate=0.08, max_leaf_nodes=63,
                                           min_samples_leaf=40, l2_regularization=1.0, monotonic_cst=cst,
                                           early_stopping=False, random_state=SEED)
    model.fit(X[tr], y[tr], sample_weight=w)

    cal_neg = (grp == "cal") & (y == 0)
    p_cal = model.predict_proba(X[cal_neg])[:, 1]
    thr_alert = max(float(np.quantile(p_cal, 0.99)), 0.5)
    thr_verify = max(min(float(np.quantile(p_cal, 0.95)), thr_alert), 0.3)
    print(f"alert level {thr_alert:.3f}   verify level {thr_verify:.3f}")

    te = grp == "test"
    p_te = model.predict_proba(X[te])[:, 1]
    res = {"heldout_sites": metrics(y[te], p_te, thr_alert, thr_verify)}
    src_te = d["source"].to_numpy()[te]
    for s_ in sorted(set(src_te)):
        m = src_te == s_
        res[f"heldout_sites_{s_}"] = metrics(y[te][m], p_te[m], thr_alert, thr_verify)
    urls_te, y_te, Xt = d["url"].to_numpy()[te], y[te], X[te]
    order = np.argsort(-p_te)

    def pick(idx, n):
        return [(str(urls_te[i])[:120], round(float(p_te[i]), 3)) for i in idx[:n]]

    res["examples_caught"] = pick([i for i in order[:5000] if y_te[i] == 1], 15)
    res["examples_false_alarms"] = pick([i for i in order[:20000] if y_te[i] == 0 and p_te[i] >= thr_alert], 15)
    res["examples_missed"] = pick([i for i in order[::-1][:20000] if y_te[i] == 1], 10)
    # each explicit trick: how often it appears in benign vs malicious test links
    res["tricks_in_test_links"] = {
        n: {"malicious": int((Xt[y_te == 1, M.FEATURES.index(n)] > 0).sum()),
            "benign": int((Xt[y_te == 0, M.FEATURES.index(n)] > 0).sum())}
        for n in MONOTONIC}

    # independent test: PhiUSIIL phishing links (other collectors, other years) vs the benign test links
    if a.phiusiil and os.path.exists(a.phiusiil):
        with zipfile.ZipFile(a.phiusiil) as z:
            name = [n for n in z.namelist() if n.endswith(".csv")][0]
            with z.open(name) as f:
                ph = pd.read_csv(io.TextIOWrapper(f, encoding="utf-8", errors="replace"), usecols=["URL", "label"],
                                 nrows=20_000 if a.quick else None)
        ph_bad = ph[ph["label"] == 0]["URL"].astype(str)
        ph_bad = ph_bad[~ph_bad.map(M.normalise).isin(set(d["norm"])) & ph_bad.map(M.has_structure)]
        Xp = np.array([M.manipulation_features(u)[0] for u in ph_bad], dtype=float)
        pp = model.predict_proba(Xp)[:, 1]
        res["independent_phiusiil_phishing_links"] = {
            "n": int(len(pp)), "caught_at_alert": round(float((pp >= thr_alert).mean()), 4),
            "caught_at_verify": round(float((pp >= thr_verify).mean()), 4)}
        res["note_phiusiil"] = ("PhiUSIIL's legitimate URLs are bare homepages (no path), which this model does "
                                "not judge, so false alarms are measured on the benign held-out links above.")

    os.makedirs(a.out, exist_ok=True)
    bundle = {"kind": "cyberguard-url-manipulation", "version": 1, "features": list(M.FEATURES), "model": model,
              "thr_alert": thr_alert, "thr_verify": thr_verify,
              "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    joblib.dump(bundle, os.path.join(a.out, "url_manipulation.joblib"), compress=3)
    info = {"model": "HistGradientBoostingClassifier", "features": list(M.FEATURES),
            "data": {"links": int(len(y)), "malicious": int(y.sum()),
                     "train_malicious": int((y[tr] == 1).sum()), "train_benign": int((y[tr] == 0).sum()),
                     "sources": ["DEPHIDES (PhishTank + CommonCrawl, MIT)",
                                 "Malicious URLs dataset (Kaggle sid321axn: ISCX-URL-2016, PhishTank, PhishStorm, "
                                 "malware domain lists)", "PhiUSIIL Phishing URL Dataset (UCI, test only)"],
                     "normalisation": "scheme and leading www. removed (dataset collection shortcut)"},
            "thr_alert": thr_alert, "thr_verify": thr_verify, "results": res, "trained_at": bundle["trained_at"]}
    with open(os.path.join(a.out, "url_manipulation.metrics.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2, ensure_ascii=False)
    print(json.dumps({k: v for k, v in res.items() if not k.startswith("examples")}, indent=2))
    print(f"done in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    sys.exit(main())
