"""
Train the domain-name phishing model (Module 5: Malicious URL & Website Detection).

Real data only:
  * PhiUSIIL Phishing URL Dataset (UCI #967, CC BY 4.0, 2024): 100,945 phishing + 134,850 legitimate URLs
      https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
  * Tranco top-1M list (research ranking of real popular sites): https://tranco-list.eu/
Put the downloaded zips (do NOT unzip them) in backend/app/ml/training/data/:
    phiusiil+phishing+url+dataset.zip   (or PhiUSIIL_Phishing_URL_Dataset.csv)
    tranco_*.zip                         (or top-1m.csv)

Run from backend/:   python -m app.ml.training.train_url_domain
Output: app/ml/models/url_domain_model.joblib (+ .metrics.json)

Shortcuts found in PhiUSIIL and how they are avoided (checked before training):
  * 100% of legitimate URLs are "https://www.<domain>" homepages -> we use only the registered
    domain NAME on both sides, so scheme / www / path cannot be learned.
  * Its page features (password fields etc.) were collected after most phishing pages were taken
    down (46% have < 10 lines of HTML) -> NOT used. Fake-login pages are checked live at scan time.
  * All hosting-platform names (x.web.app, x.firebaseapp.com...) are phishing in the data, because
    the legitimate lists never contain them -> excluded; a rule covers hosting platforms instead.
  * Domains that appear on BOTH sides (hacked popular sites) -> dropped from both.
Evaluation: 20% of domains held out, plus 30% of Tranco never used for training (false alarms on
real popular sites, by rank, and on Indian .in sites).
"""
import glob
import json
import os
import re
import sys
import time
import warnings
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd

from app.detectors import domain_model as DM

warnings.filterwarnings("ignore", category=UserWarning)
HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
OUT = os.path.join(HERE, "..", "models", "url_domain_model.joblib")
TARGET_FALSE_ALARMS = 0.01      # alert threshold: flag at most 1% of held-out legitimate domains


def find(patterns):
    for p in patterns:
        hits = sorted(glob.glob(os.path.join(DATA, p)))
        if hits:
            return hits[0]
    return None


def hosts_of(urls: pd.Series) -> pd.Series:
    return (urls.astype(str).str.replace(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", regex=True)
            .str.split(r"[/?#]", regex=True).str[0].str.split("@").str[-1].str.split(":").str[0]
            .str.lower().str.rstrip("."))


def main() -> int:
    t0 = time.time()
    phi = find(["phiusiil*.zip", "PhiUSIIL*.csv"])
    tra = find(["tranco*.zip", "top-1m.csv*"])
    if not phi or not tra:
        sys.exit(f"Missing data in {DATA}: need the PhiUSIIL zip/csv and the Tranco zip/csv (see header).")
    print(f"PhiUSIIL: {os.path.basename(phi)}\nTranco:   {os.path.basename(tra)}")
    d = pd.read_csv(phi, usecols=["URL", "label"])                 # label 1 = legitimate, 0 = phishing
    t = pd.read_csv(tra, header=None, names=["rank", "dom"])

    def rows(hosts, labels, ranks=None):
        out = []
        for i, (h, y) in enumerate(zip(hosts, labels)):
            p = DM.site_parts(h)
            if p["ip"] or not p["name"]:
                continue
            out.append((p["name"], p["suffix"], p["site"], bool(p["platform"]), int(y),
                        int(ranks[i]) if ranks is not None else 0))
        return pd.DataFrame(out, columns=["name", "suffix", "site", "platform", "y", "rank"])

    D = rows(hosts_of(d["URL"]), 1 - d["label"]).drop_duplicates("site")
    T = rows(t["dom"].astype(str).str.lower(), [0] * len(t), t["rank"].to_numpy()).drop_duplicates("site")
    print(f"Parsed domains in {time.time() - t0:.0f}s: PhiUSIIL {len(D):,}, Tranco {len(T):,}")
    phish_sites = set(D.loc[D.y == 1, "site"])
    ambiguous = phish_sites & (set(T.site) | set(D.loc[D.y == 0, "site"]))
    platform_phish = int((D.platform & (D.y == 1)).sum())
    D = D[~D.site.isin(ambiguous) & ~D.platform]
    T = T[~T.site.isin(ambiguous) & ~T.platform & ~T.site.isin(set(D.site))]
    rng = np.random.default_rng(0)
    T["holdout"] = rng.random(len(T)) < 0.3
    legit = pd.concat([D[D.y == 0], T[~T.holdout].sample(min(250_000, int((~T.holdout).sum())), random_state=0)])
    data = pd.concat([legit, D[D.y == 1]]).sample(frac=1, random_state=1).reset_index(drop=True)
    data["test"] = rng.random(len(data)) < 0.2
    tr, te, TH = data[~data.test], data[data.test], T[T.holdout]
    print(f"Phishing domains {int((data.y == 1).sum()):,} | legitimate {int((data.y == 0).sum()):,} | "
          f"dropped: {len(ambiguous):,} on both sides, {platform_phish:,} on hosting platforms")

    g = tr.groupby("suffix").y.agg(["sum", "count"])
    prior = float(tr.y.mean())
    tld_rate = ((g["sum"] + 20 * prior) / (g["count"] + 20)).to_dict()      # smoothed phishing share per TLD

    def X(df):
        return np.asarray([DM.name_features(n, s, tld_rate, prior) for n, s in zip(df.name, df.suffix)], dtype=np.float32)

    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import average_precision_score, roc_auc_score

    hgb = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, random_state=0).fit(X(tr), tr.y)
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True, max_features=200_000)
    lr = LogisticRegression(C=2, max_iter=2000).fit(vec.fit_transform([DM.text_of(n, s) for n, s in zip(tr.name, tr.suffix)]), tr.y)
    bundle = {"kind": DM.BUNDLE_KIND, "version": DM.BUNDLE_VERSION, "features": DM.FEATURES,
              "hgb": hgb, "lr": lr, "vec": vec, "tld_rate": tld_rate, "prior": prior, "threshold": 0.5}

    def P(df):
        return DM.probabilities(bundle, df.name, df.suffix)

    print(f"Trained in {time.time() - t0:.0f}s, evaluating ...")
    p = P(te)
    yte = te.y.to_numpy()
    thr = float(np.quantile(p[yte == 0], 1 - TARGET_FALSE_ALARMS))
    bundle["threshold"] = thr
    ph = P(TH)
    buckets = {"top_10k": (0, 1e4), "10k_100k": (1e4, 1e5), "100k_1M": (1e5, 1e6)}
    metrics = {
        "held_out_domains": int(len(te)), "held_out_phishing": int(yte.sum()),
        "roc_auc": round(float(roc_auc_score(yte, p)), 4),
        "pr_auc": round(float(average_precision_score(yte, p)), 4), "phishing_share": round(float(yte.mean()), 4),
        "alert_threshold": round(thr, 4),
        "phishing_caught_at_threshold": round(float((p[yte == 1] >= thr).mean()), 4),
        "legit_flagged_at_threshold": round(float((p[yte == 0] >= thr).mean()), 4),
        "unseen_popular_sites_flagged": {k: round(float((ph[(TH["rank"] > lo) & (TH["rank"] <= hi)] >= thr).mean()), 4)
                                         for k, (lo, hi) in buckets.items()},
        "unseen_indian_in_sites_flagged": round(float((ph[TH.suffix.str.endswith("in").to_numpy()] >= thr).mean()), 4),
    }
    card = {"model": "HistGradientBoosting (name features) + char 3-5-gram LogisticRegression, averaged",
            "data": [os.path.basename(phi), os.path.basename(tra)],
            "sources": ["https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset (CC BY 4.0)",
                        "https://tranco-list.eu/"],
            "scope": "registered domain name only (scheme, www, path, page content NOT used -- see header)",
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "metrics": metrics}
    bundle["card"] = card
    print(json.dumps(metrics, indent=2))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    joblib.dump(bundle, OUT, compress=3)
    with open(OUT.replace(".joblib", ".metrics.json"), "w") as f:
        json.dump(card, f, indent=2)
    print(f"Saved -> {OUT}  ({os.path.getsize(OUT) / 1e6:.1f} MB, {time.time() - t0:.0f}s total)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
