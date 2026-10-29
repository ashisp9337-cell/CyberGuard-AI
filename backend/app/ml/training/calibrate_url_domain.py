"""
Re-measure the domain-name model's "verify" level on 2026 websites (added 21 Oct). Nothing is retrained.

Why: the model (app/detectors/domain_model.py) was trained on PhiUSIIL + Tranco (2024 lists). Its own alert level is
judged on those lists. This script takes REAL websites of 2026 that the model never saw -- the Chrome UX Report
top-1M list (real Chrome traffic, monthly; cached on GitHub by zakird/crux-top-lists) minus every site in Tranco and
PhiUSIIL -- and sets the level where only 1% of them score higher (chosen on one half of the sites, checked on the
other half). It reports how many 2026 phishing domains reach that level (urlscan.io collection; optionally a list of
new Phishing.Database domains). No website is ever opened: only the NAMES are scored.

Run from backend/:   python -m app.ml.training.calibrate_url_domain
  (downloads the Chrome UX Report list once, ~9 MB, into app/ml/training/data/crux/ -- git ignores it)
Output: app/ml/models/url_domain_model.modern.json (read by app/detectors/domain_model.py)
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import urllib.request
import zipfile
from datetime import datetime, timezone

import numpy as np

from app.detectors import domain_model as DM
from app.detectors.url_features_v2 import split_url

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
CRUX = os.path.join(DATA, "crux", "current.csv.gz")
CRUX_URL = "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz"
SCANS = os.path.join(DATA, "urlscan", "scans.jsonl")
TARGET_FALSE_ALARMS = 0.01


def site_of(host: str):
    p = DM.site_parts((host or "").lower())
    return None if (p["platform"] or p["ip"] or not p["name"] or not p["site"]) else (p["site"], p["name"], p["suffix"])


def training_sites() -> set:
    """Every site the model could have seen in training (Tranco + PhiUSIIL), so the real 2026 sites are unseen."""
    out = set()
    tranco = sorted(f for f in os.listdir(DATA) if f.startswith("tranco") and f.endswith(".zip"))
    for name in tranco:
        with zipfile.ZipFile(os.path.join(DATA, name)) as z:
            with z.open(z.namelist()[0]) as f:
                for line in io.TextIOWrapper(f, encoding="utf-8", errors="replace"):
                    if "," in line:
                        out.add(line.split(",", 1)[1].strip().lower())
    phi = os.path.join(DATA, "phiusiil+phishing+url+dataset.zip")
    if os.path.exists(phi):
        import pandas as pd
        with zipfile.ZipFile(phi) as z:
            with z.open([n for n in z.namelist() if n.endswith(".csv")][0]) as f:
                urls = pd.read_csv(io.TextIOWrapper(f, encoding="utf-8", errors="replace"), usecols=["URL"])["URL"]
        out |= {s[0] for s in (site_of(split_url(str(u))["host"]) for u in urls) if s}
    if not tranco or not os.path.exists(phi):
        raise SystemExit("Needs the training lists in app/ml/training/data/: tranco_*.zip and "
                         "phiusiil+phishing+url+dataset.zip (the same files train_url_domain.py uses).")
    return out


def crux_sites() -> dict:
    if not os.path.exists(CRUX):
        os.makedirs(os.path.dirname(CRUX), exist_ok=True)
        print("Downloading the Chrome UX Report top-1M list (~9 MB) ...", flush=True)
        req = urllib.request.Request(CRUX_URL, headers={"User-Agent": "CyberGuard-calibration/1.0"})
        with urllib.request.urlopen(req, timeout=120) as r, open(CRUX + ".part", "wb") as f:
            f.write(r.read())
        os.replace(CRUX + ".part", CRUX)
    out = {}
    with gzip.open(CRUX, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            origin = line.split(",", 1)[0]
            if origin.startswith("http"):
                s = site_of(origin.split("://", 1)[1].split("/")[0].split(":")[0])
                if s:
                    out[s[0]] = s
    return out


def probs(bundle, items) -> np.ndarray:
    items = list(items)
    if not items:
        return np.array([])
    return np.concatenate([DM.probabilities(bundle, [n for _, n, _ in items[i:i + 20000]],
                                            [x for _, _, x in items[i:i + 20000]])
                           for i in range(0, len(items), 20000)])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scans", default=SCANS, help="urlscan.io collection (phishing sites to report on)")
    ap.add_argument("--phish-domains", default="", help="optional text file: one 2026 phishing domain per line")
    a = ap.parse_args()
    bundle = DM.load()
    if bundle is None:
        raise SystemExit("The domain-name model is missing: app/ml/models/url_domain_model.joblib")
    seen = training_sites()
    crux = crux_sites()
    real = sorted(v for k, v in crux.items() if k not in seen)
    p_real = probs(bundle, real)
    half = np.array([int(hashlib.md5(s.encode()).hexdigest(), 16) % 2 for s, _, _ in real])
    level = float(np.quantile(p_real[half == 0], 1 - TARGET_FALSE_ALARMS))
    other = p_real[half == 1]

    def phish_report(sites):
        sites = sorted({s for s in sites if s and s[0] not in seen and s[0] not in crux})
        p = probs(bundle, sites)
        return {"n": int(len(p)), "caught_at_verify_level": round(float((p >= level).mean()), 4) if len(p) else None,
                "caught_at_model_alert_level": round(float((p >= bundle["threshold"]).mean()), 4) if len(p) else None}
    results = {"real_2026_sites_other_half_flagged": round(float((other >= level).mean()), 4),
               "real_2026_sites_other_half_flagged_at_model_alert_level": round(float((other >= bundle["threshold"]).mean()), 4)}
    if os.path.exists(a.scans):
        rows = [json.loads(line) for line in open(a.scans, encoding="utf-8") if line.strip()]
        results["urlscan_2026_phishing_sites"] = phish_report(
            site_of(split_url(r["page_url"])["host"]) for r in rows if r.get("group") == "phish" and r.get("page_url"))
    if a.phish_domains and os.path.exists(a.phish_domains):
        results["extra_phishing_domains"] = phish_report(
            site_of(line.strip()) for line in open(a.phish_domains, encoding="utf-8", errors="replace") if line.strip())
    info = {"verify_level": level, "model_trained_at": (bundle.get("card") or {}).get("trained_at"),
            "model_alert_level": bundle["threshold"], "target": "1% of real 2026 sites the model never saw",
            "data": f"Chrome UX Report top-1M ({CRUX_URL}): {len(real):,} real sites not in Tranco / PhiUSIIL",
            "results": results, "calibrated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    out = os.path.join(os.path.dirname(DM.MODEL_PATH), "url_domain_model.modern.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2)
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
