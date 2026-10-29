"""
Re-measure the URL-manipulation model's alert / verify levels on MODERN links (added 21 Oct).

Why: the model was trained on 2010s-2020s link datasets (DEPHIDES, Kaggle). A QR benchmark on 21 Oct showed that on
real 2026 links it flags far too many real pages (long OAuth / tracking / Google Forms links). This script takes
the real and phishing page addresses from the urlscan.io collection (data/urlscan/scans.jsonl), keeps those with
a path or query, splits the real ones by WEBSITE into two halves, picks the levels on one half (1% / 5% of real
links) and reports the result on the other half and on 2026 phishing. Nothing is retrained.

Run from backend/:   python -m app.ml.training.calibrate_url_manipulation
Output: app/ml/models/url_manipulation.modern.json (read by app/detectors/url_manipulation.py)
"""
import argparse
import hashlib
import json
import os
from datetime import datetime, timezone

import numpy as np

from app.detectors import url_manipulation as UM
from app.detectors.url_features_v2 import registered_domain, split_url

HERE = os.path.dirname(os.path.abspath(__file__))
SCANS = os.path.join(HERE, "data", "urlscan", "scans.jsonl")


def probabilities(urls):
    out = []
    for u in urls:
        a = UM.assess(u)
        if a is None or (a.get("noPath") and not a["findings"]):
            continue
        out.append((registered_domain(split_url(u)["host"]), a["probability"]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scans", default=SCANS)
    a = ap.parse_args()
    if os.path.exists(UM.CALIBRATION_PATH):
        os.remove(UM.CALIBRATION_PATH)          # measure the model itself, not an earlier calibration
    UM._cache.clear()
    rows = [json.loads(line) for line in open(a.scans, encoding="utf-8") if line.strip()]
    real = probabilities(r["page_url"] for r in rows if r["group"] in ("genuine-login", "genuine-web") and r.get("page_url"))
    phish = probabilities(r["page_url"] for r in rows if r["group"] == "phish" and r.get("page_url"))
    half = lambda s: int(hashlib.md5(s.encode()).hexdigest(), 16) % 2          # noqa: E731
    cal = np.array([p for s, p in real if half(s) == 0])
    test = np.array([p for s, p in real if half(s) == 1])
    ph = np.array([p for _, p in phish])
    ta, tv = float(np.quantile(cal, 0.99)), float(np.quantile(cal, 0.95))
    b = UM.load_model()

    def rates(alert, verify):
        return {"real_links_other_half_flagged_at_alert": round(float((test >= alert).mean()), 4),
                "real_links_other_half_flagged_at_verify": round(float((test >= verify).mean()), 4),
                "phishing_2026_caught_at_alert": round(float((ph >= alert).mean()), 4),
                "phishing_2026_caught_at_verify": round(float((ph >= verify).mean()), 4)}
    info = {"thr_alert": ta, "thr_verify": tv, "model_trained_at": b.get("trained_at"),
            "data": f"urlscan.io page addresses with a path: {len(real)} real ({len({s for s, _ in real})} sites), "
                    f"{len(phish)} phishing",
            "old_levels": {"thr_alert": b["thr_alert"], "thr_verify": b["thr_verify"], **rates(b["thr_alert"], b["thr_verify"])},
            "new_levels": rates(ta, tv),
            "note": "The statistical part of the model hardly separates 2026 phishing from real links; at levels that "
                    "keep real links quiet it rarely fires. Explicit tricks still force alert / verify.",
            "calibrated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    with open(UM.CALIBRATION_PATH, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2)
    UM._cache.clear()
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
