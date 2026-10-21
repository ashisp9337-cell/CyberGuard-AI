"""
Copy a small, balanced sample of the urlscan page copies (data/urlscan/dom/*.html.gz) to backend/fl_sample/, so the
Fake Login model's feature code can be developed and tested on real pages. Read-only for the originals; the copies
are compressed HTML text (urlscan's stored copy of the page) - nothing is opened, run or visited.

Run from backend/:   python -m app.ml.training.sample_dom
"""
import argparse
import json
import os
import random
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data", "urlscan")
BACKEND = os.path.abspath(os.path.join(HERE, "..", "..", ".."))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30, help="pages per group (phishing / real login)")
    ap.add_argument("--out", default=os.path.join(BACKEND, "fl_sample"))
    a = ap.parse_args()
    rows = [json.loads(line) for line in open(os.path.join(DATA, "scans.jsonl"), encoding="utf-8") if line.strip()]
    have = {r["uuid"]: r for r in rows if os.path.exists(os.path.join(DATA, "dom", r["uuid"] + ".html.gz"))}
    rng = random.Random(21)
    phish = [r for r in have.values() if r["group"] == "phish" and not r.get("cloaked")]
    real, seen_sites = [], set()
    for r in sorted((r for r in have.values() if r["group"] == "genuine-login"), key=lambda r: r["uuid"]):
        if r.get("apex") not in seen_sites:                     # one page per real site, as many sites as possible
            seen_sites.add(r.get("apex"))
            real.append(r)
    pick = rng.sample(phish, min(a.n, len(phish))) + real[: a.n]
    os.makedirs(a.out, exist_ok=True)
    for r in pick:
        shutil.copy2(os.path.join(DATA, "dom", r["uuid"] + ".html.gz"), os.path.join(a.out, r["uuid"] + ".html.gz"))
    with open(os.path.join(a.out, "sample.jsonl"), "w", encoding="utf-8") as f:
        for r in pick:
            f.write(json.dumps(r) + "\n")
    print(f"copied {len(pick)} pages ({min(a.n, len(phish))} phishing, {min(a.n, len(real))} real login) to {a.out}")


if __name__ == "__main__":
    main()
