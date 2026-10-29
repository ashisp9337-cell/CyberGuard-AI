"""
Train the API-abuse / web-attack request model (module 6, "API Abuse Detection"). Real data only.

DATA (downloaded by this script from GitHub, each file pinned to one commit and checked by SHA-256; ~130 MB in total,
saved in app/ml/training/data/api_abuse/ which git ignores). The files are plain text: they are only READ, never run
or opened in a browser. Windows Defender may still warn about the attack text inside them - that is expected.
  * CSIC 2010 HTTP dataset (Spanish National Research Council): 36,000 normal training requests, 36,000 normal test
    requests and 25,065 attack / anomalous requests to an e-commerce web application.  https://www.tic.itefi.csic.es/dataset/
  * HttpParams dataset (MIT licence): attack values made with sqlmap, XSSYA, Vega and FuzzDB.  github.com/Morzeux/HttpParamsDataset
  * DEPHIDES (MIT licence): real links from CommonCrawl - here only the LEGITIMATE ones, as normal web requests
    from thousands of different websites.  github.com/ebubekirbbr/dephides
  * Fwaf (no licence stated) - TEST ONLY, never trained on: 1.29 million real web-log queries and 48,000 attack
    queries from another source.  github.com/faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall

HONEST TESTS (all on data the model never saw):
  * CSIC: the official normal TEST file + half of the attacks (the other half trains)
  * HttpParams: half of the values
  * DEPHIDES: 20% of the WEBSITES are held out completely (no page of them is trained on)
  * Fwaf: a completely different collection (independent test)
  * urlscan.io 2026 real pages from data/urlscan/scans.jsonl if present (real requests of 2026)
  * whole LOGS: 20 random real requests per log - how many normal logs get flagged
Alert / verify levels are chosen on 10% of the DEPHIDES websites (not used for training or testing).

Run from backend/ (venv active):
    python -m app.ml.training.train_api_abuse --download     # first time: downloads + checks the data (~130 MB)
    python -m app.ml.training.train_api_abuse                # trains + tests, ~2-5 minutes, ~2 GB RAM
Output: app/ml/models/api_abuse.joblib (+ api_abuse.metrics.json). The previous model is kept as api_abuse.previous.joblib.
"""
import argparse
import csv
import hashlib
import json
import os
import random
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

import numpy as np

from app.detectors import api_abuse as AA

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data", "api_abuse")
MODELS_DIR = os.path.join(HERE, "..", "models")
SEED = 42
GH = "https://raw.githubusercontent.com/"
FILES = {   # local name: (download URL pinned to a commit, SHA-256)
    "csic_normalTrafficTraining.txt": (
        GH + "baksakal/HTTP-DATASET-CSIC-2010-MACHINE-LEARNING-GUI-AND-SERVER/87c6c2c3519f7eb0662cef2244ddc76f89bf48eb/normalTrafficTraining.txt",
        "d3344377d4721b03b906ca232ab44bfd81b9c1356f967ec9d348532ec420f000"),
    "csic_normalTrafficTest.txt": (
        GH + "baksakal/HTTP-DATASET-CSIC-2010-MACHINE-LEARNING-GUI-AND-SERVER/87c6c2c3519f7eb0662cef2244ddc76f89bf48eb/normalTrafficTest.txt",
        "f4526669566789be7fd99f79e1bc2989ab39e74ab7ed5d667621fe23dce4ea6f"),
    "csic_anomalousTrafficTest.txt": (
        GH + "baksakal/HTTP-DATASET-CSIC-2010-MACHINE-LEARNING-GUI-AND-SERVER/87c6c2c3519f7eb0662cef2244ddc76f89bf48eb/anomalousTrafficTest.txt",
        "ec77d784966896330869c5b596ede6a716101c14b5f139144915bb10822a03e1"),
    "httpparams_payload_full.csv": (
        GH + "Morzeux/HttpParamsDataset/926670a710283f87c05b554680facf3f9530548c/payload_full.csv",
        "a4e62ba13435ad3dd583c5790db2175629020fc41c56e1b26baa02a9ae45f03d"),
    "dephides_train.txt": (GH + "ebubekirbbr/dephides/e66ef86fc93c6881c194833d479db9862354d7c4/dataset/small_dataset/train.txt",
                           "a7593fe02bebd6cfbce86475b1de967599d910337eaf2a49d9a8936050a8ce37"),
    "dephides_val.txt": (GH + "ebubekirbbr/dephides/e66ef86fc93c6881c194833d479db9862354d7c4/dataset/small_dataset/val.txt",
                         "01200730756213ec4a23a55e3032138a222054b8d5e6ed0b1105ea14e4824883"),
    "dephides_test.txt": (GH + "ebubekirbbr/dephides/e66ef86fc93c6881c194833d479db9862354d7c4/dataset/small_dataset/test.txt",
                          "b499772be0fa380273a959d750a7d7a0a346bd29a5f1ef1aac662eb2a6fe8af9"),
    "fwaf_goodqueries.txt": (GH + "faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall/9c92866c55ee361743fbf9379a33b51bdcf376b8/goodqueries.txt",
                             "4779cd9b2b1e995c40ea81ad86edaec8e405e5143e001c31625c7de4e83cb3d6"),
    "fwaf_badqueries.txt": (GH + "faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall/9c92866c55ee361743fbf9379a33b51bdcf376b8/badqueries.txt",
                            "f2252eb0fe6f4e26c31387f49647c146f0c54f0c9473ca6271507cb7ba7ae98b"),
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(data_dir):
    os.makedirs(data_dir, exist_ok=True)
    for name, (url, digest) in FILES.items():
        path = os.path.join(data_dir, name)
        if os.path.exists(path) and sha256(path) == digest:
            print(f"  ok (already here)  {name}")
            continue
        print(f"  downloading        {name} ...", flush=True)
        req = urllib.request.Request(url, headers={"User-Agent": "CyberGuard-training/1.0"})
        with urllib.request.urlopen(req, timeout=300) as r, open(path + ".part", "wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
        if sha256(path + ".part") != digest:
            os.remove(path + ".part")
            sys.exit(f"Checksum mismatch for {name}: the download is not the expected file. Nothing was saved. "
                     "Check your connection and run --download again.")
        os.replace(path + ".part", path)
        print(f"  ok (checked)       {name}")


def check_files(data_dir, allow_unverified=False):
    missing = [n for n in FILES if not os.path.exists(os.path.join(data_dir, n))]
    if missing:
        sys.exit(f"Missing data files in {data_dir}: {', '.join(missing)}\nRun first:  "
                 "python -m app.ml.training.train_api_abuse --download")
    if not allow_unverified:
        bad = [n for n, (_, d) in FILES.items() if sha256(os.path.join(data_dir, n)) != d]
        if bad:
            sys.exit(f"These files are not the expected versions (SHA-256 differs): {', '.join(bad)}. "
                     "Delete them and run --download again.")


# ---- readers -------------------------------------------------------------------------------------------------
_REQ = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS|TRACE) (\S+) HTTP/\d\.\d$")


def read_csic(path):
    """Raw CSIC requests -> list of request texts (path + query + form body)."""
    with open(path, encoding="latin-1") as f:
        lines = f.read().replace("\r\n", "\n").split("\n")
    out, i = [], 0
    while i < len(lines):
        m = _REQ.match(lines[i])
        if not m:
            i += 1
            continue
        method, url = m.groups()
        i += 1
        while i < len(lines) and lines[i].strip():
            i += 1
        body = ""
        while i < len(lines) and not lines[i].strip():
            i += 1
        if method in ("POST", "PUT", "PATCH") and i < len(lines) and not _REQ.match(lines[i]):
            body, i = lines[i].strip(), i + 1
        u = urlsplit(url)
        out.append(AA.request_text(u.path, u.query, body))
    return out


def read_dephides_legit(paths):
    """(website, request text) for every LEGITIMATE DEPHIDES link that has a path or query."""
    out = []
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                label, _, url = line.rstrip("\n").partition("\t")
                if label != "legitimate":
                    continue
                try:
                    u = urlsplit(url if "://" in url else "http://" + url)
                except ValueError:
                    continue
                if u.path not in ("", "/") or u.query:
                    out.append((u.netloc.lower(), AA.request_text(u.path, u.query)))
    return out


def read_httpparams(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        rows = list(csv.DictReader(f))
    # every value is put in the same neutral request, for both labels, so the wrapper itself teaches nothing
    return [("/api/item?q=" + r["payload"], int(r["label"] == "anom")) for r in rows]


def read_lines(path, keep=lambda s: True):
    with open(path, encoding="latin-1") as f:
        return [s for s in (line.strip() for line in f) if s and keep(s)]


def bucket(key, n):
    return int(hashlib.md5(key.encode("utf-8", "replace")).hexdigest(), 16) % n


# ---- metrics -------------------------------------------------------------------------------------------------
def auc(neg, pos):
    from sklearn.metrics import roc_auc_score
    return round(float(roc_auc_score(np.r_[np.zeros(len(neg)), np.ones(len(pos))], np.r_[neg, pos])), 4)


def rates(p, ta, tv):
    p = np.asarray(p)
    return {"n": int(len(p)), "at_alert": round(float((p >= ta).mean()), 4), "at_verify": round(float((p >= tv).mean()), 4)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--download", action="store_true", help="download + check the data, then stop")
    ap.add_argument("--data-dir", default=DATA_DIR)
    ap.add_argument("--out", default=MODELS_DIR)
    ap.add_argument("--quick", action="store_true", help="tiny run (automated tests only)")
    ap.add_argument("--allow-unverified", action="store_true", help="skip SHA-256 checks (automated tests only)")
    a = ap.parse_args()
    if a.download:
        print("Downloading the training data (pinned versions, SHA-256 checked):")
        download(a.data_dir)
        print("Done. Now train:  python -m app.ml.training.train_api_abuse")
        return
    check_files(a.data_dir, a.allow_unverified)
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    t0 = time.time()
    d = lambda n: os.path.join(a.data_dir, n)          # noqa: E731
    csic_norm_train, csic_norm_test = read_csic(d("csic_normalTrafficTraining.txt")), read_csic(d("csic_normalTrafficTest.txt"))
    csic_attack = read_csic(d("csic_anomalousTrafficTest.txt"))
    csic_att_tr = [x for x in csic_attack if bucket(x, 2) == 0]
    csic_att_te = [x for x in csic_attack if bucket(x, 2) == 1]
    hp = read_httpparams(d("httpparams_payload_full.csv"))
    hp_tr = [(x, y) for x, y in hp if bucket(x, 2) == 0]
    hp_te = [(x, y) for x, y in hp if bucket(x, 2) == 1]
    dep = read_dephides_legit([d("dephides_train.txt"), d("dephides_val.txt"), d("dephides_test.txt")])
    dep_tr = [x for s, x in dep if bucket(s, 10) < 7]
    dep_cal = [x for s, x in dep if bucket(s, 10) == 7]
    dep_te = [x for s, x in dep if bucket(s, 10) >= 8]
    fwaf_good = read_lines(d("fwaf_goodqueries.txt"))
    fwaf_bad = read_lines(d("fwaf_badqueries.txt"))
    if a.quick:
        rnd = random.Random(SEED)
        cut = lambda xs, n: rnd.sample(xs, min(n, len(xs)))   # noqa: E731
        csic_norm_train, csic_norm_test, csic_att_tr, csic_att_te = (cut(csic_norm_train, 600), cut(csic_norm_test, 300),
                                                                     cut(csic_att_tr, 400), cut(csic_att_te, 200))
        hp_tr, hp_te, dep_tr, dep_cal, dep_te = cut(hp_tr, 400), cut(hp_te, 200), cut(dep_tr, 800), cut(dep_cal, 300), cut(dep_te, 300)
        fwaf_good, fwaf_bad = cut(fwaf_good, 300), cut(fwaf_bad, 300)
    print(f"Loaded ({time.time() - t0:.0f}s): CSIC normal {len(csic_norm_train):,} train / {len(csic_norm_test):,} test, "
          f"CSIC attacks {len(csic_att_tr):,} / {len(csic_att_te):,}, HttpParams {len(hp_tr):,} / {len(hp_te):,}, "
          f"real CommonCrawl requests {len(dep_tr):,} train / {len(dep_cal):,} levels / {len(dep_te):,} test (by website)")

    X_text = csic_norm_train + csic_att_tr + [x for x, _ in hp_tr] + dep_tr
    y = np.array([0] * len(csic_norm_train) + [1] * len(csic_att_tr) + [yy for _, yy in hp_tr] + [0] * len(dep_tr))
    print(f"Training on {len(y):,} requests ({int(y.sum()):,} attacks) ...", flush=True)
    vec = TfidfVectorizer(analyzer="char", ngram_range=(1, 4), min_df=3, sublinear_tf=True,
                          max_features=40_000 if a.quick else 300_000, dtype=np.float32)
    X = vec.fit_transform([AA.shape(x) for x in X_text])
    model = LogisticRegression(max_iter=3000, C=2.0, class_weight="balanced")
    model.fit(X, y)

    def P(texts):
        return model.predict_proba(vec.transform([AA.shape(t) for t in texts]))[:, 1] if len(texts) else np.array([])

    # levels: 0.1% (alert) / 0.5% (verify) of real requests from websites used neither for training nor for testing
    p_cal = P(dep_cal)
    thr_alert, thr_verify = float(np.quantile(p_cal, 0.999)), float(np.quantile(p_cal, 0.995))
    print(f"Levels: alert {thr_alert:.4f}  verify {thr_verify:.4f}  ({time.time() - t0:.0f}s)")

    p_cn, p_ca, p_dep = P(csic_norm_test), P(csic_att_te), P(dep_te)
    p_hp = P([x for x, _ in hp_te])
    hp_y = np.array([yy for _, yy in hp_te])
    fq_good = [g for g in fwaf_good if "?" in g]
    rnd = random.Random(SEED)
    fq_good_s = rnd.sample(fq_good, min(len(fq_good), 30_000))
    fwaf_bad_probe = [b for b in fwaf_bad if "xxpathxx" in b.lower()]           # "does this old script exist?" probes
    fwaf_bad_payload = [b for b in fwaf_bad if "xxpathxx" not in b.lower()]
    p_fg, p_fb, p_fbp = P(fq_good_s), P(fwaf_bad_payload), P(fwaf_bad_probe)
    res = {
        "auc": {"csic_official_test": auc(p_cn, p_ca), "httpparams_heldout_values": auc(p_hp[hp_y == 0], p_hp[hp_y == 1]),
                "fwaf_independent_attack_payloads": auc(p_fg, p_fb),
                "fwaf_independent_all_attacks_incl_probes": auc(p_fg, np.r_[p_fb, p_fbp]),
                "unseen_websites_vs_csic_attacks": auc(p_dep, p_ca)},
        "attacks_caught": {"csic_attacks": rates(p_ca, thr_alert, thr_verify),
                           "httpparams_attack_values": rates(p_hp[hp_y == 1], thr_alert, thr_verify),
                           "fwaf_attack_payloads": rates(p_fb, thr_alert, thr_verify),
                           "fwaf_probes_for_old_scripts": rates(p_fbp, thr_alert, thr_verify)},
        "real_requests_flagged": {"unseen_websites_commoncrawl": rates(p_dep, thr_alert, thr_verify),
                                  "unseen_websites_with_query": rates(P([x for x in dep_te if "?" in x]), thr_alert, thr_verify),
                                  "csic_normal_test": rates(p_cn, thr_alert, thr_verify),
                                  "fwaf_real_queries_independent": rates(p_fg, thr_alert, thr_verify)},
    }
    scans = os.path.join(HERE, "data", "urlscan", "scans.jsonl")
    if os.path.exists(scans) and not a.quick:
        with open(scans, encoding="utf-8") as f:
            rows = [json.loads(line) for line in f if line.strip()]
        real26 = sorted({AA.request_text(u.path, u.query) for u in (urlsplit(r[k]) for r in rows if r.get("group") != "phish"
                                                                     for k in ("page_url", "task_url") if r.get(k))})
        res["real_requests_flagged"]["urlscan_2026_real_pages"] = rates(P(real26), thr_alert, thr_verify)
    # whole logs: 20 random real requests from unseen websites per log; "flagged" = any request reaches the level
    rnd = random.Random(SEED + 1)
    pool = np.asarray(p_dep)
    logs = [pool[rnd.sample(range(len(pool)), min(20, len(pool)))].max() for _ in range(2000)] if len(pool) else []
    res["normal_20_request_logs_flagged"] = rates(logs, thr_alert, thr_verify)
    res["note"] = ("CSIC 'anomalous' also contains requests that are only badly formed (wrong field formats), not "
                   "attacks; a syntax model cannot and should not flag those, so its CSIC catch rate is lower than "
                   "on real attack payloads. Fwaf 'probes for old scripts' (?x=XXpathXX) are requests for known "
                   "vulnerable file names - judged here by syntax only, so mostly not caught. Fwaf's 'good' queries are not "
                   "clean: 4% of those with a '?' are real scanner attacks (Nessus probes, union select, |ping|), so "
                   "its false-alarm numbers are an upper bound; the clean normal sets are the unseen CommonCrawl "
                   "websites and the urlscan.io 2026 pages.")
    print(json.dumps(res, indent=2))

    bundle = {"kind": AA.BUNDLE_KIND, "version": AA.BUNDLE_VERSION, "vectorizer": vec, "model": model,
              "thr_alert": thr_alert, "thr_verify": thr_verify,
              "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "quick": bool(a.quick)}
    metrics = {"model": "TF-IDF character 1-4-grams of the request SHAPE + logistic regression",
               "trained_at": bundle["trained_at"], "quick_run": bool(a.quick),
               "data": {"csic2010": "https://www.tic.itefi.csic.es/dataset/ (copy: github baksakal/HTTP-DATASET-CSIC-2010...)",
                        "httpparams": "github.com/Morzeux/HttpParamsDataset (MIT)",
                        "dephides_legitimate": "github.com/ebubekirbbr/dephides (MIT, CommonCrawl links)",
                        "fwaf_test_only": "github.com/faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall",
                        "training_requests": int(len(y)), "training_attacks": int(y.sum())},
               "levels": {"thr_alert": thr_alert, "thr_verify": thr_verify,
                          "chosen_on": "10% of DEPHIDES websites used for nothing else: alert = 0.1%, verify = 0.5% of their real requests"},
               "results": res}
    os.makedirs(a.out, exist_ok=True)
    import joblib
    out = os.path.join(a.out, "api_abuse.joblib")
    if os.path.exists(out) and not a.quick:
        os.replace(out, os.path.join(a.out, "api_abuse.previous.joblib"))
    joblib.dump(bundle, out + ".part")
    os.replace(out + ".part", out)
    with open(os.path.join(a.out, "api_abuse.metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"\nSaved {out} and api_abuse.metrics.json  ({time.time() - t0:.0f}s total)")


if __name__ == "__main__":
    main()
