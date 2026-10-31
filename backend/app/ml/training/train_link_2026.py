r"""Train the 2026 link model (app/detectors/link_2026.py) on the urlscan.io collection, and test it honestly.

Data: data/urlscan/scans.jsonl (collect_urlscan.py, on this PC): real phishing links (OpenPhish / PhishTank) and real
sites' pages, with the date urlscan.io saw them. Each record gives two links: the one submitted and the final page.
Split BY DATE and BY SITE (no site in two parts). The dates move with the data (31 Oct), so new collections are used:
    test         the last 7 days in the collection, sites never seen in training
    calibration  the 2 days before that                   -> alert / verify levels
    train        everything earlier
(--train-end 2026-10-12 --cal-end 2026-10-14 gives the first, 26 Oct, split.)
Real 2026 sites from the Chrome UX Report (6,000 ordinary + every real site on a free website host such as vercel.app)
are split by site 50 / 25 / 25 into the same three parts, so the model cannot learn "free host = phishing".
The test runs the WHOLE URL engine offline (no link is opened) on the exact same links three times: without a 2026
model, with the INSTALLED model and with the new one. The new model is saved only if it beats the installed one
(higher AUC, catches at least as many, at most 0.2 points more real links / real free-hosted sites flagged) and also
beats having no model. Otherwise NO file is changed and the result goes to link_2026.rejected.metrics.json.
The installed model is kept as link_2026.previous.joblib. Only reads the data. About 2-4 minutes. From backend/:
    python -I app\ml\training\train_link_2026.py
"""
import argparse
import datetime
import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "..")))   # the backend folder (python -I ignores cwd)

import joblib  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402

from app.detectors import link_2026 as L  # noqa: E402

DATA = os.path.join(HERE, "data", "urlscan", "scans.jsonl")
MODELS = os.path.join(HERE, "..", "models")
TEST_DAYS, CAL_DAYS = 7, 2
MIN_TEST_PHISH = 200             # fewer phishing links in the test days than this: the result would mean little
NOISE = 0.002                    # 0.2 points: allowed extra share of real links flagged against the installed model
SEED = 42
N_CRUX = 2000
# Alert level = the score only 0.5% of each kind of real calibration link reaches (set on calibration data only).
ALERT_Q, VERIFY_Q = 0.995, 0.95


def links(r):
    return list(dict.fromkeys(u for u in (r.get("task_url"), r.get("page_url")) if u))


def site(r):
    return (r.get("apex") or r.get("task_domain") or "").lower()


def crux_real(seen):
    """Real 2026 sites (Chrome UX Report top-1M) not in the urlscan collection, as home-page links, split by site into
    train / calibration / test. Two kinds: ordinary sites (N_CRUX per part) and EVERY real site on a free website host
    (vercel.app, github.io, pages.dev ...) - so the model cannot learn "free host = phishing"."""
    import gzip
    from app.detectors import malicious_url as MU
    from app.ml.training import calibrate_url_domain as C
    C.crux_sites()                                          # makes sure the list is there (downloads it once)
    ordinary, hosted = [], []
    with gzip.open(C.CRUX, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            origin = line.split(",", 1)[0]
            if not origin.startswith("http"):
                continue
            host = origin.split("://", 1)[1].split("/")[0].split(":")[0].lower()
            if host in seen or host.startswith("www.") and host[4:] in seen:
                continue
            (hosted if MU.free_host(host)[0] else ordinary).append(f"https://{host}/")
    rng = random.Random(SEED)
    rng.shuffle(ordinary)
    rng.shuffle(hosted)
    ordinary = ordinary[:3 * N_CRUX]
    def parts(xs):
        a, b = len(xs) // 2, len(xs) * 3 // 4
        return xs[:a], xs[a:b], xs[b:]
    return parts(ordinary), parts(hosted)


def engine_scores(urls, bundle):
    """Whole URL engine, offline, with the given 2026 model bundle (None = no 2026 model). Nothing on disk changes."""
    from app.detectors import malicious_url as MU
    orig = L.load_model
    L.load_model = lambda: bundle
    try:
        return np.array([MU.analyze_url(u, subtopic_id="fraudulent-website", network=False)["riskScore"] for u in urls])
    finally:
        L.load_model = orig


def split_days(rows, train_end=None, cal_end=None):
    """-> (train_end, cal_end): train before train_end, calibration train_end..cal_end, test from cal_end."""
    if train_end and cal_end:
        return train_end, cal_end
    last = datetime.date.fromisoformat(max(r["time"][:10] for r in rows))
    test_from = last - datetime.timedelta(days=TEST_DAYS - 1)
    return (test_from - datetime.timedelta(days=CAL_DAYS)).isoformat(), test_from.isoformat()


def rates(y, s, level):
    y, s = np.asarray(y), np.asarray(s)
    return {"caught": round(float((s[y == 1] >= level).mean()), 4), "real_flagged": round(float((s[y == 0] >= level).mean()), 4)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-end", help="first calibration day, e.g. 2026-10-12 (default: from the data)")
    ap.add_argument("--cal-end", help="first test day, e.g. 2026-10-14 (default: the last 7 days of the data)")
    a = ap.parse_args()
    t0 = time.time()
    if not os.path.isfile(DATA):
        sys.exit(f"{DATA} not found - it is made by collect_urlscan.py")
    rows = [json.loads(line) for line in open(DATA, encoding="utf-8") if line.strip()]
    rows = [r for r in rows if r.get("label") in (0, 1) and links(r)]
    TRAIN_END, CAL_END = split_days(rows, a.train_end, a.cal_end)
    print(f"{len(rows):,} urlscan.io scans, {min(r['time'][:10] for r in rows)} to {max(r['time'][:10] for r in rows)}; "
          f"train before {TRAIN_END}, calibration {TRAIN_END} to {CAL_END}, test from {CAL_END}")
    train = [r for r in rows if r["time"][:10] < TRAIN_END]
    seen = {site(r) for r in train}
    cal = [r for r in rows if TRAIN_END <= r["time"][:10] < CAL_END and site(r) not in seen]
    test = [r for r in rows if r["time"][:10] >= CAL_END and site(r) not in seen]
    hosts = {h for r in rows for h in (r.get("task_domain"), r.get("page_domain"), site(r)) if h}
    (ord_tr, ord_cal, ord_te), (fh_tr, fh_cal, fh_te) = crux_real(hosts)
    crux_cal, crux_test = ord_cal + fh_cal, ord_te + fh_te

    def xy(part):
        xs, ys = [], []
        for r in part:
            for u in links(r):
                xs.append(u); ys.append(int(r["label"]))
        return xs, np.array(ys)
    n_test_phish = sum(len(links(r)) for r in test if r["label"] == 1)
    if n_test_phish < MIN_TEST_PHISH:
        sys.exit(f"only {n_test_phish} phishing links in the test days (need {MIN_TEST_PHISH}): collect newer data first "
                 f"(python -m app.ml.training.collect_urlscan --phish 6000 --web 4000 --no-dom). Nothing was changed.")
    xtr, ytr = xy(train)
    xtr, ytr = xtr + ord_tr + fh_tr, np.r_[ytr, np.zeros(len(ord_tr) + len(fh_tr), int)]
    pipe = Pipeline([("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True,
                                               max_features=200_000)),
                     ("lr", LogisticRegression(C=1.0, max_iter=2000, class_weight="balanced"))])
    pipe.fit([L.normalise(u) for u in xtr], ytr)

    def p(urls):
        return pipe.predict_proba([L.normalise(u) for u in urls])[:, 1]
    xca, yca = xy(cal)
    # each KIND of real link (urlscan real pages with a path, ordinary sites, free-hosted sites) must stay at or under
    # the rate on its own - the easy home pages may not pull the level down for the harder real pages
    groups = [p([u for u, y in zip(xca, yca) if y == 0]), p(ord_cal), p(fh_cal)]
    thr_alert = max(float(np.quantile(g, ALERT_Q)) for g in groups)
    thr_verify = max(float(np.quantile(g, VERIFY_Q)) for g in groups)
    bundle = {"kind": L.KIND, "pipeline": pipe, "thr_alert": thr_alert, "thr_verify": thr_verify,
              "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    xte, yte = xy(test)
    pt, pc = p(xte), p(crux_test)
    y_all, p_all = np.r_[yte, np.zeros(len(crux_test), int)], np.r_[pt, pc]
    model_alone = {"links": int(len(y_all)), "phishing": int(y_all.sum()), "auc": round(float(roc_auc_score(y_all, p_all)), 4),
                   "auc_urlscan_links_only": round(float(roc_auc_score(yte, pt)), 4),
                   "at_alert": rates(y_all, p_all, thr_alert), "at_verify": rates(y_all, p_all, thr_verify),
                   "crux_real_sites_flagged_at_alert": round(float((pc >= thr_alert).mean()), 4),
                   "real_free_hosted_sites_flagged_at_alert": round(float((p(fh_te) >= thr_alert).mean()), 4)}

    # the whole URL engine, offline, on the same links: no 2026 model / the installed model / the new one.
    # Nothing on disk changes until the decision.
    os.makedirs(MODELS, exist_ok=True)
    out = os.path.join(MODELS, "link_2026.joblib")
    installed = L.load_model()                      # None if there is no (readable) installed model
    urls = xte + crux_test
    n_ph = len(xte)

    def engine_result(scores):
        return {"auc": round(float(roc_auc_score(y_all, scores)), 4), **rates(y_all, scores, 51),
                "crux_real_sites_flagged_at_51": round(float((scores[n_ph:] >= 51).mean()), 4),
                "real_free_hosted_sites_flagged_at_51": round(float((scores[-len(fh_te):] >= 51).mean()), 4)}
    before = engine_result(engine_scores(urls, None))
    now = engine_result(engine_scores(urls, installed)) if installed else None
    after = engine_result(engine_scores(urls, bundle))
    plain = engine_scores(["https://my-portfolio.vercel.app/", "https://john-smith.github.io/",
                           "https://recipes-blog.netlify.app/"], bundle)
    engine = {"before": before, "installed": now, "after": after, "real_free_hosted_test_sites": len(fh_te),
              "plain_projects_scores": [int(x) for x in plain]}

    def beats(new, old, strict):
        return ((new["auc"] > old["auc"]) and (new["caught"] > old["caught"] if strict else new["caught"] >= old["caught"])
                and new["real_flagged"] - old["real_flagged"] <= (0.01 if strict else NOISE)
                and new["real_free_hosted_sites_flagged_at_51"] - old["real_free_hosted_sites_flagged_at_51"]
                <= (0.01 if strict else NOISE))
    keep = beats(after, before, True) and (now is None or beats(after, now, False)) and max(engine["plain_projects_scores"]) < 51
    metrics = {
        "what": "2026 link model (app/detectors/link_2026.py): character pieces of the whole link, logistic regression",
        "data": "urlscan.io collection on this PC (OpenPhish / PhishTank phishing + real sites' pages, 2026) "
                "+ Chrome UX Report real 2026 sites",
        "split": {"train": f"before {TRAIN_END}", "calibration": f"{TRAIN_END} to {CAL_END} + 25% of the real sites",
                  "test": f"{CAL_END} and later, sites never seen in training + another 25% of the real sites",
                  "train_links": len(xtr), "calibration_links": len(xca) + len(crux_cal), "test_links": len(urls)},
        "thr_alert": round(thr_alert, 4), "thr_verify": round(thr_verify, 4), "level_rule":
        "alert: only 0.5% of each kind of real calibration link reaches it (raises the score); verify: 5% (a note only)",
        "results": {"model_alone": model_alone, "whole_url_engine_offline": engine},
        "kept": keep, "keep_rule": "kept only if, on the same later links, the whole engine with the new model has a higher "
                                   "AUC and catch rate than without a 2026 model (at most 1 point more real links / real "
                                   "free-hosted sites flagged) AND than with the installed model (catches at least as "
                                   "many, at most 0.2 points more real links / real free-hosted sites flagged), and plain "
                                   "personal projects (my-portfolio.vercel.app ...) stay below 51",
        "note": "the installed model may have trained on a few of the real Chrome UX Report test sites (their split "
                "depends on the collection), which can only make the installed model look better - not the new one",
        "trained_at": bundle["trained_at"], "seconds": round(time.time() - t0),
    }
    if keep:
        tmp = out + ".tmp"
        joblib.dump(bundle, tmp)
        if os.path.exists(out):
            import shutil
            shutil.copy2(out, os.path.join(MODELS, "link_2026.previous.joblib"))
        os.replace(tmp, out)
        metrics_path = os.path.join(MODELS, "link_2026.metrics.json")
    else:
        metrics_path = os.path.join(MODELS, "link_2026.rejected.metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=1)
    print(json.dumps(metrics["results"], indent=1))
    print(f"levels: alert {thr_alert:.3f}, verify {thr_verify:.3f}")
    for name, r in (("no 2026 model", before), ("installed model", now), ("new model", after)):
        if r:
            print(f"  whole engine, {name:16s} AUC {r['auc']:.4f}  caught {r['caught']:.1%}  real links flagged "
                  f"{r['real_flagged']:.2%}  real free-hosted flagged {r['real_free_hosted_sites_flagged_at_51']:.2%}")
    if keep:
        print("KEPT - better than the installed model: link_2026.joblib saved (old one: link_2026.previous.joblib)")
    else:
        print(f"NOT KEPT - not better on every count; no model file changed (details: {os.path.basename(metrics_path)})")
    return 0 if keep else 3

if __name__ == "__main__":
    sys.exit(main())
