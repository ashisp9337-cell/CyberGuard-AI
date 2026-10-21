"""
Train the Fake Login Page model (URL Security -> "Fake login page", Phishing -> "Fraudulent website") from the page
copies collected by collect_urlscan.py: data/urlscan/scans.jsonl + data/urlscan/dom/<uuid>.html.gz.

  phishing pages : reported by OpenPhish / PhishTank, scanned by urlscan.io while live      label 1
  real logins    : login pages of real banks, mail, shops, government sites                  label 0
  real websites  : ordinary popular websites (Tranco list), when their page copy was downloaded label 0
  Pages whose phishing link ended on the REAL site (cloaked - the visitor was sent away) are left out.

Clues: app/detectors/login_page_features.py (the SAME code the live scan uses). Model: HistGradientBoosting.

Honest testing - three traps avoided:
  * real sites: there are only a few dozen, so a model could just memorise "accounts.google.com = real". Every
    real site is held out as a whole (grouped folds): each score comes from a model that never saw that site.
  * phishing kits: many phishing pages are copies of one kit. Pages with the same kit fingerprint (title + form
    fields + form target) stay together, so a kit is never in training and test at once.
  * time: a second test trains on phishing scanned BEFORE October and tests on October's new phishing.
Alert level = only 1% of real login pages (out-of-fold) reach it; verify level = 5%.

Run from backend/ (a few minutes, CPU only; reads the saved page text, never visits any site):
    python -m app.ml.training.train_fake_login
Output: app/ml/models/fake_login.joblib + fake_login.metrics.json
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

import numpy as np

from app.detectors import fake_login
from app.detectors import login_page_features as LF
from app.detectors import trusted_domains

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data", "urlscan")
MODELS = os.path.join(HERE, "..", "models")
KIND = "cyberguard-fake-login"
URL_FEATURES = [f for f in LF.FEATURES if f.startswith("url_")]
BRAND_FEATURES = ["brand_mismatch", "title_has_brand_mismatch", "links_to_brand_official", "resources_from_brand_official"]


def kit_fingerprint(html: str) -> str:
    """Same title + same input fields + same form target = same phishing kit."""
    title = re.sub(r"\s+", " ", (re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S) or [None, ""])[1]).strip().lower()
    inputs = sorted(re.findall(r"<input[^>]*?name=[\"']?([\w\-]+)", html, re.I))[:20]
    actions = sorted(re.sub(r"https?://[^/]+", "", a).lower() for a in re.findall(r"<form[^>]*?action=[\"']?([^\"'\s>]*)", html, re.I))[:5]
    return hashlib.sha1(json.dumps([title[:80], inputs, actions]).encode()).hexdigest()[:16]


def read_page_copy(path: str, limit: int = 2_000_000) -> str:
    """Text of a saved page copy. urlscan sends its stored page gzip-compressed and the collector compressed it once
    more, so the file can be gzip inside gzip (possibly cut short by the download size cap): unwrap every layer,
    tolerating a cut-off end."""
    import zlib
    with gzip.open(path, "rb") as f:
        data = f.read(limit * 4)
    for _ in range(3):
        if data[:2] != b"\x1f\x8b":
            break
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            data = d.decompress(data, limit * 4)
        except zlib.error:
            break
    return data[:limit].decode("utf-8", errors="ignore")


def load(data_dir: str, limit: int = 0):
    rows = [json.loads(line) for line in open(os.path.join(data_dir, "scans.jsonl"), encoding="utf-8") if line.strip()]
    out, skipped = [], Counter()
    for r in rows:
        if r.get("group") not in ("phish", "genuine-login", "genuine-web"):
            continue
        if r.get("cloaked") in (True, "True") or (r["group"] == "phish" and str(r.get("final_trusted")) == "True"):
            skipped["phishing link ended on the real site (cloaked)"] += 1
            continue
        path = os.path.join(data_dir, "dom", r["uuid"] + ".html.gz")
        if not os.path.exists(path):
            if r["group"] != "genuine-web":           # most ordinary websites have no page copy (only a sample has)
                skipped["no saved page copy"] += 1
            continue
        try:
            html = read_page_copy(path)
        except (OSError, EOFError):
            skipped["unreadable page copy"] += 1
            continue
        if len(html) < 200:
            skipped["empty page"] += 1
            continue
        url = r.get("page_url") or r.get("task_url") or ""
        vals = LF.extract(html, url)
        if not fake_login.judgeable(vals):          # same rule as the live scan: nothing to judge without JavaScript
            skipped[f"page shows nothing to judge ({r['group']})"] += 1
            continue
        label = 1 if r["group"] == "phish" else 0
        group = ("kit:" + kit_fingerprint(html)) if label else ("site:" + (r.get("apex") or r.get("page_domain") or ""))
        out.append({"x": LF.vector(vals), "y": label, "group": group, "time": r.get("time") or "",
                    "site": r.get("apex") or "", "facts": vals["_facts"], "url": url,
                    "ask": fake_login.asks_for_secrets(vals),
                    "kind": r["group"]})
        if limit and len(out) >= limit:
            break
    return out, skipped


def model_factory():
    from sklearn.ensemble import HistGradientBoostingClassifier
    return HistGradientBoostingClassifier(max_iter=300, learning_rate=0.05, max_leaf_nodes=15, l2_regularization=1.0,
                                          class_weight="balanced", random_state=42)


def out_of_fold(X, y, groups, folds=5):
    """Each page scored by a model that never saw its kit / site."""
    from sklearn.model_selection import GroupKFold
    p = np.zeros(len(y))
    for tr, te in GroupKFold(n_splits=folds).split(X, y, groups):
        m = model_factory().fit(X[tr], y[tr])
        p[te] = m.predict_proba(X[te])[:, 1]
    return p


def level(real_scores, share: float) -> float:
    """Lowest score that at most `share` of real pages reach (scores >= level). Ties are handled: if many real pages
    share one score exactly at the quantile, the level moves just above it instead of flagging all of them."""
    real_scores = np.sort(np.asarray(real_scores, float))
    t = float(np.quantile(real_scores, 1 - share))
    if (real_scores >= t).mean() > share + 1e-9:
        above = real_scores[real_scores > t]
        t = float(above[0]) if len(above) and (real_scores >= above[0]).mean() <= share + 1e-9 else float(np.nextafter(t, 2.0))
    return t


def report(p, y, ta, tv):
    from sklearn.metrics import roc_auc_score
    out = {"n": int(len(y)), "fake": int(y.sum()), "real": int((1 - y).sum())}
    if 0 < y.sum() < len(y):
        out["auc"] = round(float(roc_auc_score(y, p)), 4)
    if y.sum():
        out.update(caught_at_alert=round(float((p[y == 1] >= ta).mean()), 4),
                   caught_at_verify=round(float((p[y == 1] >= tv).mean()), 4))
    if (1 - y).sum():
        out.update(false_alarms_at_alert=round(float((p[y == 0] >= ta).mean()), 4),
                   false_alarms_at_verify=round(float((p[y == 0] >= tv).mean()), 4))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DATA)
    ap.add_argument("--out", default=MODELS)
    ap.add_argument("--limit", type=int, default=0, help="only this many pages (quick test)")
    a = ap.parse_args()
    import joblib

    t0 = time.time()
    items, skipped = load(a.data, a.limit)
    if len(items) < 20 or len({i["y"] for i in items}) < 2:
        raise SystemExit(f"Not enough pages ({len(items)}): {dict(skipped)}")
    X = np.array([i["x"] for i in items], float)
    y = np.array([i["y"] for i in items])
    groups = np.array([i["group"] for i in items])
    n_groups_real = len({g for g, yy in zip(groups, y) if yy == 0})
    folds = max(2, min(5, n_groups_real))
    print(f"read {len(items)} pages in {time.time() - t0:.0f}s: {int(y.sum())} phishing ({len(set(groups[y == 1]))} kits), "
          f"{int((1 - y).sum())} real pages ({n_groups_real} sites); skipped {dict(skipped)}", flush=True)

    # 1. all clues, grouped out-of-fold -> alert / verify levels + honest results
    p = out_of_fold(X, y, groups, folds)
    real = p[y == 0]
    ta = level(real, 0.01)
    tv = min(level(real, 0.05), ta)
    results = {"all_clues_unseen_kits_and_sites": report(p, y, ta, tv)}

    # 2. only what the page itself shows (no address, no brand-domain list) -> how much the HTML alone tells
    keep = [i for i, f in enumerate(LF.FEATURES) if f not in URL_FEATURES + BRAND_FEATURES]
    p_page = out_of_fold(X[:, keep], y, groups, folds)
    ta_p = level(p_page[y == 0], 0.01)
    tv_p = min(level(p_page[y == 0], 0.05), ta_p)
    results["page_only_no_address_no_brand_list"] = report(p_page, y, ta_p, tv_p)

    # 3. time: phishing before October -> train; October phishing -> test (real sites still grouped)
    times = np.array([i["time"][:7] for i in items])
    newest = (y == 1) & (times >= "2026-10")
    if newest.sum() >= 20 and ((y == 1) & ~newest).sum() >= 20:
        from sklearn.model_selection import GroupKFold
        p_time = np.zeros(len(y))
        real_idx, new_idx = np.where(y == 0)[0], np.where(newest)[0]
        for tr_r, te_r in GroupKFold(n_splits=folds).split(real_idx, groups=groups[real_idx]):
            tr = np.r_[np.where((y == 1) & ~newest)[0], real_idx[tr_r]]
            m = model_factory().fit(X[tr], y[tr])
            p_time[real_idx[te_r]] = m.predict_proba(X[real_idx[te_r]])[:, 1]       # real sites never seen
            p_time[new_idx] += m.predict_proba(X[new_idx])[:, 1] / folds              # October phishing never seen
        sel = newest | (y == 0)
        results["time_test_october_phishing_unseen"] = report(p_time[sel], y[sel], ta, tv)

    # false alarms separately for real LOGIN pages and ordinary real WEBSITES (out-of-fold)
    kinds = np.array([i["kind"] for i in items])
    results["false_alarms_by_kind"] = {
        k: {"pages": int((kinds == k).sum()), "at_alert": round(float((p[kinds == k] >= ta).mean()), 4),
            "at_verify": round(float((p[kinds == k] >= tv).mean()), 4)}
        for k in ("genuine-login", "genuine-web") if (kinds == k).any()}

    # what a LIVE scan would show: official sites (trusted list) are capped low anyway, so the false alarms that matter
    # are on real pages that are NOT on the trusted list. Compared with and without the rule "alert only when the page
    # asks for a password / card / OTP / login" (otherwise at most verify).
    untrusted = np.array([not trusted_domains.is_trusted(i["url"]) for i in items])
    asks = np.array([i["ask"] for i in items])

    def live(gate):
        alert = (p >= ta) & (asks if gate else True)
        verify = p >= tv
        out = {"phishing_caught_at_alert": round(float(alert[y == 1].mean()), 4),
               "phishing_caught_at_verify_or_alert": round(float(verify[y == 1].mean()), 4)}
        for k in ("genuine-login", "genuine-web"):
            sel = (kinds == k) & untrusted
            if sel.any():
                out[f"{k}_not_trusted_pages"] = int(sel.sum())
                out[f"{k}_not_trusted_false_alarms_at_alert"] = round(float(alert[sel].mean()), 4)
                out[f"{k}_not_trusted_false_alarms_at_verify"] = round(float(verify[sel].mean()), 4)
        sel = (y == 0) & untrusted
        out["all_real_not_trusted_false_alarms_at_alert"] = round(float(alert[sel].mean()), 4) if sel.any() else 0.0
        return out
    no_gate, gated = live(False), live(True)
    fa0, fa1 = no_gate["all_real_not_trusted_false_alarms_at_alert"], gated["all_real_not_trusted_false_alarms_at_alert"]
    drop = no_gate["phishing_caught_at_alert"] - gated["phishing_caught_at_alert"]
    alert_needs_ask = bool(fa0 > 0 and fa1 <= 0.6 * fa0 and drop <= 0.05)   # big false-alarm cut for a small catch loss
    results["live_scan_effect"] = {"without_rule": no_gate, "alert_only_if_page_asks_for_secrets": gated,
                                   "rule_used": alert_needs_ask}

    # which real sites cause false alarms (out-of-fold)
    fa = Counter(i["site"] for i, s in zip(items, p) if i["y"] == 0 and s >= tv)
    results["real_sites_with_false_alarms_at_verify"] = dict(fa.most_common(10))
    fa_u = Counter(i["site"] for i, s, u in zip(items, p, untrusted) if i["y"] == 0 and u and s >= tv)
    results["not_trusted_real_sites_with_false_alarms_at_verify"] = dict(fa_u.most_common(15))
    missed = Counter((i["facts"]["title"] or "(no title)")[:40] for i, s in zip(items, p) if i["y"] == 1 and s < tv)
    results["most_common_missed_phishing_titles"] = dict(missed.most_common(10))

    # final model on everything
    model = model_factory().fit(X, y)
    bundle = {"kind": KIND, "version": 1, "features": LF.FEATURES, "model": model, "thr_alert": ta, "thr_verify": tv,
              "alert_needs_ask": alert_needs_ask, "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    os.makedirs(a.out, exist_ok=True)
    joblib.dump(bundle, os.path.join(a.out, "fake_login.joblib"), compress=3)
    info = {"model": "HistGradientBoosting on page clues (login_page_features.py)", "features": LF.FEATURES,
            "pages": {"phishing": int(y.sum()), "real_login": int((kinds == "genuine-login").sum()),
                      "real_website": int((kinds == "genuine-web").sum()), "phishing_kits": len(set(groups[y == 1])),
                      "real_sites": n_groups_real}, "skipped": dict(skipped), "thr_alert": ta, "thr_verify": tv,
            "alert_needs_ask": alert_needs_ask,
            "results": results, "trained_at": bundle["trained_at"],
            "data": "urlscan.io page copies: phishing reported by OpenPhish / PhishTank vs real login pages",
            "seconds": round(time.time() - t0)}
    with open(os.path.join(a.out, "fake_login.metrics.json"), "w") as f:
        json.dump(info, f, indent=2)
    print(json.dumps({k: info[k] for k in ("pages", "skipped", "thr_alert", "thr_verify", "results")}, indent=2))
    return info


if __name__ == "__main__":
    main()
