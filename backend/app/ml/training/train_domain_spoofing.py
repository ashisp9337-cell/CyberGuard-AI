"""
Train the Domain Spoofing model (URL Security -> "Domain spoofing"): a brand name inside a domain the brand
does not own (paypal-login-secure.com, sbi-kyc-update.in, coinbase-wallet.app).

Data -- all REAL domains, nothing synthetic, nothing downloaded while training:
  * PhiUSIIL Phishing URL Dataset (UCI, already in data/): 235k real URLs (100k phishing, 135k legitimate)
      - phishing domains that contain a protected brand name           -> POSITIVES
      - legitimate domains that contain a protected brand name          -> negatives
  * Tranco top-1M list (already in data/)
      - top 10,000 sites + CyberGuard's Indian banks / brands           -> the PROTECTED brand names
      - top 100,000                                                     -> known sites, never judged
      - rank 100,001 - 1,000,000 that contain a brand name              -> negatives (real sites such as
        lenovositegroup.com, greekcommunity.com.au, talkandroid.com)
      - how often each domain ending is used by real sites              -> feature
  * wordfreq (pip package, training only): the 60,000 most common English words, so the model can tell a
    brand ("coinbase") from an ordinary word ("world", "media") and see words glued across a brand's edge.

Model: HistGradientBoostingClassifier on the ~27 numbers from app/detectors/domain_spoofing.py (the scanner
uses the same code). Domains are split 70% train / 10% calibration / 20% test by NAME (x.cf and x.gq stay
together), so the test measures new domains abusing the protected brands -- the situation in real use.
Per-brand history (how often a brand's name was used by phishing domains) is counted from training domains
only, out-of-fold, so no domain ever sees its own label. Popular Tranco sites that carry one of CyberGuard's
own protected brand names (paypal-support.net ...) are left out of training: many are the brand's own
defensive domains and their owner is unknown.
Alert level = 1% false alarms, verify level = 5%, measured on real genuine domains that contain a brand name.

Run from backend/ (a few minutes):
    pip install wordfreq            (only needed for training, not for the app)
    python -m app.ml.training.train_domain_spoofing

Output: app/ml/models/domain_spoofing.joblib  +  domain_spoofing.metrics.json
"""
import argparse
import glob
import hashlib
import io
import json
import math
import os
import random
import sys
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

from app.detectors import domain_spoofing as S
from app.detectors.lookalike_domain import split_domain
from app.detectors.url_features_v2 import BRAND_DOMAINS

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
MODELS_DIR = os.path.join(HERE, "..", "models")
SEED = 42
COMMON_WORD_RANK = 20_000
MONOTONIC = {"security_words": 1, "brand_splits_word": -1, "via_lookalike_letters": 1}


def split_of(key: str) -> str:
    """70% train / 10% calibration / 20% test, by domain name (all endings of one name stay together)."""
    h = int(hashlib.md5(key.encode()).hexdigest(), 16) % 10
    return "train" if h < 7 else "cal" if h == 7 else "test"


def read_csv_zip(path, **kw):
    with zipfile.ZipFile(path) as z:
        name = [n for n in z.namelist() if n.endswith(".csv")][0]
        with z.open(name) as f:
            return pd.read_csv(io.TextIOWrapper(f, encoding="utf-8", errors="replace"), **kw)


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


def english_words(n=60_000):
    try:
        import wordfreq
    except ImportError:
        sys.exit("Training needs the word list: pip install wordfreq")
    out = {}
    for w in wordfreq.top_n_list("en", n):
        if w.isascii() and w.isalpha() and len(w) >= 2:
            out.setdefault(w, len(out) + 1)
    return out


def build_table(tranco_regs, rank, n_protected, n_allow, words):
    suffixes = Counter(split_domain(d)[2] for d in tranco_regs)
    total = max(sum(suffixes.values()), 1)
    tld_share = {k: v / total for k, v in suffixes.items()}
    brands, owned = {}, defaultdict(set)

    def add(key, r, reg, suffix):
        if len(key) < 3 or not key.isalpha() and not key.isalnum():
            return
        wr = S.NOT_A_WORD if key not in words else math.log10(words[key])
        if key not in brands or r < brands[key][0]:
            brands[key] = (int(r), reg, suffix, wr)

    generic = set(S.SECURITY_WORDS) | {"www", "mail", "email", "news", "shop", "store", "cloud", "host", "server",
                                       "media", "online", "digital", "group", "global", "world", "network"}
    # popular sites become protected names only if the name is not an ordinary English word
    # ("business", "history", "monster" are words, "coinbase", "shopee", "naver" are names)
    for d in tranco_regs[:n_protected]:
        reg, label, suffix = split_domain(d)
        key = S.brand_key(label)
        if len(key) >= 5 and key not in generic and words.get(key, 10 ** 9) > COMMON_WORD_RANK:
            add(key, rank[d], reg, suffix)
    for name, doms in BRAND_DOMAINS.items():              # curated brands (incl. Indian banks): always protected
        group = {split_domain(d)[0] for d in doms}
        name_key = S.brand_key(name)
        for reg in group:
            label, suffix = split_domain(reg)[1:]
            key = S.brand_key(label)
            # sub-brands that are everyday words (live.com, office.com, windows.com) are not protected names
            if key == name_key or words.get(key, 10 ** 9) > 5_000:
                add(key, min(rank.get(reg, 5_000), 5_000), reg, suffix)
            owned[key] |= group
        owned[name_key] |= group
        if len(name_key) >= 3 and words.get(name_key, 10 ** 9) > 5_000 and name_key not in brands:
            best = min(group, key=lambda r: rank.get(r, 10 ** 9))       # "icici", "paytm" themselves
            add(name_key, min(rank.get(best, 5_000), 5_000), best, split_domain(best)[2])
    for d in tranco_regs:                                  # every site whose name IS the brand belongs to it
        reg, label, _ = split_domain(d)
        key = S.brand_key(label)
        if key in brands:
            owned[key].add(reg)
    for key, (_, reg, _, _) in brands.items():
        owned[key].add(reg)
    return S.BrandTable(brands, dict(owned), words, tld_share, allow=tranco_regs[:n_allow])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tranco", default=(glob.glob(os.path.join(DATA_DIR, "tranco*.csv.zip")) or [""])[0])
    ap.add_argument("--phiusiil", default=(glob.glob(os.path.join(DATA_DIR, "phiusiil*.zip")) or [""])[0])
    ap.add_argument("--out", default=MODELS_DIR)
    ap.add_argument("--protected", type=int, default=10_000)
    ap.add_argument("--allow", type=int, default=100_000)
    ap.add_argument("--extra-test", default="", help="optional CSV (url,label good/bad) used only as an extra test")
    ap.add_argument("--quick", action="store_true", help="tiny run (automated tests only)")
    a = ap.parse_args()
    t0 = time.time()
    rng = random.Random(SEED)

    tr = read_csv_zip(a.tranco, header=None, names=["rank", "domain"], nrows=30_000 if a.quick else None)
    rank = {}
    for r, d in zip(tr["rank"], tr["domain"]):
        reg = split_domain(str(d))[0]
        rank.setdefault(reg, int(r))
    regs = sorted(rank, key=rank.get)
    words = english_words(5_000 if a.quick else 60_000)
    n_prot = min(a.protected, len(regs) // 3) if a.quick else a.protected
    n_allow = min(a.allow, len(regs) // 2) if a.quick else a.allow
    table = build_table(regs, rank, n_prot, n_allow, words)
    print(f"Tranco {len(regs):,} sites, {len(table.brands):,} protected brand names, {len(words):,} words "
          f"({time.time() - t0:.0f}s)")

    # ---- real domains ------------------------------------------------------------------------
    ph = read_csv_zip(a.phiusiil, usecols=["Domain", "label"], nrows=40_000 if a.quick else None)
    ph["reg"] = [split_domain(str(d))[0] for d in ph["Domain"]]
    lab = ph.groupby("reg")["label"].agg(lambda s: int(round(s.mean())))      # PhiUSIIL: 1 = legitimate
    rows = []          # (domain, y, source)
    for reg, l in lab.items():
        rows.append((reg, 1 - int(l), "phiusiil"))
    seen = set(lab.index)
    rows += [(d, 0, "tranco") for d in regs[n_allow:] if d not in seen]

    curated = {S.brand_key(split_domain(d)[1]) for doms_ in BRAND_DOMAINS.values() for d in doms_}
    curated |= {S.brand_key(n) for n in BRAND_DOMAINS}
    X, y, grp, src, doms, fold = [], [], [], [], [], []
    dropped = 0
    for d, yy, s in rows:
        f, det = S.spoofing_features(d, table)
        if f is None:
            continue
        if s == "tranco" and det["brand"] in curated:
            # popular sites carrying a big brand's name (paypal-support.net, azurecontainerapps.dev) are often
            # the brand's own defensive / product domains: their owner is unknown, so they are not used as
            # "genuine" examples. PhiUSIIL's verified-legitimate sites are.
            dropped += 1
            continue
        name = split_domain(d)[1]                  # same name, other ending (x.cf / x.gq) stays in one split
        X.append(f)
        y.append(yy)
        grp.append(split_of(name))
        fold.append(int(hashlib.md5(("f" + name).encode()).hexdigest(), 16) % 5)
        src.append(s)
        doms.append((d, det["brand"]))
    X, y, grp, src, fold = np.array(X, dtype=float), np.array(y), np.array(grp), np.array(src), np.array(fold)
    brand_of = np.array([b for _, b in doms])
    print(f"domains with a brand name inside: {len(y):,}  (phishing {int(y.sum()):,}); {dropped:,} popular sites "
          f"with a big brand's name left out (owner unknown) ({time.time() - t0:.0f}s)")
    for s_ in ("train", "cal", "test"):
        m = grp == s_
        print(f"  {s_:5s}: {int(y[m].sum()):6,} phishing   {int((y[m] == 0).sum()):7,} genuine")

    # per-brand history (how often each brand's name was used by phishing domains) -- from TRAINING rows only;
    # training rows get it out-of-fold so a domain never sees its own label
    tr_m = grp == "train"

    def counts(mask):
        c = defaultdict(lambda: [0, 0])
        for b, yy in zip(brand_of[mask], y[mask]):
            c[b][0] += int(yy)
            c[b][1] += 1
        return {k: tuple(v) for k, v in c.items()}

    table.stats = counts(tr_m)
    table.prior = float(y[tr_m].mean())
    table.curated = {k for k in curated if k in table.brands}
    cur_rows = tr_m & np.isin(brand_of, list(table.curated))
    table.prior_curated = float(y[cur_rows].mean()) if cur_rows.any() else table.prior
    print(f"phishing share: all brand-carrying domains {table.prior:.2f}, CyberGuard's protected brands "
          f"{table.prior_curated:.2f}")
    i_rate, i_seen = S.FEATURES.index("brand_phish_rate"), S.FEATURES.index("brand_seen_log")
    for k in range(5):
        in_k = tr_m & (fold == k)
        st = counts(tr_m & (fold != k))
        for r in np.where(in_k)[0]:
            X[r, i_rate], X[r, i_seen] = table.brand_history(brand_of[r], st)
    for r in np.where(~tr_m)[0]:
        X[r, i_rate], X[r, i_seen] = table.brand_history(brand_of[r])

    tr_m = grp == "train"
    w = np.where(y[tr_m] == 1, (y[tr_m] == 0).sum() / max((y[tr_m] == 1).sum(), 1), 1.0)
    cst = [MONOTONIC.get(n, 0) for n in S.FEATURES]
    model = HistGradientBoostingClassifier(max_iter=40 if a.quick else 500, learning_rate=0.06, max_leaf_nodes=31,
                                           min_samples_leaf=30, l2_regularization=1.0, monotonic_cst=cst,
                                           early_stopping=False, random_state=SEED)
    model.fit(X[tr_m], y[tr_m], sample_weight=w)

    cal_neg = (grp == "cal") & (y == 0)
    p_cal = model.predict_proba(X[cal_neg])[:, 1]
    thr_alert = max(float(np.quantile(p_cal, 0.99)), 0.5)
    thr_verify = max(min(float(np.quantile(p_cal, 0.95)), thr_alert), 0.3)
    print(f"alert level {thr_alert:.3f}   verify level {thr_verify:.3f}")

    te = grp == "test"
    p_te = model.predict_proba(X[te])[:, 1]
    res = {"heldout_domains_all": metrics(y[te], p_te, thr_alert, thr_verify)}
    ph_m = src[te] == "phiusiil"
    res["heldout_domains_phiusiil_only"] = metrics(y[te][ph_m], p_te[ph_m], thr_alert, thr_verify)
    cur_m = np.array([doms[i][1] in curated for i in np.where(te)[0]])
    res["heldout_domains_curated_brands"] = metrics(y[te][cur_m], p_te[cur_m], thr_alert, thr_verify)
    res["heldout_tranco_genuine_false_alarms"] = metrics(y[te][~ph_m], p_te[~ph_m], thr_alert, thr_verify)
    d_te = [doms[i] for i in np.where(te)[0]]
    order = np.argsort(-p_te)
    res["examples_caught"] = [(d_te[i][0], d_te[i][1], round(float(p_te[i]), 3)) for i in order
                              if y[te][i] == 1][:20]
    res["examples_missed"] = [(d_te[i][0], d_te[i][1], round(float(p_te[i]), 3)) for i in order[::-1]
                              if y[te][i] == 1][:15]
    res["examples_false_alarms"] = [(d_te[i][0], d_te[i][1], round(float(p_te[i]), 3)) for i in order
                                    if y[te][i] == 0 and p_te[i] >= thr_alert][:20]
    res["note"] = ("Domains without a protected brand name are never flagged by this model; false-alarm rates "
                   "above are among genuine domains that DO contain a brand name.")

    if a.extra_test and os.path.exists(a.extra_test):
        ex = pd.read_csv(a.extra_test)
        ex["reg"] = [split_domain(str(u))[0] for u in ex["url"]]
        ex = ex.drop_duplicates("reg")
        ex = ex[~ex["reg"].isin(seen) & ~ex["reg"].isin(set(regs))]
        Xe, ye = [], []
        for d, l in zip(ex["reg"], ex["label"]):
            f, _ = S.spoofing_features(d, table)
            if f is not None:
                Xe.append(f)
                ye.append(int(str(l).lower() in ("bad", "phishing", "malicious", "1")))
        if Xe:
            res["extra_independent_test"] = metrics(ye, model.predict_proba(np.array(Xe))[:, 1], thr_alert, thr_verify)

    os.makedirs(a.out, exist_ok=True)
    bundle = {"kind": "cyberguard-domain-spoofing", "version": 1, "features": list(S.FEATURES), "model": model,
              "table": table.to_state(), "thr_alert": thr_alert, "thr_verify": thr_verify,
              "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    joblib.dump(bundle, os.path.join(a.out, "domain_spoofing.joblib"), compress=3)
    info = {"model": "HistGradientBoostingClassifier", "features": list(S.FEATURES),
            "data": {"protected_brand_names": len(table.brands), "allowlist": len(table.allow),
                     "train_phishing": int(((y == 1) & tr_m).sum()), "train_genuine": int(((y == 0) & tr_m).sum()),
                     "sources": ["PhiUSIIL Phishing URL Dataset (UCI)", "Tranco top-1M (tranco-list.eu)",
                                 "wordfreq English word list"]},
            "thr_alert": thr_alert, "thr_verify": thr_verify, "results": res, "trained_at": bundle["trained_at"]}
    with open(os.path.join(a.out, "domain_spoofing.metrics.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2, ensure_ascii=False)
    print(json.dumps(res, indent=2, ensure_ascii=True))
    print(f"done in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    sys.exit(main())
