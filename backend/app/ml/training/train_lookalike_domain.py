"""
Train the Look-alike Domain model (URL Security -> "Look-alike domains").

Data (all public, nothing is downloaded while training):
  * Tranco top-1M list (tranco_*.csv.zip, already in data/) -- the most visited sites, research-grade ranking
      - top 10,000 sites + CyberGuard's Indian banks / brands = the PROTECTED list (sites that get imitated)
      - top 100,000 = known sites, never judged by this model (allowlist)
      - rank 100,001 - 1,000,000 that sit close to a protected name = REAL hard negatives
        (genuine different sites such as king.com next to bing.com)
  * dnstwist (pip package) -- generates the look-alike tricks attackers register for each protected site:
    homoglyphs (incl. other alphabets / IDN), typos, swapped / missing / doubled letters, neighbouring keys,
    one-bit changes, hyphens, plurals ...  -> POSITIVES. Variants that are real sites in Tranco are dropped.
  * PhiUSIIL Phishing URL Dataset (UCI, 235k real URLs, already in data/) -- used ONLY for the final test:
    real phishing domains that imitate a protected site vs real legitimate domains that happen to be close.

Model: HistGradientBoostingClassifier on the ~30 numbers from app/detectors/lookalike_domain.py
(the scanner uses the same code). Protected sites are split 70% train / 10% calibration / 20% test,
so the model is tested on look-alikes of sites it has never seen.
Alert level = 1% false alarms, "verify" level = 5% false alarms on real close-but-genuine domains.

Run from backend/ (about 5-15 minutes, uses all CPU cores):
    pip install dnstwist           (only needed for training, not for the app)
    python -m app.ml.training.train_lookalike_domain

Output: app/ml/models/lookalike_domain.joblib  +  lookalike_domain.metrics.json
"""
import argparse
import glob
import hashlib
import io
import json
import os
import random
import sys
import time
import zipfile
from datetime import datetime, timezone
from multiprocessing import Pool

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

from app.detectors import lookalike_domain as L
from app.detectors.url_features_v2 import BRAND_DOMAINS

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
MODELS_DIR = os.path.join(HERE, "..", "models")
SEED = 42
FUZZERS = {"addition": 2, "bitsquatting": 2, "homoglyph": 6, "hyphenation": 2, "insertion": 2, "omission": 2,
           "repetition": 2, "replacement": 2, "transposition": 2, "vowel-swap": 2, "cyrillic": 1, "plural": 1,
           "tld-swap": 2}
SWAP_TLDS = ["com", "net", "org", "in", "co", "co.in", "info", "online", "site", "xyz", "top", "shop", "app"]
COMBO = 3
MONOTONIC = {"dist_skel": -1, "norm_dist_skel": -1, "skeleton_identical": 1, "mixed_script": 1}


def split_of(brand: str) -> str:
    h = int(hashlib.md5(brand.encode()).hexdigest(), 16) % 10
    return "train" if h < 7 else "cal" if h == 7 else "test"


def read_csv_zip(path, **kw):
    with zipfile.ZipFile(path) as z:
        name = [n for n in z.namelist() if n.endswith(".csv")][0]
        with z.open(name) as f:
            return pd.read_csv(io.TextIOWrapper(f, encoding="utf-8", errors="replace"), **kw)


# ---- worker helpers (top level so they also work on Windows) ------------------------------------
_IDX = None


def _init(index_state):
    global _IDX
    _IDX = L.BrandIndex.from_state(index_state)


def _feat(domain):
    try:
        f, d = L.lookalike_features(domain, _IDX)
    except Exception:
        return None
    if f is None:
        return None
    return f, d.get("brandDomain"), bool(d.get("noNearBrand"))


def _homoglyphs(fz, n, rnd):
    """n homoglyph variants (half with one, half with two swapped glyphs). Same glyph tables as dnstwist's own
    homoglyph fuzzer (incl. the per-TLD IDN rules of the registries), but sampled instead of enumerating all
    ~10,000 combinations -- that is what makes dnstwist slow on long names."""
    import idna
    a = fz.glyphs_ascii
    b = fz.glyphs_idn_by_tld.get(fz.tld, fz.glyphs_unicode)
    glyphs = {k: sorted(set(a.get(k, [])) | set(b.get(k, []))) for k in set(a) | set(b)}

    def one(label):
        spots = [(i, c) for i, c in enumerate(label) if glyphs.get(c)]
        spots += [(i, label[i:i + 2]) for i in range(len(label) - 1) if glyphs.get(label[i:i + 2])]
        if not spots:
            return None
        i, c = rnd.choice(spots)
        return label[:i] + rnd.choice(glyphs[c]) + label[i + len(c):]

    out = set()
    for k in range(n * 4):
        if len(out) >= n:
            break
        v = one(fz.domain)
        if v and k % 2:
            v = one(v)
        if not v or v == fz.domain:
            continue
        try:
            out.add(idna.encode(".".join(filter(None, [fz.subdomain, v, fz.tld]))).decode())
        except Exception:
            continue
    return sorted(out)


def _fuzz(args):
    brand, cap, seed = args
    import dnstwist
    rnd = random.Random(seed)
    try:
        fz = dnstwist.Fuzzer(brand, dictionary=[], tld_dictionary=SWAP_TLDS)
        fz.generate(fuzzers=[f for f in FUZZERS if f != "homoglyph"])
    except Exception:
        return []
    by = {}
    for x in fz.domains:
        if x["fuzzer"] in FUZZERS and x["domain"] != brand:
            by.setdefault(x["fuzzer"], []).append(x["domain"])
    try:
        by["homoglyph"] = _homoglyphs(fz, FUZZERS["homoglyph"] * cap * 2, rnd)
    except Exception:
        pass
    out = []
    for fuzzer, doms in sorted(by.items()):
        rnd.shuffle(doms)
        out += [(d, fuzzer) for d in doms[:FUZZERS[fuzzer] * cap]]
    # attackers often combine a typo with another ending (labanquepostal.co for labanquepostale.fr)
    typos = [d for d, f in out if f not in ("tld-swap", "plural")]
    suffix = L.split_domain(brand)[2]
    for d in rnd.sample(typos, min(len(typos), COMBO * cap)):
        label = L.split_domain(d)[1]
        tld = rnd.choice([t for t in SWAP_TLDS if t != suffix])
        out.append((f"{label}.{tld}", "typo+other-ending"))
    return out


def _map(fn, items, workers, state=None, chunksize=500):
    """Pool.map, or a plain loop for --workers 1 (tests, low-memory PCs)."""
    if workers <= 1:
        if state is not None:
            _init(state)
        return [fn(x) for x in items]
    kw = {"initializer": _init, "initargs": (state,)} if state is not None else {}
    with Pool(workers, **kw) as pool:
        return pool.map(fn, items, chunksize=chunksize)


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tranco", default=(glob.glob(os.path.join(DATA_DIR, "tranco*.csv.zip")) or [""])[0])
    ap.add_argument("--phiusiil", default=(glob.glob(os.path.join(DATA_DIR, "phiusiil*.zip")) or [""])[0])
    ap.add_argument("--out", default=MODELS_DIR)
    ap.add_argument("--protected", type=int, default=10_000, help="top-N Tranco sites to protect")
    ap.add_argument("--allow", type=int, default=100_000, help="top-N Tranco sites never judged")
    ap.add_argument("--per-fuzzer", type=int, default=1, help="variants per brand = this x FUZZERS weight")
    ap.add_argument("--max-negatives", type=int, default=300_000, help="Tranco sites sampled as genuine examples")
    ap.add_argument("--quick", action="store_true", help="tiny run (automated tests only)")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    a = ap.parse_args()
    t0 = time.time()
    rng = random.Random(SEED)

    # 1. Tranco -> ranks of registered domains
    tr = read_csv_zip(a.tranco, header=None, names=["rank", "domain"], nrows=20_000 if a.quick else None)
    rank = {}
    for r, d in zip(tr["rank"], tr["domain"]):
        reg = L.split_domain(str(d))[0]
        if reg not in rank:
            rank[reg] = int(r)
    regs_by_rank = sorted(rank, key=rank.get)
    print(f"Tranco: {len(rank):,} registered domains ({time.time() - t0:.0f}s)")

    # 2. protected list + allowlist
    n_prot = min(a.protected, 500) if a.quick else a.protected
    n_allow = min(a.allow, 2_000) if a.quick else a.allow
    protected = [(d, rank[d]) for d in regs_by_rank[:n_prot]]
    for doms in BRAND_DOMAINS.values():
        for d in doms:
            reg = L.split_domain(d)[0]
            protected.append((reg, min(rank.get(reg, 5_000), 5_000)))
    allow = set(regs_by_rank[:n_allow])
    index = L.BrandIndex(protected, allowlist=allow)
    state = index.to_state()
    brands = sorted({reg for reg, _ in protected if len(L.skeleton(L.split_domain(reg)[1])) >= 4})
    print(f"protected sites: {len(brands):,}   allowlist: {len(index.allow):,}")

    # 3. positives: dnstwist variants of every protected site
    jobs = [(b, a.per_fuzzer, rng.randrange(1 << 30)) for b in brands]
    variants = _map(_fuzz, jobs, a.workers, chunksize=20)
    known = set(rank)
    pos_dom, pos_brand, pos_fuzzer = [], [], []
    for b, vs in zip(brands, variants):
        for d, fz in vs:
            reg = L.split_domain(d)[0]
            if reg in known or reg in index.allow:          # a real site, not a made-up look-alike
                continue
            pos_dom.append(reg)
            pos_brand.append(b)
            pos_fuzzer.append(fz)
    print(f"look-alike variants (positives): {len(pos_dom):,} ({time.time() - t0:.0f}s)")

    # 4. negatives: real Tranco sites ranked beyond the allowlist
    neg_dom = [d for d in regs_by_rank[n_allow:] if d not in index.exact]
    if len(neg_dom) > a.max_negatives:                      # a random 300k of the 900k is plenty (speed)
        neg_dom = rng.sample(neg_dom, a.max_negatives)

    pos_f = _map(_feat, pos_dom, a.workers, state)
    neg_f = _map(_feat, neg_dom, a.workers, state)
    print(f"features computed ({time.time() - t0:.0f}s)")

    rows = []    # (features, label, split, kind)
    for f, b, fz in zip(pos_f, pos_brand, pos_fuzzer):
        if f is None or f[2]:                               # no protected site nearby -> not a look-alike
            continue
        rows.append((f[0], 1, split_of(b), fz))
    far_kept = 0
    n_far = 5_000 if a.quick else 60_000
    for f in neg_f:
        if f is None:
            continue
        if f[2]:                                            # far from every protected site (easy negative)
            if far_kept >= n_far:
                continue
            far_kept += 1
            rows.append((f[0], 0, ("train", "cal", "test")[rng.choice((0,) * 7 + (1,) + (2,) * 2)], "far"))
        else:
            rows.append((f[0], 0, split_of(f[1]), "near"))
    X = np.array([r[0] for r in rows], dtype=float)
    y = np.array([r[1] for r in rows])
    sp = np.array([r[2] for r in rows])
    kind = np.array([r[3] for r in rows])
    for s in ("train", "cal", "test"):
        m = sp == s
        print(f"  {s:5s}: {int((y[m] == 1).sum()):7,} look-alikes   {int(((y == 0) & m & (kind == 'near')).sum()):7,} "
              f"close genuine   {int(((y == 0) & m & (kind == 'far')).sum()):6,} far genuine")

    # 5. train (positives and negatives weighted to equal total)
    tr_m = sp == "train"
    w = np.where(y[tr_m] == 1, 1.0, (y[tr_m] == 1).sum() / max((y[tr_m] == 0).sum(), 1))
    cst = [MONOTONIC.get(n, 0) for n in L.FEATURES]
    model = HistGradientBoostingClassifier(max_iter=40 if a.quick else 400, learning_rate=0.08, max_leaf_nodes=31,
                                           min_samples_leaf=40, l2_regularization=1.0, monotonic_cst=cst,
                                           early_stopping=False, random_state=SEED)
    model.fit(X[tr_m], y[tr_m], sample_weight=w)

    # 6. alert levels from real close-but-genuine domains of calibration sites
    cal_neg = (sp == "cal") & (y == 0) & (kind == "near")
    if cal_neg.sum() < 20:
        cal_neg = (sp == "cal") & (y == 0)
    p_cal = model.predict_proba(X[cal_neg])[:, 1]
    thr_alert = float(np.quantile(p_cal, 0.99))
    thr_verify = float(min(np.quantile(p_cal, 0.95), thr_alert))
    thr_alert, thr_verify = max(thr_alert, 0.5), max(thr_verify, 0.3)
    print(f"alert level {thr_alert:.3f}   verify level {thr_verify:.3f}")

    te = sp == "test"
    p_te = model.predict_proba(X[te])[:, 1]
    res = {"heldout_sites_all": metrics(y[te], p_te, thr_alert, thr_verify)}
    near = kind[te] != "far"
    res["heldout_sites_close_genuine_only"] = metrics(y[te][near], p_te[near], thr_alert, thr_verify)
    res["caught_by_trick"] = {}
    for fz in list(FUZZERS) + ["typo+other-ending"]:
        m = (kind[te] == fz)
        if m.any():
            res["caught_by_trick"][fz] = {"n": int(m.sum()), "at_alert": round(float((p_te[m] >= thr_alert).mean()), 3),
                                          "at_verify": round(float((p_te[m] >= thr_verify).mean()), 3)}

    # 7. real-world test: PhiUSIIL (never used for training)
    if a.phiusiil and os.path.exists(a.phiusiil):
        ph = read_csv_zip(a.phiusiil, usecols=["Domain", "label"], nrows=30_000 if a.quick else None)
        ph["reg"] = [L.split_domain(str(d))[0] for d in ph["Domain"]]
        ph = ph.drop_duplicates("reg")
        ph = ph[~ph["reg"].isin(index.allow)]
        fs = _map(_feat, list(ph["reg"]), a.workers, state)
        keep = [i for i, f in enumerate(fs) if f is not None and not f[2]]
        if keep:
            Xr = np.array([fs[i][0] for i in keep], dtype=float)
            yr = np.array([1 - int(ph["label"].iloc[i]) for i in keep])      # PhiUSIIL: label 1 = legitimate
            pr = model.predict_proba(Xr)[:, 1]
            dist = Xr[:, L.FEATURES.index("dist_skel")]
            res["phiusiil_close_to_a_protected_site"] = metrics(yr, pr, thr_alert, thr_verify)
            m1 = dist <= 1
            res["phiusiil_within_one_edit"] = metrics(yr[m1], pr[m1], thr_alert, thr_verify)
            # short names collide by chance (comru.net / cymru.com); names of 7+ letters rarely do
            m7 = m1 & (Xr[:, L.FEATURES.index("len_brand")] >= 7)
            res["phiusiil_within_one_edit_of_a_7plus_letter_name"] = metrics(yr[m7], pr[m7], thr_alert, thr_verify)
            # all PhiUSIIL legitimate domains (incl. far ones) -> overall false-alarm rate on real sites
            n_legit = int((ph["label"] == 1).sum())
            fa = int(((yr == 0) & (pr >= thr_alert)).sum())
            res["phiusiil_false_alarms_all_legit_domains"] = {"legit_domains": n_legit, "alerts": fa,
                                                              "rate": round(fa / max(n_legit, 1), 5)}
            caught = [(ph["reg"].iloc[i], round(float(p), 3)) for i, p, yy in zip(keep, pr, yr) if yy == 1 and p >= thr_alert]
            res["phiusiil_examples_caught"] = caught[:25]
            fps = [(ph["reg"].iloc[i], round(float(p), 3)) for i, p, yy in zip(keep, pr, yr) if yy == 0 and p >= thr_alert]
            res["phiusiil_examples_false_alarms"] = fps[:25]

    os.makedirs(a.out, exist_ok=True)
    bundle = {"kind": "cyberguard-lookalike", "version": 1, "features": list(L.FEATURES), "model": model,
              "index": state, "thr_alert": thr_alert, "thr_verify": thr_verify,
              "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    joblib.dump(bundle, os.path.join(a.out, "lookalike_domain.joblib"), compress=3)
    info = {"model": "HistGradientBoostingClassifier", "features": list(L.FEATURES),
            "data": {"protected_sites": len(brands), "allowlist": len(index.allow),
                     "train_lookalikes": int(((y == 1) & tr_m).sum()), "train_genuine": int(((y == 0) & tr_m).sum()),
                     "sources": ["Tranco top-1M (tranco-list.eu)", "dnstwist look-alike generator",
                                 "PhiUSIIL Phishing URL Dataset (UCI, test only)"]},
            "thr_alert": thr_alert, "thr_verify": thr_verify, "results": res, "trained_at": bundle["trained_at"]}
    with open(os.path.join(a.out, "lookalike_domain.metrics.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2, ensure_ascii=False)
    print(json.dumps(res, indent=2, ensure_ascii=True))
    print(f"done in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    sys.exit(main())
