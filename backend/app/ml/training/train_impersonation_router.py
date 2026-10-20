"""
Train the IMPERSONATION ROUTER: "which identity does this message claim?" -> the right subtopic detector.

Classes
    government-impersonation  management-impersonation  teacher-impersonation  financial-impersonation
    brand-impersonation       contact-impersonation     none  (no specific identity: lottery, prize, adult spam ...)

Training data (all already in app/ml/training/data/)
    * the five impersonation message sets: every message (scam AND genuine) is about its topic, so both teach
      the router what a bank / brand / government / boss / university message looks like
    * contact: REAL personal messages from the SMS corpus that talk to/as mum, dad, son, friend ... (genuine)
      + REAL reported "Hi Mum, new number" scams (known_contact_scams_real.tsv, with source links)
    * none: REAL scam SMS that claim no specific identity + real everyday SMS without a relationship

Model: TF-IDF (words 1-2 + characters 3-5) + multinomial Logistic Regression -> probabilities per class.
The router (app/services/subtopic_router.py) adds these probabilities to its rule votes (sender name, subject,
signature, titles, saved contacts ...), so rules explain WHY and the model covers wording the rules miss.

Test: 20% of messages (fixed hash of the text) are never trained on. The script prints, for that test set,
the routing result of the OLD router (rules only) and the NEW router (rules + model): right / generic / wrong.
"generic" is not an error: the scan then runs every impersonation detector and keeps the strongest.

Run from backend/:   python -m app.ml.training.train_impersonation_router
Output: app/ml/models/impersonation_router.joblib + impersonation_router.metrics.json
"""
import argparse
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
MODELS = os.path.join(HERE, "..", "models")
SEED = 42
TOPIC_FILES = {
    "government-impersonation": "government_official_impersonation.csv",
    "management-impersonation": "senior_management_impersonation.csv",
    "teacher-impersonation": "teacher_university_impersonation.csv",
    "financial-impersonation": "financial_institution_impersonation.csv",
    "brand-impersonation": "brand_impersonation.csv",
}
RELATION = re.compile(
    r"\b(mum|mom|mummy|mama|mother|dad|daddy|papa|father|son|daughter|beta|bro|brother|sis|sister|aunt|aunty|"
    r"auntie|uncle|cousin|grandma|granny|nan|nana|grandpa|friend|bestie|bhai|didi)\b|\bnew number\b|\bit'?s me\b", re.I)
TOPIC_WORDS = re.compile(
    r"\b(bank|a/c|account|card|upi|kyc|loan|otp|amazon|flipkart|paypal|apple|netflix|order|delivery|parcel|"
    r"tax|refund|government|govt|police|court|aadhaar|pan|ceo|manager|director|boss|university|college|exam|"
    r"student|scholarship)\b", re.I)


def norm(t):
    return re.sub(r"[^a-z0-9]+", " ", str(t).lower()).strip()


def bucket(t):
    return int(pd.util.hash_array(np.array([norm(t)], dtype=object), categorize=False)[0] % 100)


def load_sms():
    rows = []
    with open(os.path.join(DATA, "phishing_sms_clean_v2.tsv"), encoding="utf-8", errors="replace") as f:
        next(f)
        for line in f:
            lab, _, text = line.rstrip("\n").partition("\t")
            if text.strip() and lab in ("legitimate", "phishing"):
                rows.append((text, int(lab == "phishing")))
    df = pd.DataFrame(rows, columns=["text", "scam"])
    df["key"] = df["text"].map(norm)
    return df[df["key"].str.len() > 3].drop_duplicates("key").reset_index(drop=True)


def build_dataset(max_none=3000):
    parts = []
    for sub, f in TOPIC_FILES.items():
        d = pd.read_csv(os.path.join(DATA, f)).dropna(subset=["text"])
        parts.append(pd.DataFrame({"text": d["text"], "y": sub,
                                   "real": d["source"].astype(str).str.contains("real"), "origin": f}))
    sms = load_sms()
    rel = sms[sms["text"].str.contains(RELATION) & ~sms["text"].str.contains(TOPIC_WORDS) & (sms.scam == 0)]
    parts.append(pd.DataFrame({"text": rel["text"], "y": "contact-impersonation", "real": True,
                               "origin": "real personal SMS"}))
    scams = pd.read_csv(os.path.join(DATA, "known_contact_scams_real.tsv"), sep="\t")
    parts.append(pd.DataFrame({"text": scams["text"], "y": "contact-impersonation", "real": True,
                               "origin": "real reported contact scams"}))
    plain = sms[~sms["text"].str.contains(RELATION) & ~sms["text"].str.contains(TOPIC_WORDS)]
    none = pd.concat([plain[plain.scam == 1].sample(n=min(max_none, int((plain.scam == 1).sum())), random_state=SEED),
                      plain[plain.scam == 0].sample(n=min(max_none // 2, int((plain.scam == 0).sum())), random_state=SEED)])
    parts.append(pd.DataFrame({"text": none["text"], "y": "none", "real": True, "origin": "real SMS, no identity"}))
    df = pd.concat(parts, ignore_index=True)
    df["key"] = df["text"].map(norm)
    df = df[df["key"].str.len() > 1].drop_duplicates("key")
    df["b"] = df["text"].map(bucket)
    return df.reset_index(drop=True)


def make_model():
    return Pipeline([
        ("feats", FeatureUnion([
            ("words", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2, max_df=0.95, sublinear_tf=True)),
            ("chars", TfidfVectorizer(lowercase=True, analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                      sublinear_tf=True, max_features=150_000)),
        ])),
        ("clf", LogisticRegression(max_iter=3000, class_weight="balanced", C=4.0)),
    ])


def route_all(texts, model):
    """Route every text with the real router code; model=None -> rules only (the old router)."""
    from app.services import subtopic_router as R
    saved = R._router_model
    R._router_model = (lambda: model) if model is not None else (lambda: None)
    try:
        out = []
        for t in texts:
            try:
                out.append(R.classify(module_id="impersonation", text_input=t, url_input=None, file_path=None,
                                      file_name=None, extra_field_values={}).subtopic_id)
            except R.RoutingError:
                out.append("generic")
        return out
    finally:
        R._router_model = saved


def score(gold, got):
    per = defaultdict(Counter)
    for g, p in zip(gold, got):
        want = "generic" if g == "none" else g
        per[g]["right" if p == want else "generic" if p == "generic" else "wrong"] += 1
    rep = {}
    for g, c in sorted(per.items()):
        n = sum(c.values())
        rep[g] = {"n": n, **{k: round(c[k] / n, 3) for k in ("right", "generic", "wrong")}}
    tot = sum((c for c in per.values()), Counter())
    n = sum(tot.values())
    rep["ALL"] = {"n": n, **{k: round(tot[k] / n, 3) for k in ("right", "generic", "wrong")}}
    return rep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=MODELS)
    ap.add_argument("--max-test", type=int, default=400, help="test messages per class for the router check")
    a = ap.parse_args()
    df = build_dataset()
    train, test = df[df.b >= 20], df[df.b < 20]
    print("training messages per class:", train["y"].value_counts().to_dict())
    model = make_model().fit(train["text"], train["y"])

    # model alone on the test set
    pred = model.predict(test["text"])
    model_acc = {c: round(float((pred[test.y.values == c] == c).mean()), 3) for c in sorted(df.y.unique())}

    # full router (rules + model) vs old router (rules only), on REAL test messages where possible
    t = test[test.real | test.origin.isin(["senior_management_impersonation.csv", "teacher_university_impersonation.csv"])]
    t = t.groupby("y", group_keys=False).apply(lambda g: g.sample(n=min(a.max_test, len(g)), random_state=SEED))
    old = score(t.y.tolist(), route_all(t.text.tolist(), None))
    new = score(t.y.tolist(), route_all(t.text.tolist(), model))
    print("\nmodel alone (test, share predicted correctly):", json.dumps(model_acc))
    print(f"\n{'class':26s} {'OLD right/generic/wrong':>26s}   {'NEW right/generic/wrong':>26s}")
    for c in new:
        o, n = old[c], new[c]
        print(f"{c:26s} {o['right']:>8.0%} {o['generic']:>7.0%} {o['wrong']:>7.0%}     "
              f"{n['right']:>8.0%} {n['generic']:>7.0%} {n['wrong']:>7.0%}   (n={n['n']})")

    os.makedirs(a.out, exist_ok=True)
    joblib.dump({"kind": "cyberguard-impersonation-router", "version": 1, "model": model,
                 "classes": list(model.classes_)}, os.path.join(a.out, "impersonation_router.joblib"), compress=3)
    info = {"model": "TF-IDF (words 1-2 + characters 3-5) + multinomial Logistic Regression",
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "training_rows": train["y"].value_counts().to_dict(),
            "test": "20% of messages by text hash, never trained on; router check on real messages (management / "
                    "teacher sets have no real-only part)",
            "model_alone_accuracy": model_acc, "router_old_rules_only": old, "router_new_rules_plus_model": new}
    with open(os.path.join(a.out, "impersonation_router.metrics.json"), "w") as f:
        json.dump(info, f, indent=2)
    return info


if __name__ == "__main__":
    main()
