"""
Retrain the Financial, Brand, Government, Senior-management and Teacher/University impersonation models
with REAL genuine messages (management and teacher also use the real email corpus, phishing_email_real.tsv).

Why: the old training sets had real scam SMS on one side and only SYNTHETIC (hand-written) genuine
messages on the other, so the models partly learned "real writing = scam". On real genuine bank SMS
the old Financial model raised false alarms on almost everything.

What this script does:
  1. Loads the real SMS corpus (phishing_sms_clean_v2.tsv: real genuine + real scam messages).
  2. Cleans obvious label mistakes with "confident learning": a 5-fold cross-validated model scores
     every message; a "genuine" message the model is >= 97% sure is a scam (or the reverse) is set aside.
  3. Holds out 20% of the real messages (by a fixed hash of the text) as a TEST set that no model
     ever trains on.
  4. For each subtopic: scams = the subtopic's existing scam examples + real scam SMS about that topic;
     genuine = the existing hand-written genuine examples + REAL genuine SMS about the same topic
     (bank / shop / government messages -- the hard cases) + other real genuine SMS.
  5. Trains TF-IDF (words 1-2 + characters 3-5) + Logistic Regression -- same kind of model, same
     input (Brand still masks brand names) and same file name, so the detectors need no change.
  6. Compares OLD vs NEW on the held-out real test set, both the model alone and the full detector
     (model + rules, the score users actually see).

Run from backend/ (a few minutes):
    python -m app.ml.training.retrain_impersonation_real
Output: app/ml/models/{financial_impersonation,brand_impersonation,government_official_impersonation,
        senior_management_impersonation,teacher_university_impersonation}.joblib
        + <name>.metrics.json
"""
import argparse
import json
import os
import random
import re
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import FeatureUnion, Pipeline

from app.detectors.brand_text import mask_brands

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
MODELS = os.path.join(HERE, "..", "models")
SEED = 42

TOPICS = {
    "financial": {
        "csv": "financial_institution_impersonation.csv", "out": "financial_impersonation.joblib",
        "re": r"\b(?:bank|banking|a/c|acct|account|card|debit|credit|upi|kyc|loan|emi|balance|neft|imps|rtgs|atm|pin|"
              r"netbanking|net banking|wallet|paytm|phonepe|gpay|ifsc|cheque|transaction|txn|payment|refund)\b",
        "mask": False,
    },
    "brand": {
        "csv": "brand_impersonation.csv", "out": "brand_impersonation.joblib",
        "re": r"\b(?:amazon|flipkart|netflix|paypal|apple|icloud|microsoft|outlook|office ?365|google|gmail|ebay|fedex|dhl|"
              r"ups|usps|royal mail|delivery|parcel|package|order|shipment|courier|subscription|prime|account)\b",
        "mask": True,
    },
    "government": {
        "csv": "government_official_impersonation.csv", "out": "government_official_impersonation.joblib",
        "re": r"\b(?:tax|refund|hmrc|irs|government|govt|gov|aadhaar|aadhar|pan card|passport|police|court|customs|visa|"
              r"dvla|fine|penalty|ministry|council|license|licence|uidai|epfo|income tax|social security|benefit)\b",
        "mask": False,
    },
    # these two also learn from the real EMAIL corpus: CEO / manager fraud and fake university notices arrive by email
    "management": {
        "csv": "senior_management_impersonation.csv", "out": "senior_management_impersonation.joblib",
        "re": r"\b(?:ceo|cfo|coo|md|managing director|director|chairman|my manager|your manager|boss|hr department|"
              r"payroll|wire transfer|gift ?cards?|vendor payment|invoice|urgent task|are you at your desk|"
              r"confidential request)\b",
        "mask": False, "email": True,
    },
    "teacher": {
        "csv": "teacher_university_impersonation.csv", "out": "teacher_university_impersonation.joblib",
        "re": r"\b(?:university|college|professor|prof\.|dean|principal|teacher|exam|examination|admission|scholarship|"
              r"tuition|semester|hall ticket|hostel|registrar|campus|student|marksheet|degree certificate)\b",
        "mask": False, "email": True,
    },
}


def norm(t: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(t).lower()).strip()


def bucket(t: str) -> int:
    return int(pd.util.hash_array(np.array([norm(t)], dtype=object), categorize=False)[0] % 100)


def make_pipeline():
    return Pipeline([
        ("feats", FeatureUnion([
            ("words", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2, max_df=0.95, sublinear_tf=True)),
            ("chars", TfidfVectorizer(lowercase=True, analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                      sublinear_tf=True, max_features=150_000)),
        ])),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=2.0)),
    ])


def load_sms():
    rows = []
    with open(os.path.join(DATA, "phishing_sms_clean_v2.tsv"), encoding="utf-8", errors="replace") as f:
        next(f)
        for line in f:
            lab, _, text = line.rstrip("\n").partition("\t")
            if text.strip() and lab in ("legitimate", "phishing"):
                rows.append((text, int(lab == "phishing")))
    df = pd.DataFrame(rows, columns=["text", "y"])
    df["key"] = df["text"].map(norm)
    df = df[df["key"].str.len() > 3]
    # the same text with both labels -> drop it entirely; otherwise keep one copy
    conflict = df.groupby("key")["y"].nunique()
    df = df[~df["key"].isin(conflict[conflict > 1].index)].drop_duplicates("key")
    return df.reset_index(drop=True)


ON_TOPIC_CLEAN = 0.80     # stricter for on-topic "genuine" messages: many are mislabelled scams in this corpus


def clean_labels(df, threshold=0.97):
    """Confident learning: drop rows whose out-of-fold prediction strongly disagrees with the label.
    Keeps the out-of-fold scam probability in column "p" for the stricter on-topic check later."""
    pipe = Pipeline([("tf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
                     ("lr", LogisticRegression(max_iter=1000, class_weight="balanced", C=2.0))])
    p = cross_val_predict(pipe, df["text"], df["y"], cv=StratifiedKFold(5, shuffle=True, random_state=SEED),
                          method="predict_proba")[:, 1]
    df = df.assign(p=p)
    bad = ((df["y"] == 0) & (p >= threshold)) | ((df["y"] == 1) & (p <= 1 - threshold))
    return df[~bad].reset_index(drop=True), df[bad]


def load_email():
    """Real phishing / legitimate emails (phishing_email_real.tsv), first 3,000 characters of each."""
    em = pd.read_csv(os.path.join(DATA, "phishing_email_real.tsv"), sep="\t", header=None, names=["label", "text"],
                     on_bad_lines="skip", quoting=3, dtype=str).dropna()
    em = em[em["label"].str.lower().isin(["phishing", "legitimate"])]
    em = pd.DataFrame({"text": em["text"].str[:3000], "y": (em["label"].str.lower() == "phishing").astype(int)})
    em["key"] = em["text"].map(norm)
    conflict = em.groupby("key")["y"].nunique()
    em = em[~em["key"].isin(conflict[conflict > 1].index)].drop_duplicates("key")
    return em.assign(p=0.0).reset_index(drop=True)


def detector_module(topic):
    if topic == "management":
        from app.detectors import senior_management_impersonation as m
        return m, m.analyze_senior_management_impersonation
    if topic == "teacher":
        from app.detectors import teacher_university_impersonation as m
        return m, m.analyze_teacher_university_impersonation
    if topic == "financial":
        from app.detectors import financial_impersonation as m
        return m, m.analyze_financial_impersonation
    if topic == "brand":
        from app.detectors import brand_impersonation as m
        return m, m.analyze_brand_impersonation
    from app.detectors import government_impersonation as m
    return m, m.analyze_government_impersonation


def evaluate(model, mask, test_sets):
    out = {}
    for name, (texts, y) in test_sets.items():
        x = [mask_brands(t) if mask else t for t in texts]
        p = model.predict_proba(x)[:, 1]
        y = np.asarray(y)
        r = {"n": int(len(y))}
        if y.min() == 0:
            r["false_alarm_rate"] = round(float((p[y == 0] >= 0.5).mean()), 4)
        if y.max() == 1:
            r["caught_rate"] = round(float((p[y == 1] >= 0.5).mean()), 4)
        if y.min() == 0 and y.max() == 1:
            r["roc_auc"] = round(float(roc_auc_score(y, p)), 4)
        out[name] = r
    return out


def evaluate_detector(topic, model, test_sets):
    """Full detector score (model + rules) as users see it; >= 51 counts as flagged.
    The given model is handed to the detector in memory -- no model file is touched."""
    mod, fn = detector_module(topic)
    original = mod._get_model
    mod._get_model = lambda: model
    try:
        out = {}
        for name, (texts, y) in test_sets.items():
            s = np.array([fn(t, {}, "test")["riskScore"] for t in texts])
            y = np.asarray(y)
            r = {"n": int(len(y))}
            if y.min() == 0:
                r["false_alarm_rate"] = round(float((s[y == 0] >= 51).mean()), 4)
            if y.max() == 1:
                r["caught_rate"] = round(float((s[y == 1] >= 51).mean()), 4)
            out[name] = r
        return out
    finally:
        mod._get_model = original


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--out", default=MODELS)
    ap.add_argument("--max-test", type=int, default=600, help="messages per test group for the slower detector check")
    a = ap.parse_args()
    rng = random.Random(SEED)
    os.makedirs(a.out, exist_ok=True)

    sms = load_sms()
    sms, dropped = clean_labels(sms)
    print(f"Real SMS: {len(sms):,} kept, {len(dropped):,} set aside as probable label mistakes "
          f"({int((dropped.y == 0).sum())} 'genuine' that look like scams, {int((dropped.y == 1).sum())} the reverse)")
    sms["b"] = sms["text"].map(bucket)
    train_sms, test_sms = sms[sms.b >= 20], sms[sms.b < 20]
    test_keys = set(test_sms["key"])
    email = None
    report = {}

    for topic, cfg in TOPICS.items():
        if a.only and topic not in a.only.split(","):
            continue
        rx = re.compile(cfg["re"], re.I)
        old = pd.read_csv(os.path.join(DATA, cfg["csv"])).dropna(subset=["text", "label"])
        old["y"] = (old["label"] == "phishing").astype(int)
        old["key"] = old["text"].map(norm)
        old = old[~old["key"].isin(test_keys)]          # nothing from the test set may be trained on

        src_train, src_test = train_sms, test_sms
        if cfg.get("email"):
            if email is None:
                email = load_email()
                email["b"] = email["text"].map(bucket)
            src_train = pd.concat([train_sms, email[email.b >= 20]], ignore_index=True)
            src_test = pd.concat([test_sms, email[email.b < 20]], ignore_index=True)
            old = old[~old["key"].isin(set(email[email.b < 20]["key"]))]
        on_topic = src_train[src_train["text"].str.contains(rx)]
        real_scam = on_topic[on_topic.y == 1]
        real_hard_genuine = on_topic[(on_topic.y == 0) & (on_topic.p < ON_TOPIC_CLEAN)]
        set_aside_train = int(((on_topic.y == 0) & (on_topic.p >= ON_TOPIC_CLEAN)).sum())
        other_genuine = src_train[(src_train.y == 0) & ~src_train.index.isin(on_topic.index)]
        n_other = min(len(other_genuine), max(2000, 2 * len(real_hard_genuine)))
        other_genuine = other_genuine.sample(n=n_other, random_state=SEED)

        train = pd.concat([old[["text", "y", "key"]], real_scam[["text", "y", "key"]],
                           real_hard_genuine[["text", "y", "key"]], other_genuine[["text", "y", "key"]]])
        train = train.drop_duplicates("key")
        x = [mask_brands(t) if cfg["mask"] else t for t in train["text"]]
        model = make_pipeline().fit(x, train["y"])

        # held-out REAL test sets
        t_topic = src_test[src_test["text"].str.contains(rx)]
        set_aside_test = int(((t_topic.y == 0) & (t_topic.p >= ON_TOPIC_CLEAN)).sum())
        t_topic = t_topic[(t_topic.y == 1) | (t_topic.p < ON_TOPIC_CLEAN)]
        t_other = src_test[~src_test.index.isin(t_topic.index)]
        def take(df, n):
            return df.sample(n=min(n, len(df)), random_state=SEED) if len(df) > n else df
        kind = "SMS + email" if cfg.get("email") else "SMS"
        tests = {
            f"real genuine {topic}-related {kind}": (list(t_topic[t_topic.y == 0].text), [0] * int((t_topic.y == 0).sum())),
            f"real {topic}-related scam {kind}": (list(t_topic[t_topic.y == 1].text), [1] * int((t_topic.y == 1).sum())),
            f"real genuine everyday {kind}": (list(take(t_other[t_other.y == 0], 3000).text),
                                              [0] * min(3000, int((t_other.y == 0).sum()))),
        }
        old_path = os.path.join(MODELS, cfg["out"])
        old_model = joblib.load(old_path)
        res = {"old_model": evaluate(old_model, cfg["mask"], tests), "new_model": evaluate(model, cfg["mask"], tests)}

        small = {}
        for k, (texts, ys) in tests.items():
            d = take(pd.DataFrame({"t": texts, "y": ys}), a.max_test)
            small[k] = (d.t.tolist(), d.y.tolist())
        res["old_detector"] = evaluate_detector(topic, old_model, small)
        res["new_detector"] = evaluate_detector(topic, model, small)
        joblib.dump(model, os.path.join(a.out, cfg["out"]), compress=3)

        info = {"topic": topic, "model": "TF-IDF (words 1-2 + characters 3-5) + Logistic Regression",
                "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "training_rows": {"scam": int(train.y.sum()), "genuine": int((1 - train.y).sum()),
                                  "real_scam_sms_added": len(real_scam), "real_genuine_on_topic": len(real_hard_genuine),
                                  "real_genuine_other": len(other_genuine),
                                  "previous_dataset_rows_used": len(old)},
                "label_cleaning": {"dropped_genuine_looking_like_scam": int((dropped.y == 0).sum()),
                                   "dropped_scam_looking_genuine": int((dropped.y == 1).sum()),
                                   "on_topic_genuine_set_aside_train": set_aside_train,
                                   "on_topic_genuine_set_aside_test": set_aside_test,
                                   "on_topic_threshold": ON_TOPIC_CLEAN},
                "test": "held-out 20% of real SMS (never trained on); detector = model + rules, flagged at score >= 51",
                "results": res}
        with open(os.path.join(a.out, cfg["out"].replace(".joblib", ".metrics.json")), "w") as f:
            json.dump(info, f, indent=2)
        report[topic] = res
        print(f"\n=== {topic}")
        for k, v in res.items():
            print(f"  {k:<13} {json.dumps(v)}")
    return report


if __name__ == "__main__":
    main()
