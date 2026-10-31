"""
Retrains the SMS phishing classifier (TF-IDF + Logistic Regression) on the
CLEANED dataset, with a trap-set gate. Run from backend/:

    python -m app.ml.training.train_sms_phishing

Output: app/ml/models/phishing_sms.joblib (same filename the app already
loads for the "sms-analysis" subtopic — no detector/wiring changes needed).

WHAT WAS WRONG BEFORE
The original phishing_sms.tsv had 10,185 exact duplicate rows, 34 messages
with CONTRADICTORY labels, and 174 malformed lines that were raw SMS-log
export records, not real label/text training rows. Separately — and this
was the bigger problem — the "legitimate" class skewed heavily toward old,
casual chat-style text and had almost no modern transactional messages
(delivery tracking, bill reminders), so the model treated that whole pattern
as suspicious by default. The cleaned v2 dataset fixes the data-quality
issues AND adds synthetic modern-transactional legitimate examples as hard
negatives.

The TRAP SET below uses the exact real false positives found during live
testing (a food-delivery notice, a bill reminder, a dentist reminder), so
this gate checks the actual problem that was found, not a generic proxy.

(31 Oct) MODEL v2: word 1-2-grams + character 2-5-grams (catches spelling tricks such as "acc0unt", "P4YTM",
"K Y C") with logistic regression, C=10 - chosen on a validation split INSIDE the 80% training part (the 20% test
part was not used to choose it). The new model is only saved when it beats the model already installed on the
same never-trained-on 20% test part (real messages only, the template rows left out), as the APP scores them
(model + scam rules, risk 51+ = flagged):
  * AUC higher, AND
  * genuine SMS flagged in the app: not more than now, AND
  * scams flagged in the app: at most 0.5 point fewer than now, AND
  * the trap set passes.
Otherwise the installed model is kept and nothing is written. The old model is kept as phishing_sms.previous.joblib.
"""
import argparse
import os
import shutil
import sys
import warnings

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(HERE, "..", "models")
DEFAULT_DATA = os.path.join(HERE, "data", "phishing_sms_clean_v2.tsv")
OUT_NAME = "phishing_sms.joblib"

TRAP_LEGIT = [
    "Your Swiggy order #4432 is out for delivery. Track in the app.",
    "Your electricity bill of Rs 1840 is due on 25 Sep. Pay via the official app to avoid late fee.",
    "Reminder: dentist appointment tomorrow 10am. Reply C to confirm.",
    "Mom, running 10 mins late, see you soon!",
    "Your Amazon package was delivered to the front desk at 3:40 PM.",
    "Your Zomato order has been confirmed and will arrive in 35 minutes.",
    "Reminder: your car service appointment is scheduled for tomorrow at 9 AM.",
    "Your recharge of Rs 199 was successful. Validity extended to 28 days.",
    "Hey, are we still meeting for lunch at noon tomorrow?",
    "Your flight PNR XYZ123 is confirmed for departure at 6:45 AM.",
    "Thanks for paying your rent this month, receipt attached in the app.",
    "Your prescription is ready for pickup at the pharmacy.",
]
TRAP_PHISH = [
    "Dear customer, your SBI account has been blocked. Update KYC now http://sbi-kyc-update.example.test",
    "URGENT! You have won a 1000 prize. Call now to claim",
    "Hi, this is HR. We need your bank details for payroll correction today. Reply with account number.",
    "Your account will be suspended in 24 hours unless you verify your details at this link immediately",
    "Congratulations! You've been selected for a free iPhone. Click the link to claim before it expires!",
    "Your parcel is on hold, pay the customs fee here to release delivery http://fee-release.example.test",
]
LEGIT_MAX_FLAG_RATE = 0.10
PHISH_MIN_CATCH_RATE = 0.85
ORIGINAL = os.path.join(HERE, "data", "phishing_sms.tsv")      # rows not in it are the added template messages
MAX_CATCH_DROP = 0.005


def make_pipeline():
    words = TfidfVectorizer(lowercase=True, stop_words="english", ngram_range=(1, 2), min_df=2, max_df=0.95,
                            sublinear_tf=True)
    chars = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=3, sublinear_tf=True, max_features=300_000)
    return Pipeline([("features", FeatureUnion([("words", words), ("chars", chars)])),
                     ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=10.0))])


def app_rates(model, texts, labels):
    """Share of genuine / scam messages the APP flags (risk 51+), scoring with `model` - rules included, link
    destinations not looked up (no network)."""
    from app.detectors import phishing
    real_get = phishing._get_model
    phishing._get_model = lambda subtopic_id: model
    try:
        flagged = [phishing.analyze_text(t, subtopic_id="sms-analysis", scan_links=False)["riskScore"] >= 51
                   for t in texts]
    finally:
        phishing._get_model = real_get
    g = [f for f, y in zip(flagged, labels) if y == 0]
    s = [f for f, y in zip(flagged, labels) if y == 1]
    return sum(g) / max(len(g), 1), sum(s) / max(len(s), 1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DEFAULT_DATA)
    ap.add_argument("--out", default=OUT_NAME)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    df = pd.read_csv(args.data, sep="\t", header=None, names=["label", "text"]).dropna(subset=["text"])
    df["y"] = (df["label"] == "phishing").astype(int)
    print(f"Loaded {len(df):,} rows ({int(df.y.sum()):,} phishing / {int((1 - df.y).sum()):,} legitimate)")

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["y"], test_size=0.2, random_state=42, stratify=df["y"]
    )
    pipeline = make_pipeline()
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UserWarning)
        pipeline.fit(X_train, y_train)
    proba = pipeline.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    print("\nHeld-out split of the cleaned data:")
    print(f"  accuracy {accuracy_score(y_test, pred):.4f}  precision {precision_score(y_test, pred):.4f}  "
          f"recall {recall_score(y_test, pred):.4f}  F1 {f1_score(y_test, pred):.4f}  AUC {roc_auc_score(y_test, proba):.4f}")

    def score(t: str) -> float:
        return float(pipeline.predict_proba([t])[0][1])

    legit_scores = [(score(t), t) for t in TRAP_LEGIT]
    phish_scores = [(score(t), t) for t in TRAP_PHISH]
    flagged = [x for x in legit_scores if x[0] >= 0.5]
    missed = [x for x in phish_scores if x[0] < 0.5]
    flag_rate = len(flagged) / len(TRAP_LEGIT)
    catch_rate = 1 - len(missed) / len(TRAP_PHISH)

    print("\nTRAP SET — the exact real false positives found during review, plus similar ones:")
    print(f"  legitimate wrongly flagged: {len(flagged)}/{len(TRAP_LEGIT)} ({flag_rate:.0%})  bar: <= {LEGIT_MAX_FLAG_RATE:.0%}")
    for p, t in sorted(flagged, reverse=True):
        print(f"     FALSE POSITIVE  P={p:.2f}  {t[:80]}")
    print(f"  phishing caught:            {len(TRAP_PHISH) - len(missed)}/{len(TRAP_PHISH)} ({catch_rate:.0%})  bar: >= {PHISH_MIN_CATCH_RATE:.0%}")
    for p, t in sorted(missed):
        print(f"     MISSED          P={p:.2f}  {t[:80]}")

    passed = flag_rate <= LEGIT_MAX_FLAG_RATE and catch_rate >= PHISH_MIN_CATCH_RATE
    if not passed and not args.force:
        print("\nTrap-set bar NOT met — model NOT saved. (Use --force to override.)")
        return 2

    os.makedirs(MODELS_DIR, exist_ok=True)
    out_path = os.path.join(MODELS_DIR, args.out)

    # ---- keep rule: beat the INSTALLED model on the same real test messages, as the app scores them ----
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "..")))
    if os.path.exists(out_path) and os.path.exists(ORIGINAL):
        orig = set(pd.read_csv(ORIGINAL, sep="\t", header=None, names=["label", "text"], on_bad_lines="skip",
                               engine="python", quoting=3)["text"].dropna().astype(str))
        real = X_test.astype(str).isin(orig).values
        texts, labels = list(X_test[real]), list(y_test[real])
        old = joblib.load(out_path)
        auc_old = roc_auc_score(labels, old.predict_proba(texts)[:, 1])
        auc_new = roc_auc_score(labels, pipeline.predict_proba(texts)[:, 1])
        print(f"\nReal held-out test messages ({len(texts):,}, template rows left out) - scored the way the app does:")
        g_old, s_old = app_rates(old, texts, labels)
        g_new, s_new = app_rates(pipeline, texts, labels)
        print(f"  installed model: AUC {auc_old:.4f}  genuine flagged {g_old:.2%}  scams flagged {s_old:.2%}")
        print(f"  new model:       AUC {auc_new:.4f}  genuine flagged {g_new:.2%}  scams flagged {s_new:.2%}")
        better = auc_new > auc_old and g_new <= g_old and s_new >= s_old - MAX_CATCH_DROP
        if not better and not args.force:
            print("\nThe new model is NOT better on every count - the installed model is kept, nothing written.")
            return 3
        shutil.copy2(out_path, os.path.join(MODELS_DIR, "phishing_sms.previous.joblib"))
        print("  better on every count: the installed model is kept as phishing_sms.previous.joblib")
    joblib.dump(pipeline, out_path)
    print(f"\n{'Bar met. ' if passed else 'FORCED. '}Saved -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())