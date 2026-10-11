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
"""
import argparse
import os
import sys

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

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
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, stop_words="english", ngram_range=(1, 2),
                                   min_df=2, max_df=0.95, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", C=3.0)),
    ])
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
    joblib.dump(pipeline, out_path)
    print(f"\n{'Bar met. ' if passed else 'FORCED. '}Saved -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())