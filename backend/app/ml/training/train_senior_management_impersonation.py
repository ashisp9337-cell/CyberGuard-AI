"""
Trains the Senior Management (CEO fraud / BEC) Impersonation text classifier
(TF-IDF + Logistic Regression). Run from backend/:

    python -m app.ml.training.train_senior_management_impersonation

Output: app/ml/models/senior_management_impersonation.joblib

CONTEXT: same situation as Teacher/University — checked directly, and this
project's existing datasets have no usable real Business Email Compromise
examples (the old email corpus's "CEO/wire transfer"-adjacent rows are stock-
pump spam and Enron corporate mail, not BEC scams). This dataset
(senior_management_impersonation.csv) is entirely synthetic, covering
classic BEC patterns: gift-card requests, urgent off-channel wire transfers,
vendor-account-change fraud, and "don't tell anyone" secrecy pressure —
against synthetic ordinary business correspondence.
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
DEFAULT_DATA = os.path.join(HERE, "data", "senior_management_impersonation.csv")
OUT_NAME = "senior_management_impersonation.joblib"

TRAP_LEGIT = [
    "hey did the ceo approve the budget yet, need to know before the call",
    "the vendor payment went through fine, all good",
    "just sent the report to the manager, fingers crossed they like it",
    "can you forward me the invoice from the supplier when you get a sec",
    "finance approved the expense report finally, took forever",
    "heads up the call with the client got pushed to next week",
    "Hi team, please find attached the Q3 budget. Let me know if anything looks off before Friday's review.",
    "The board meeting has been rescheduled to next Tuesday at 2 PM. Please update your calendars.",
    "Please review the attached contract with the vendor before our call on Thursday.",
    "This is a reminder that expense reports for last month are due by the 5th through the finance portal.",
    "Thanks for your work on the proposal, the director reviewed it and has a few comments attached.",
    "Can we schedule a call with the VP to discuss the account next week?",
]
TRAP_PHISH = [
    "Hi, I'm in a meeting and can't talk, I need you to buy 5 gift cards worth $200 each and send me the codes urgently, will explain later",
    "This is the CEO, are you at your desk? I need a wire transfer of $10000 sent to a new vendor account today, it's confidential",
    "URGENT: the vendor's bank details have changed, please update the payment for invoice 4471 to the new account before end of day",
    "I'm travelling and my phone is acting up so I'm emailing from a personal account, need you to process an urgent payment today, keep this discreet",
    "Quick favor, are you available right now? Need you to buy gift cards for a client, send the codes before 5pm, keep this between us",
    "We're finalizing a confidential acquisition, I need funds wired to the account below by end of day, do not discuss this with anyone",
]
LEGIT_MAX_FLAG_RATE = 0.10
PHISH_MIN_CATCH_RATE = 0.85


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DEFAULT_DATA)
    ap.add_argument("--out", default=OUT_NAME)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    df = pd.read_csv(args.data).dropna(subset=["text", "label"])
    df["y"] = (df["label"] == "phishing").astype(int)
    print(f"Loaded {len(df):,} rows ({int(df.y.sum()):,} phishing / {int((1 - df.y).sum()):,} legitimate)")
    print(df.groupby("source")["y"].agg(["count", "mean"]).round(3).to_string())

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["y"], test_size=0.2, random_state=42, stratify=df["y"]
    )
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, stop_words="english", ngram_range=(1, 2),
                                   min_df=2, max_df=0.95, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", C=1.0)),
    ])
    pipeline.fit(X_train, y_train)
    proba = pipeline.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    print("\nHeld-out split of the SAME data (do not trust this alone — this dataset is synthetic):")
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

    print("\nHAND-WRITTEN TRAP SET (the real test — independent of the training templates):")
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