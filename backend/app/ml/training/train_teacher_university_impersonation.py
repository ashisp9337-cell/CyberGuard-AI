"""
Trains the Teacher/University Authority Impersonation text classifier
(TF-IDF + Logistic Regression). Run from backend/:

    python -m app.ml.training.train_teacher_university_impersonation

Output: app/ml/models/teacher_university_impersonation.joblib

IMPORTANT CONTEXT (read this before trusting anything about this model)
Unlike the Financial Institution and Brand models, there is no usable REAL
phishing data for this subtopic anywhere in this project's datasets —
checked directly: filtering for exam/scholarship/HOD/registrar/tuition-fee
terms pulls almost entirely unrelated content (real-estate ads, old Enron
corporate email, personal chat). This dataset (teacher_university_impersonation.csv)
is therefore built ENTIRELY from synthetic, hand-designed examples covering
realistic academic-scam patterns (fake exam-fee threats, fake scholarship
fees, fake result-withheld threats, fake portal-credential phishing) against
synthetic legitimate academic notices and casual student chat.

This makes the trap-set check below more important than usual, not less —
it's the only real check this model gets before going live.
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
DEFAULT_DATA = os.path.join(HERE, "data", "teacher_university_impersonation.csv")
OUT_NAME = "teacher_university_impersonation.joblib"

# Hand-written, independent of the training templates.
TRAP_LEGIT = [
    "hey did the professor post the assignment yet",
    "exam got moved to next friday, check the notice board",
    "can you send me your notes from yesterday's class, i missed it",
    "just paid my hostel fee online, all sorted now",
    "the wifi in my dorm has been down all morning so annoying",
    "got my scholarship confirmation email today, so relieved",
    "Dear Student, your assignment for Data Structures is due next Friday. Please submit it through the portal.",
    "This is a reminder that the mid-semester exam is scheduled next week in the main hall.",
    "The library will remain open until 9 PM during the exam period. Plan your study schedule accordingly.",
    "Your internal assessment marks have been uploaded to the portal. Contact your professor during office hours with questions.",
    "picked up my id card renewal from the office today, took like five minutes",
    "registered for next semester finally, the portal was so slow today",
]
TRAP_PHISH = [
    "URGENT: your degree certificate is on hold, pay Rs 5000 now at this link to avoid losing it forever",
    "Dear Student, this is the exam controller. Your hall ticket will not be issued unless you pay the exam fee immediately, click here",
    "Congratulations you have been selected for a scholarship of Rs 20000, pay a processing fee of Rs 500 within the hour to claim it",
    "This is your HOD, I am stuck in a meeting, please buy exam fee coupons worth Rs 3000 urgently and send me the codes",
    "Your student portal password expires in 1 hour, verify immediately at the link or lose access before tomorrow's exam",
    "Final notice from Registrar: unpaid tuition of Rs 15000 detected, settle now via the link or your ID will be deactivated tonight",
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