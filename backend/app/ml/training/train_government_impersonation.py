"""
Trains the Government Official Impersonation text classifier (TF-IDF +
Logistic Regression). Run from backend/:

    python -m app.ml.training.train_government_impersonation

Output: app/ml/models/government_official_impersonation.joblib

DATA MIX (different from Teacher/University and Senior Management):
192 REAL government-agency impersonation phishing messages (HMRC/DVLA/IRS/
Income Tax Dept tax-refund scams, filtered from phishing_sms.tsv and
deduplicated), topped up with synthetic phishing examples covering
themes barely represented in the real data (arrest-warrant threats,
immigration/visa fee scams, customs duty threats, social-security
re-verification scams) — against synthetic legitimate government notices
and casual chat. Bank-branded "update your PAN card" messages were
deliberately excluded here even though many mention government documents,
because they impersonate a BANK, not a government agency, and already
belong to the Financial Institution dataset — this keeps the two subtopics'
training data from overlapping.
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
DEFAULT_DATA = os.path.join(HERE, "data", "government_official_impersonation.csv")
OUT_NAME = "government_official_impersonation.joblib"

TRAP_LEGIT = [
    "finally got my passport renewed, took like 3 weeks lol",
    "going to the dmv tomorrow to sort out my license, wish me luck",
    "voted today, the line was so long but at least it's done",
    "filed my taxes finally, such a relief",
    "got a notice about jury duty, trying to figure out if i can get out of it",
    "renewed my vehicle registration online, way easier than i expected",
    "Dear Student, your passport renewal application has been received and is being processed.",
    "This is a reminder that your vehicle registration is due for renewal by the end of the month.",
    "Your voter registration has been confirmed. You can check your polling station on the official website.",
    "Notice: public offices will be closed next Monday for a national holiday.",
    "Your application reference has been received and is under review. No further action is needed at this time.",
]
TRAP_PHISH = [
    "FINAL NOTICE: a warrant has been issued for your arrest due to unpaid fines. Pay $500 online now to avoid prosecution",
    "URGENT: your passport has been flagged for suspension, verify your identity and pay a reinstatement fee within 24 hours",
    "This is an automated call, failure to appear in court tomorrow will result in an arrest warrant, press 1 to resolve immediately",
    "Notice: an unpaid customs duty on your recent shipment must be settled today or legal action will be taken",
    "You have an unclaimed tax refund, apply now at the link to receive your payment",
    "WARNING: Criminal Investigation Division is filing a lawsuit against you, call this number immediately for more information",
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
    print("\nHeld-out split of the SAME data (do not trust this alone):")
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