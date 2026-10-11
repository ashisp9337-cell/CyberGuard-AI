"""
Trains the Organization/Brand Impersonation text classifier (TF-IDF +
Logistic Regression) on brand-MASKED text. Run from backend/:

    python -m app.ml.training.prepare_brand_dataset      # builds the CSV
    python -m app.ml.training.train_brand_impersonation  # trains + checks

Output: app/ml/models/brand_impersonation.joblib

READ THIS BEFORE TRUSTING THE NUMBERS
The accuracy on a held-out split of the training data will look near-perfect
(the phishing and the synthetic negatives are easy to tell apart by style).
That number is NOT evidence the model works. The check that matters is the
hand-written TRAP SET below: messages written independently of the training
templates, including ordinary chat that mentions brands and genuine-looking
notifications, which a shortcut-learning model flags as phishing. The model
is only saved if it clears the bar on that set (use --force to override).
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

from app.detectors.brand_text import mask_brands

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(HERE, "..", "models")
DEFAULT_DATA = os.path.join(HERE, "data", "brand_impersonation.csv")
OUT_NAME = "brand_impersonation.joblib"

TRAP_LEGIT = [
    "watching netflix tonight want to join",
    "i bought a new macbook from apple last week its amazing",
    "can you share the google doc with me",
    "hey did the netflix thing work for u yet still buffering on mine",
    "just got my amazon order finally lol took forever",
    "my instagram keeps logging me out, so annoying",
    "we're using zoom for the standup at 10, link is in the calendar",
    "paypal me the money for dinner whenever you get a chance",
    "Your Apple ID was used to sign in on a new iPhone in Mumbai. If this was you, no action is needed.",
    "Microsoft account: Your monthly Microsoft 365 invoice is now available in your billing dashboard.",
    "Your Spotify Premium payment of Rs 119 was processed successfully. Thank you for being a subscriber.",
    "Zoom: Your cloud recording is now available to view in your Zoom account.",
    "Your Amazon package was delivered to the front desk at 3:40 PM.",
    "LinkedIn: Priya Nair accepted your connection request.",
    "Your Dropbox folder 'Project Files' was shared with rohan@example.test.",
    "dhl said the courier will come between 2 and 5 tomorrow, can someone be home",
]
TRAP_PHISH = [
    "Your Amazon account has been locked due to suspicious activity, verify now at the link to avoid permanent suspension",
    "Netflix: your payment failed, update your card details immediately or your account will be cancelled today",
    "ur paypal got hacked!! click here now to fix it or lose ur money http://paypa1-secure.example.test",
    "congrats u won a free iphone from apple!! claim it here b4 midnight http://apple-gift.example.test",
    "ur netflix acct is on hold pls update ur card asap link below",
    "Dear Customer, your Microsoft account will be closed within 24 hours. Verify your identity immediately to avoid loss of access.",
    "DHL: Your parcel is on hold due to unpaid customs fees. Pay Rs 49 now to release delivery.",
    "Instagram security: your account will be permanently deleted unless you confirm your password at the link below.",
    "Apple ID locked. Unusual sign-in detected. Confirm your identity now: http://appleid-verify.example.test",
    "WhatsApp: your account will expire today. Renew for free now http://wa-renew.example.test",
    "You have been selected for a $500 Amazon gift card. Claim within 12 hours http://amzn-reward.example.test",
    "FedEx: delivery failed, reschedule and pay the Rs 30 redelivery fee here http://fedex-redeliver.example.test",
]
LEGIT_MAX_FLAG_RATE = 0.10   # at most 10% of trap-legit messages may score >= 0.5
PHISH_MIN_CATCH_RATE = 0.85  # at least 85% of trap-phishing must score >= 0.5


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DEFAULT_DATA)
    ap.add_argument("--out", default=OUT_NAME)
    ap.add_argument("--force", action="store_true", help="save even if the trap-set bar is not met")
    args = ap.parse_args()

    df = pd.read_csv(args.data).dropna(subset=["text", "label"])
    df["y"] = (df["label"] == "phishing").astype(int)
    df["masked"] = df["text"].map(mask_brands)
    print(f"Loaded {len(df):,} rows ({int(df.y.sum()):,} phishing / {int((1 - df.y).sum()):,} legitimate)")
    print(df.groupby("source")["y"].agg(["count", "mean"]).round(3).to_string())

    X_train, X_test, y_train, y_test = train_test_split(
        df["masked"], df["y"], test_size=0.2, random_state=42, stratify=df["y"]
    )
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2, max_df=0.95, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", C=1.0)),
    ])
    pipeline.fit(X_train, y_train)
    proba = pipeline.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    print("\nHeld-out split of the SAME data (do not trust this by itself):")
    print(f"  accuracy {accuracy_score(y_test, pred):.4f}  precision {precision_score(y_test, pred):.4f}  "
          f"recall {recall_score(y_test, pred):.4f}  F1 {f1_score(y_test, pred):.4f}  AUC {roc_auc_score(y_test, proba):.4f}")

    def score(t: str) -> float:
        return float(pipeline.predict_proba([mask_brands(t)])[0][1])

    legit_scores = [(score(t), t) for t in TRAP_LEGIT]
    phish_scores = [(score(t), t) for t in TRAP_PHISH]
    flagged = [x for x in legit_scores if x[0] >= 0.5]
    missed = [x for x in phish_scores if x[0] < 0.5]
    flag_rate = len(flagged) / len(TRAP_LEGIT)
    catch_rate = 1 - len(missed) / len(TRAP_PHISH)

    print("\nHAND-WRITTEN TRAP SET (this is the real test):")
    print(f"  legitimate wrongly flagged: {len(flagged)}/{len(TRAP_LEGIT)} ({flag_rate:.0%})   bar: <= {LEGIT_MAX_FLAG_RATE:.0%}")
    for p, t in sorted(flagged, reverse=True):
        print(f"     FALSE POSITIVE  P={p:.2f}  {t[:80]}")
    print(f"  phishing caught:            {len(TRAP_PHISH) - len(missed)}/{len(TRAP_PHISH)} ({catch_rate:.0%})   bar: >= {PHISH_MIN_CATCH_RATE:.0%}")
    for p, t in sorted(missed):
        print(f"     MISSED          P={p:.2f}  {t[:80]}")
    print(f"  mean P on legit: {sum(p for p, _ in legit_scores) / len(legit_scores):.2f}   "
          f"mean P on phishing: {sum(p for p, _ in phish_scores) / len(phish_scores):.2f}")

    passed = flag_rate <= LEGIT_MAX_FLAG_RATE and catch_rate >= PHISH_MIN_CATCH_RATE
    if not passed and not args.force:
        print("\nTrap-set bar NOT met — model NOT saved. (Use --force to save anyway.)")
        return 2

    os.makedirs(MODELS_DIR, exist_ok=True)
    out_path = os.path.join(MODELS_DIR, args.out)
    joblib.dump(pipeline, out_path)
    print(f"\n{'Bar met. ' if passed else 'FORCED. '}Saved -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())