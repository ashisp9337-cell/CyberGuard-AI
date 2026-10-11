"""
Trains the Social Media Message Analysis text classifier (TF-IDF +
Logistic Regression). Run from backend/:

    python -m app.ml.training.train_social_media_phishing

Output: app/ml/models/phishing_social.joblib (the filename phishing.py's
MODEL_FILES already expects for "social-media-analysis" — this file never
existed before, which is why that subtopic ran on weak rules only).

CONTEXT: checked directly — this project's SMS/email datasets have almost no
usable real social-media DM/comment-scam examples (only 105 loosely-matching
SMS rows, mostly noise; wrong register entirely, since SMS text doesn't
resemble Instagram DM or comment text). This dataset
(social_media_phishing.csv) is therefore entirely synthetic, covering
realistic platform-specific scam patterns: fake modeling/brand-ambassador
offers, crypto "double your money" scams, fake verification-badge scams,
romance-scam money requests, and fake giveaway/account-suspension phishing —
against synthetic genuine DMs/comments and casual fan interaction.
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
DEFAULT_DATA = os.path.join(HERE, "data", "social_media_phishing.csv")
OUT_NAME = "phishing_social.joblib"

TRAP_LEGIT = [
    "omg your last post was so good, what camera do u use",
    "hey saw ur story, where was that taken looks amazing",
    "lol thanks for the follow, love ur content too",
    "congrats on hitting 10k followers thats insane",
    "can u send me the link to that product u posted about",
    "just followed u, ur feed is so aesthetic",
    "Hi, thanks for reaching out! We'd love to collaborate with you - no fees involved, we'll send over a contract first.",
    "Your Instagram account has been verified. No further action needed.",
    "Reminder: your scheduled post will go live tomorrow at 9 AM.",
    "Thanks for the great feedback on your last post, engagement is up this week!",
    "Hi, loved your last post! Would you be open to a quick call about a possible collab, no strings attached?",
]
TRAP_PHISH = [
    "Hey! I'm a talent scout for a modeling agency, saw your profile and think you'd be perfect. DM me your bank details so we can process your first payment.",
    "I'm a crypto investor, I can double your money in 48 hours guaranteed. Send funds to this wallet to get started.",
    "Hi, I run a verification service, I can get you the blue checkmark for a fee. Just send your login details and I'll handle the rest.",
    "We noticed unusual activity on your account. Click this link to verify your identity or your account will be permanently disabled within 24 hours.",
    "You've won our monthly giveaway! Send your bank account details to claim your prize before it expires in 2 hours.",
    "I'm offering huge followers growth overnight, just send payment and your username and password to get started today.",
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