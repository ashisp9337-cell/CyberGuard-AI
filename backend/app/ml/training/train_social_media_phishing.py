"""
Trains the Social Media Message Analysis classifier ("is this comment / DM a scam?").
Run from backend/:

    python -m app.ml.training.train_social_media_phishing

Output: app/ml/models/phishing_social.joblib  (+ phishing_social.metrics.json)
        -- the filename app/detectors/phishing.py already loads for "social-media-analysis".
        Until this file exists that subtopic runs on rules only.

DATA (real first):
  1. UCI YouTube Spam Collection (UCI #380, CC BY 4.0; Alberto, Lochter & Almeida 2015):
     1,956 REAL YouTube comments from 5 music videos, labelled spam (1,005) or normal (951).
     File: data/youtube+spam+collection.zip (the zip from the UCI page, not unpacked).
     Spam there = scam/self-promotion comments: free gift cards, "make money", "check my channel", links.
  2. Real short messages from data/phishing_sms_clean_v2.tsv (the cleaned SMS corpus this project
     already uses): a balanced sample. Chat-style DMs are written like SMS, so these teach the model
     real scam wording (prizes, blocked accounts, links, payment requests).
  3. data/social_media_phishing.csv: hand-written platform scams (fake modelling offers, crypto
     doubling, paid verification badges, giveaway phishing) that real public data barely contains.
     Kept, but with LOW weight, and never used to judge the model.

HONEST TESTS (none of these rows are trained on):
  * an entire YouTube video's comments held out (Shakira, 370 comments) -> unseen-video test
  * 20% of the SMS sample held out
  * a hand-written trap set of normal and scam DMs/comments; the model is NOT saved unless it passes
"""
import argparse
import html
import io
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
MODELS_DIR = os.path.join(HERE, "..", "models")
OUT_NAME = "phishing_social.joblib"
YOUTUBE_ZIP_NAMES = ("youtube+spam+collection.zip", "youtube_spam_collection.zip", "YouTube-Spam-Collection-v1.zip")
HOLDOUT_VIDEO = "Shakira"
SMS_PER_CLASS = 4000
SOURCE_WEIGHT = {"youtube-real": 0.45, "sms-real": 0.40, "curated-dm": 0.15}   # share of total training weight

TRAP_LEGIT = [
    "omg your last post was so good, what camera do u use",
    "hey saw ur story, where was that taken looks amazing",
    "lol thanks for the follow, love ur content too",
    "congrats on hitting 10k followers thats insane",
    "can u send me the link to that product u posted about",
    "just followed u, ur feed is so aesthetic",
    "Hi, thanks for reaching out! We'd love to collaborate with you - no fees involved, we'll send over a contract first.",
    "Reminder: your scheduled post will go live tomorrow at 9 AM.",
    "this song never gets old, still listening in 2026",
    "who else is here after the concert last night",
    "bro are we still meeting at the library at 5?",
    "happy birthday!! have an amazing day",
]
TRAP_PHISH = [
    "Hey! I'm a talent scout for a modeling agency, saw your profile and think you'd be perfect. DM me your bank details so we can process your first payment.",
    "I'm a crypto investor, I can double your money in 48 hours guaranteed. Send funds to this wallet to get started.",
    "Hi, I run a verification service, I can get you the blue checkmark for a fee. Just send your login details and I'll handle the rest.",
    "We noticed unusual activity on your account. Click this link to verify your identity or your account will be permanently disabled within 24 hours.",
    "You've won our monthly giveaway! Send your bank account details to claim your prize before it expires in 2 hours.",
    "FREE iTunes gift card codes!!! get yours here before they run out http://bit.ly/free-codes",
    "earn $500 a day working from home, no experience needed, message me now",
    "Congratulations you are selected for Paytm cashback of Rs 5000, click the link and enter your UPI PIN to receive",
]
LEGIT_MAX_FLAG_RATE = 0.10
PHISH_MIN_CATCH_RATE = 0.85


def _clean(t: str) -> str:
    t = html.unescape(str(t))
    t = re.sub(r"<br\s*/?>", " ", t, flags=re.I)
    t = re.sub(r"<[^>]+>", " ", t)
    t = t.replace('""', '"')
    return re.sub(r"\s+", " ", t).strip().strip('"').strip()


def load_youtube() -> pd.DataFrame:
    path = next((os.path.join(DATA, n) for n in YOUTUBE_ZIP_NAMES if os.path.exists(os.path.join(DATA, n))), None)
    if not path:
        raise SystemExit(f"Missing the YouTube Spam Collection zip in {DATA} (expected {YOUTUBE_ZIP_NAMES[0]}). "
                         "Download it from https://archive.ics.uci.edu/dataset/380/youtube+spam+collection")
    rows = []
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if not name.lower().endswith(".csv") or name.startswith("__MACOSX"):
                continue
            df = pd.read_csv(io.BytesIO(z.read(name)), encoding="utf-8", on_bad_lines="skip")
            cols = {c.upper(): c for c in df.columns}
            if "CONTENT" not in cols or "CLASS" not in cols:
                continue
            video = re.sub(r"^.*?Youtube\d+-|\.csv$", "", os.path.basename(name), flags=re.I)
            for text, cls in zip(df[cols["CONTENT"]], df[cols["CLASS"]]):
                text = _clean(text)
                if text:
                    rows.append({"text": text, "y": int(cls), "source": "youtube-real", "group": video})
    if not rows:
        raise SystemExit(f"No comment CSVs with CONTENT/CLASS columns found inside {path}.")
    return pd.DataFrame(rows).drop_duplicates(subset=["text"])


def load_sms() -> pd.DataFrame:
    df = pd.read_csv(os.path.join(DATA, "phishing_sms_clean_v2.tsv"), sep="\t", header=None, names=["label", "text"],
                     quoting=3, on_bad_lines="skip").dropna()
    df = df[df["label"].isin(["phishing", "legitimate"])].copy()
    df["text"] = df["text"].map(_clean)
    df = df[df["text"].str.len() >= 8].drop_duplicates(subset=["text"])
    df["y"] = (df["label"] == "phishing").astype(int)
    parts = [g.sample(n=min(SMS_PER_CLASS, len(g)), random_state=42) for _, g in df.groupby("y")]
    out = pd.concat(parts)[["text", "y"]]
    out["source"], out["group"] = "sms-real", "sms"
    return out


def load_curated() -> pd.DataFrame:
    df = pd.read_csv(os.path.join(DATA, "social_media_phishing.csv")).dropna(subset=["text", "label"])
    df["text"] = df["text"].map(_clean)
    df["y"] = (df["label"] == "phishing").astype(int)
    out = df.drop_duplicates(subset=["text"])[["text", "y"]].copy()
    out["source"], out["group"] = "curated-dm", "curated"
    return out


def build_pipeline() -> Pipeline:
    feats = FeatureUnion([
        ("words", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2, max_df=0.95, sublinear_tf=True)),
        ("chars", TfidfVectorizer(lowercase=True, analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                  sublinear_tf=True, max_features=150000)),
    ])
    return Pipeline([("features", feats), ("clf", LogisticRegression(max_iter=3000, C=2.0, class_weight="balanced"))])


def metrics(y, p, thr=0.5) -> dict:
    pred = (p >= thr).astype(int)
    return {"n": int(len(y)), "scam": int(y.sum()), "accuracy": round(float(accuracy_score(y, pred)), 4),
            "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y, pred, zero_division=0)), 4), "f1": round(float(f1_score(y, pred, zero_division=0)), 4),
            "roc_auc": round(float(roc_auc_score(y, p)), 4) if len(set(y)) > 1 else None}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=OUT_NAME)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    yt, sms, cur = load_youtube(), load_sms(), load_curated()
    print(f"YouTube (real):   {len(yt):,} comments ({int(yt.y.sum()):,} spam/scam) from {yt.group.nunique()} videos")
    print(f"SMS (real):       {len(sms):,} messages ({int(sms.y.sum()):,} scam)")
    print(f"Curated DMs:      {len(cur):,} messages ({int(cur.y.sum()):,} scam) -- low weight, never used for scoring")

    yt_test = yt[yt.group.str.contains(HOLDOUT_VIDEO, case=False)]
    yt_train = yt.drop(yt_test.index)
    if yt_test.empty:     # file names differ: hold out a random 20% instead
        yt_train, yt_test = train_test_split(yt, test_size=0.2, random_state=42, stratify=yt.y)
    sms_train, sms_test = train_test_split(sms, test_size=0.2, random_state=42, stratify=sms.y)
    train = pd.concat([yt_train, sms_train, cur], ignore_index=True)

    # each source gets its fixed share of the total weight, whatever its size
    w = train.source.map(lambda s: SOURCE_WEIGHT[s] / (train.source == s).sum()).to_numpy()
    w = w / w.mean()
    pipe = build_pipeline()
    pipe.fit(train.text, train.y, clf__sample_weight=w)

    res = {"youtube_unseen_video": metrics(yt_test.y.to_numpy(), pipe.predict_proba(yt_test.text)[:, 1]),
           "sms_holdout": metrics(sms_test.y.to_numpy(), pipe.predict_proba(sms_test.text)[:, 1])}
    print(f"\nUnseen YouTube video ({HOLDOUT_VIDEO}): {res['youtube_unseen_video']}")
    print(f"Held-out real SMS:                 {res['sms_holdout']}")

    score = lambda t: float(pipe.predict_proba([t])[0][1])
    flagged = [(score(t), t) for t in TRAP_LEGIT if score(t) >= 0.5]
    missed = [(score(t), t) for t in TRAP_PHISH if score(t) < 0.5]
    flag_rate, catch_rate = len(flagged) / len(TRAP_LEGIT), 1 - len(missed) / len(TRAP_PHISH)
    print(f"\nTrap set: normal messages wrongly flagged {len(flagged)}/{len(TRAP_LEGIT)} (bar <= {LEGIT_MAX_FLAG_RATE:.0%}); "
          f"scams caught {len(TRAP_PHISH) - len(missed)}/{len(TRAP_PHISH)} (bar >= {PHISH_MIN_CATCH_RATE:.0%})")
    for p, t in flagged:
        print(f"   FALSE ALARM  P={p:.2f}  {t[:90]}")
    for p, t in missed:
        print(f"   MISSED       P={p:.2f}  {t[:90]}")
    passed = flag_rate <= LEGIT_MAX_FLAG_RATE and catch_rate >= PHISH_MIN_CATCH_RATE
    if not passed and not args.force:
        print("\nTrap-set bar NOT met -- model NOT saved.")
        return 2

    # final model: refit on everything (the held-out numbers above stay the honest estimate)
    full = pd.concat([yt, sms, cur], ignore_index=True)
    wf = full.source.map(lambda s: SOURCE_WEIGHT[s] / (full.source == s).sum()).to_numpy()
    final = build_pipeline()
    final.fit(full.text, full.y, clf__sample_weight=wf / wf.mean())

    os.makedirs(MODELS_DIR, exist_ok=True)
    out = os.path.join(MODELS_DIR, args.out)
    joblib.dump(final, out)
    meta = {
        "model": "TF-IDF (word 1-2 grams + character 3-5 grams) + logistic regression, source-weighted",
        "data": {"youtube_spam_collection": {"rows": int(len(yt)), "scam": int(yt.y.sum()), "videos": int(yt.group.nunique()),
                                             "source": "https://archive.ics.uci.edu/dataset/380/youtube+spam+collection (CC BY 4.0)"},
                 "sms_real_sample": {"rows": int(len(sms)), "scam": int(sms.y.sum()), "source": "phishing_sms_clean_v2.tsv"},
                 "curated_dm": {"rows": int(len(cur)), "weight": SOURCE_WEIGHT["curated-dm"], "note": "hand-written, low weight, not used for testing"}},
        "source_weights": SOURCE_WEIGHT,
        "tests": res | {"trap_set": {"legit_flagged": len(flagged), "legit_total": len(TRAP_LEGIT),
                                     "scams_caught": len(TRAP_PHISH) - len(missed), "scams_total": len(TRAP_PHISH)}},
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    with open(os.path.join(MODELS_DIR, args.out.replace(".joblib", ".metrics.json")), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(f"\n{'Bar met.' if passed else 'FORCED.'} Saved -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
