"""
Trains the Financial Institution Impersonation text classifier: TF-IDF +
Logistic Regression, same architecture as train_phishing.py. Run from the
`backend/` directory:

    python -m app.ml.training.train_financial_impersonation

Input file (comma-separated, WITH a header — different from the older
phishing .tsv files): columns text,label,source where label is
"phishing" or "legitimate". See app/ml/training/data/financial_institution_impersonation.csv.

Output: app/ml/models/financial_impersonation.joblib — loaded by
app/detectors/financial_impersonation.py.
"""
import argparse
import os

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(HERE, "..", "models")
DEFAULT_DATA = os.path.join(HERE, "data", "financial_institution_impersonation.csv")
OUT_NAME = "financial_impersonation.joblib"


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the Financial Institution Impersonation classifier.")
    ap.add_argument("--data", default=DEFAULT_DATA)
    ap.add_argument("--out", default=OUT_NAME)
    args = ap.parse_args()

    df = pd.read_csv(args.data).dropna(subset=["text", "label"])
    df["y"] = (df["label"] == "phishing").astype(int)
    print(f"Loaded {len(df):,} rows ({int(df.y.sum()):,} phishing / {int((1 - df.y).sum()):,} legitimate)")
    if "source" in df.columns:
        print("By source:", df.groupby("source")["y"].agg(["count", "mean"]).round(3).to_dict("index"))

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["y"], test_size=0.2, random_state=42, stratify=df["y"]
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, stop_words="english", ngram_range=(1, 2),
                                   min_df=2, max_df=0.95, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", C=3.0)),
    ])
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    print("\n=== Financial Institution Impersonation Classifier — Evaluation ===")
    print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"F1:        {f1_score(y_test, y_pred):.4f}")
    print(f"ROC-AUC:   {roc_auc_score(y_test, y_proba):.4f}")
    print("\nConfusion matrix:\n", confusion_matrix(y_test, y_pred))
    print("\n" + classification_report(y_test, y_pred, target_names=["legitimate", "phishing/impersonation"]))

    os.makedirs(MODELS_DIR, exist_ok=True)
    out_path = os.path.join(MODELS_DIR, args.out)
    joblib.dump(pipeline, out_path)
    print(f"\nSaved trained pipeline -> {out_path}")
    print("The running backend picks it up automatically on the next scan (no restart needed).")


if __name__ == "__main__":
    main()