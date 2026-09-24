"""
Trains a real phishing/scam text classifier: TF-IDF features + Logistic
Regression. Run from the `backend/` directory:

    python -m app.ml.training.train_phishing
    python -m app.ml.training.train_phishing --data data/phishing_email_real.tsv --out phishing_email.joblib --pos-label phishing

With no arguments, trains the shared default model (same as before).
Pass --data/--out/--pos-label to train a subtopic-specific model — the
filename you pass to --out must match an entry in
app/detectors/phishing.py::MODEL_FILES for the app to actually use it.

Input file: tab-separated, two columns, no header: <label>\t<text>
"""
import argparse
import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
)

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(HERE, "..", "models")


def load_data(data_path: str, pos_label: str) -> pd.DataFrame:
    df = pd.read_csv(data_path, sep="\t", header=None, names=["label", "text"])
    df = df.dropna(subset=["text"])
    df["y"] = (df["label"] == pos_label).astype(int)
    return df


def main():
    parser = argparse.ArgumentParser(description="Train a phishing/scam text classifier.")
    parser.add_argument("--data", default=os.path.join(HERE, "data", "phishing_text_sample.tsv"),
                         help="Path to a tab-separated <label>\\t<text> file (relative paths are relative to backend/).")
    parser.add_argument("--out", default="phishing_pipeline.joblib",
                         help="Output filename, written into app/ml/models/. Must match an entry in "
                              "app/detectors/phishing.py::MODEL_FILES to be used by the app.")
    parser.add_argument("--pos-label", default="spam",
                         help="The label string in the data file that means 'phishing/scam' (positive class).")
    args = parser.parse_args()

    os.makedirs(MODELS_DIR, exist_ok=True)
    df = load_data(args.data, args.pos_label)
    print(f"Loaded {len(df)} labeled samples ({df['y'].sum()} positive / {len(df) - df['y'].sum()} negative)")

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["y"], test_size=0.2, random_state=42, stratify=df["y"]
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True, stop_words="english", ngram_range=(1, 2),
            min_df=2, max_df=0.95, sublinear_tf=True,
        )),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", C=3.0)),
    ])

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    print("\n=== Phishing/Scam Text Classifier — Evaluation ===")
    print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"F1:        {f1_score(y_test, y_pred):.4f}")
    print(f"ROC-AUC:   {roc_auc_score(y_test, y_proba):.4f}")
    print("\nConfusion matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\n" + classification_report(y_test, y_pred, target_names=["legitimate", "phishing/scam"]))

    out_path = os.path.join(MODELS_DIR, args.out)
    joblib.dump(pipeline, out_path)
    print(f"\nSaved trained pipeline -> {out_path}")


if __name__ == "__main__":
    main()