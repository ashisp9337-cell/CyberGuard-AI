"""
Trains a real malicious-URL classifier on hand-crafted lexical/structural
features (no external API calls needed for training) + Random Forest.

    python -m app.ml.training.train_url
    python -m app.ml.training.train_url --data data/urls_fraudulent_website.csv --out url_fraudulent_website.joblib

With no arguments, trains the shared default model (same as before).
Pass --data/--out to train a subtopic-specific model — the filename you
pass to --out must match an entry in
app/detectors/malicious_url.py::MODEL_FILES for the app to actually use it.

Input file: CSV with a header row, two columns: url,label
where label is "good"/"bad" (or "safe"/"phishing" — see --pos-label).
"""
import argparse
import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
)

from app.detectors.url_features_v2 import extract_features_v2, FEATURE_NAMES_V2

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(HERE, "..", "models")


def main():
    parser = argparse.ArgumentParser(description="Train a malicious URL classifier.")
    parser.add_argument("--data", default=os.path.join(HERE, "data", "malicious_url_sample.csv"),
                         help="Path to a CSV file with columns: url,label")
    parser.add_argument("--out", default="url_model.joblib",
                         help="Output filename, written into app/ml/models/. Must match an entry in "
                              "app/detectors/malicious_url.py::MODEL_FILES to be used by the app.")
    parser.add_argument("--pos-label", default="bad",
                         help="The label string in the data file that means 'malicious' (positive class).")
    args = parser.parse_args()

    os.makedirs(MODELS_DIR, exist_ok=True)
    df = pd.read_csv(args.data)
    df = df.dropna(subset=["url", "label"])
    df["y"] = (df["label"] == args.pos_label).astype(int)
    print(f"Loaded {len(df)} labeled URLs ({df['y'].sum()} malicious / {len(df) - df['y'].sum()} benign)")

    feats = df["url"].apply(lambda u: extract_features_v2(u if "://" in u else f"http://{u}"))
    X = pd.DataFrame(list(feats), columns=FEATURE_NAMES_V2)
    y = df["y"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=200, max_depth=14, class_weight="balanced",
        random_state=42, n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    print("\n=== Malicious URL Classifier — Evaluation ===")
    print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"F1:        {f1_score(y_test, y_pred):.4f}")
    print(f"ROC-AUC:   {roc_auc_score(y_test, y_proba):.4f}")
    print("\nConfusion matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\n" + classification_report(y_test, y_pred, target_names=["benign", "malicious"]))

    importances = sorted(zip(FEATURE_NAMES_V2, clf.feature_importances_), key=lambda x: -x[1])
    print("\nTop feature importances:")
    for name, imp in importances[:10]:
        print(f"  {name}: {imp:.4f}")

    out_path = os.path.join(MODELS_DIR, args.out)
    joblib.dump(clf, out_path)
    print(f"\nSaved trained model -> {out_path}")


if __name__ == "__main__":
    main()