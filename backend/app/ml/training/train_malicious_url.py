"""
Trains the general Malicious URL Analysis model specifically — hardcoded
paths, no command-line flags needed. Just run:

    python -m app.ml.training.train_malicious_url

Reads:  app/ml/training/data/url_general.csv
Writes: app/ml/models/url_general.joblib

Distinct from Fraudulent Website Detection: this trains on a broader,
non-brand-specific slice of confirmed malicious URLs (scams, spam,
malware distribution, generic phishing not tied to a known brand),
since "malicious" is a wider category than "impersonates a login page."
Uses the same bias-fixed v2 feature set (url_features_v2.py) as the
other URL-based subtopics.
"""
from app.ml.training.train_url import main as train_url_main
import sys

if __name__ == "__main__":
    sys.argv = [
        "train_malicious_url.py",
        "--data", "app/ml/training/data/url_general.csv",
        "--out", "url_general.joblib",
    ]
    train_url_main()