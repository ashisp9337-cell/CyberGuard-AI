"""
Trains the QR Code Phishing Detection model specifically — hardcoded
paths, no command-line flags needed. Just run:

    python -m app.ml.training.train_qr

Reads:  app/ml/training/data/url_qr.csv
Writes: app/ml/models/url_qr.joblib

A QR code just encodes a URL — once decoded (see app/detectors/
qr_decoder.py + qr_analyzer.py), it's analyzed using the same v2 URL
feature set (app/detectors/url_features_v2.py) as the other URL-based
subtopics, so training stays consistent across all of them.
"""
from app.ml.training.train_url import main as train_url_main
import sys

if __name__ == "__main__":
    sys.argv = [
        "train_qr.py",
        "--data", "app/ml/training/data/url_qr.csv",
        "--out", "url_qr.joblib",
    ]
    train_url_main()