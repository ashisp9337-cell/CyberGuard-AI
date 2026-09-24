"""
Trains the Fraudulent Website Detection model specifically — hardcoded
paths, no command-line flags needed. Just run:

    python -m app.ml.training.train_fraudulent_website

Reads:  app/ml/training/data/url_fraudulent_website.csv
Writes: app/ml/models/url_fraudulent_website.joblib
"""
from app.ml.training.train_url import main as train_url_main
import sys

if __name__ == "__main__":
    sys.argv = [
        "train_fraudulent_website.py",
        "--data", "app/ml/training/data/url_fraudulent_website.csv",
        "--out", "url_fraudulent_website.joblib",
    ]
    train_url_main()