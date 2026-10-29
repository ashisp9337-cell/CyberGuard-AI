"""measure_text_models.py: saved E-mail / SMS results, the proof that the 20% was never trained on, real-only SMS."""
import json
import os
import random
import sys
import warnings

import joblib
import pandas as pd
import pytest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from app.ml.training import measure_text_models as T

HERE = os.path.dirname(os.path.abspath(__file__))
SCAM = ["your account is blocked verify kyc now at {u}", "you won a prize of rs {n} claim at {u} today",
        "urgent pay the customs fee of {n} to release parcel {u}", "bank alert confirm your otp and pin at {u}"]
REAL = ["see you at lunch tomorrow around {n}", "the meeting moved to room {n} after the break",
        "thanks for the notes from class {n}", "mom is cooking dinner, come home by {n}"]
EXTRA = ["thing", "today", "really", "maybe", "please", "soon", "again", "later", "okay", "nice"]


def _rows(n, seed):
    r = random.Random(seed)
    out = []
    for i in range(n):
        scam = i % 3 == 0
        t = r.choice(SCAM if scam else REAL).format(u=f"http://x{r.randrange(999)}.test/a", n=r.randrange(9999))
        out.append(("phishing" if scam else "legitimate", f"{t} {r.choice(EXTRA)} {r.choice(EXTRA)} m{i}"))
    return out


def _pipeline():
    return Pipeline([("tfidf", TfidfVectorizer(lowercase=True, stop_words="english", ngram_range=(1, 2),
                                               min_df=2, max_df=0.95, sublinear_tf=True)),
                     ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", C=3.0))])


@pytest.fixture
def setup(tmp_path):
    data, models = tmp_path / "data", tmp_path / "models"
    data.mkdir()
    models.mkdir()
    real = _rows(400, 1)
    template = [("legitimate", f"your bill of rs {i} is due on {i % 28 + 1} mar pay in the official app") for i in range(60)]
    pd.DataFrame(real).to_csv(data / "orig.tsv", sep="\t", header=False, index=False)
    pd.DataFrame(real + template).to_csv(data / "clean.tsv", sep="\t", header=False, index=False)
    df = T.read_tsv(str(data / "clean.tsv"))
    y = (df["label"] == "phishing").astype(int)
    x_tr, _, y_tr, _ = train_test_split(df["text"], y, test_size=0.2, random_state=42, stratify=y)
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Unknown solver options")       # scipy notice, not ours
        joblib.dump(_pipeline().fit(x_tr, y_tr), models / "phishing_sms.joblib")     # trained like the script does
        joblib.dump(_pipeline().fit(df["text"], y), models / "leaky.joblib")          # has seen the 20%
    return data, models


def test_held_out_is_proved_and_template_rows_are_left_out(setup):
    data, models = setup
    m = T.measure("SMS", "phishing_sms.joblib", "clean.tsv", "phishing", "orig.tsv", str(models), str(data))
    assert m["held_out_confirmed"] is True and "results_unconfirmed" not in m
    r = m["results"]
    assert r["heldout"]["messages"] == 92 and r["heldout"]["messages"] == r["heldout"]["scam"] + r["heldout"]["genuine"]
    assert r["heldout_real_only"]["messages"] == r["heldout"]["messages"] - int(m["template_rows"].split(" of them")[0].split("; ")[-1])
    assert r["heldout_real_only"]["scam"] == r["heldout"]["scam"]                     # templates are all genuine
    assert "60 rows of clean.tsv are not in orig.tsv" in m["template_rows"]
    assert r["heldout_real_unseen_texts"]["messages"] <= r["heldout_real_only"]["messages"]
    for v in r.values():
        assert 0.5 < v["auc"] <= 1 and 0 <= v["caught_at_50pct"] <= 1 and 0 <= v["false_alarms_at_50pct"] <= 1
    assert len(m["model_sha256"]) == 64 and len(m["data_sha256"]) == 64


def test_a_model_that_saw_the_test_part_is_caught_and_never_shown(setup, monkeypatch):
    data, models = setup
    m = T.measure("SMS", "leaky.joblib", "clean.tsv", "phishing", "orig.tsv", str(models), str(data))
    assert m["held_out_confirmed"] is False and "results" not in m and m["results_unconfirmed"]["heldout"]["auc"]
    out = T.save(m, str(models))
    sys.path.insert(0, os.path.join(HERE, ".."))
    import show_auc
    monkeypatch.setattr(show_auc, "MODELS", str(models))
    assert show_auc.saved(os.path.basename(out), "results", "heldout", "auc") is None


def test_saved_numbers_are_what_show_auc_shows(setup, monkeypatch):
    data, models = setup
    m = T.measure("SMS", "phishing_sms.joblib", "clean.tsv", "phishing", "orig.tsv", str(models), str(data))
    out = T.save(m, str(models))
    assert os.path.basename(out) == "phishing_sms.metrics.json" and not os.path.exists(out + ".tmp")
    assert json.loads(open(out, encoding="utf-8").read()) == m
    sys.path.insert(0, os.path.join(HERE, ".."))
    import show_auc
    monkeypatch.setattr(show_auc, "MODELS", str(models))
    row = next(items for _, sub, items, _ in show_auc.ROWS if sub == "SMS / message")
    for _, file, *path in row:
        assert show_auc.saved(file, *path) == m["results"][path[1]]["auc"]


def test_normalise_treats_amounts_dates_numbers_and_links_as_the_same():
    a = T.normalise("Pay Rs 1,840 at http://bill-pay.example/x?id=9 by 25 Sep! Call 9876543210")
    b = T.normalise("pay rs 99 at https://other.example by 3 sep. call 12345")
    assert a == b
    assert T.normalise("Mail me: a.b@c.co") == T.normalise("mail me x@y.org")
    assert T.normalise("your parcel is held") != T.normalise("your account is held")


def test_missing_files_are_said_plainly(tmp_path):
    with pytest.raises(OSError, match="missing"):
        T.measure("Email", "phishing_email.joblib", "nothing.tsv", "phishing", None, str(tmp_path), str(tmp_path))
