"""2026 link model inside the URL engine: only its alert level raises a score, its verify level is a note only."""
import warnings

import joblib
import pytest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from app.detectors import link_2026 as L
from app.detectors import malicious_url as MU


def test_normalise():
    assert L.normalise("HTTPS://www.Example.com/Login/123?a=9#x") == "example.com/login/0?a=0"
    assert L.normalise("") == ""
    # the free host's own name is hidden: the model cannot learn "vercel.app = phishing"
    assert L.normalise("https://my-portfolio.vercel.app/") == "my-portfolio.freehost/"
    assert L.normalise("https://x9.github.io:8080/a") == "x0.freehost/a"


@pytest.fixture
def fake_model(tmp_path, monkeypatch):
    phish = [f"secure-verify-{i}.vercel.app/login/account-{i}" for i in range(40)]
    real = [f"shop{i}.example.org/products/item-{i}" for i in range(40)]
    pipe = Pipeline([("c", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5))), ("lr", LogisticRegression())])
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Unknown solver options")
        pipe.fit([L.normalise(u) for u in phish + real], [1] * 40 + [0] * 40)
    path = tmp_path / "link_2026.joblib"
    def install(alert, verify):
        joblib.dump({"kind": L.KIND, "pipeline": pipe, "thr_alert": alert, "thr_verify": verify, "trained_at": "t"}, path)
        L._cache.clear()
    monkeypatch.setattr(L, "MODEL_PATH", str(path))
    return install


def _score(url):
    return MU.analyze_url(url, subtopic_id="fraudulent-website", network=False)


def test_alert_level_raises_the_score(fake_model):
    url = "https://secure-verify-77.vercel.app/login/account-77"
    fake_model(0.99, 0.98)
    base = _score(url)["riskScore"]
    fake_model(0.55, 0.30)
    r = _score(url)
    assert r["riskScore"] >= 71 and r["riskScore"] >= base
    assert any(i["label"].startswith("2026 link model: looks like") and i["triggered"] for i in r["indicators"])


def test_verify_level_is_only_a_note(fake_model):
    url = "https://secure-verify-77.vercel.app/login/account-77"
    fake_model(0.999, 0.999)                 # below every level: no effect
    base = _score(url)["riskScore"]
    fake_model(0.999, 0.30)                  # verify level only
    r = _score(url)
    assert r["riskScore"] == base
    assert any("note only" in i["label"] for i in r["indicators"])


def test_without_the_model_file_the_engine_works(monkeypatch, tmp_path):
    monkeypatch.setattr(L, "MODEL_PATH", str(tmp_path / "missing.joblib"))
    L._cache.clear()
    r = _score("https://example.org/")
    assert "2026 link model" not in r["analysisEngine"]
    assert L.assess("https://example.org/") is None


def test_only_general_url_pages_use_it():
    assert "link-2026" in MU.SUBTOPIC_MODELS and "link-2026" not in MU.ALL_URL_MODELS
