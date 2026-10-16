"""URL Security -> URL manipulation: normalisation, trick detection, scanner wiring and training."""
import os
import random
import sys

import joblib
import numpy as np
import pytest

from app.detectors import malicious_url
from app.detectors import url_manipulation as M


def feats(url):
    f, findings = M.manipulation_features(url)
    return dict(zip(M.FEATURES, f)), findings


def test_scheme_and_www_are_ignored():
    # in the public datasets these say where a link was collected, not whether it is malicious
    assert M.normalise("HTTPS://www.example.com/a?b=1") == "example.com/a?b=1"
    assert M.manipulation_features("http://www.example.com/a?b=1") == M.manipulation_features("example.com/a?b=1")


def test_split_handles_userinfo_port_and_ipv6():
    assert M.split("user:pw@host.com:8080/p?q=1#f") == ("user:pw@host.com:8080", "host.com", "8080", "/p", "q=1", "f")
    assert M.split("[::1]:443/x")[1:3] == ("[::1]", "443")


@pytest.mark.parametrize("url,feature,text", [
    ("http://paypal.com@185.22.4.9/login", "userinfo_at", "'@' trick"),
    ("http://3232235777/admin", "host_odd_ip", "disguised"),
    ("http://0xC0A80101/login.php", "host_odd_ip", "disguised"),
    ("https://site.com/%2e%2e/%2e%2e/etc/passwd", "encoded_dot_segments", "'../'"),
    ("https://site.com/a/%252e%252e/b", "double_encoding", "double encoding"),
    ("https://t.co/r?url=http%3A%2F%2Fevil.xyz%2Flogin", "redirect_param_with_url", "second link"),
    ("http://1.2.3.4:8080/invoice.exe", "exec_download", "program file"),
    ("http://paypal.com.secure.verify.badsite.net/x", "hidden_domain_in_host", "hidden in front"),
])
def test_tricks_are_found_and_explained(url, feature, text):
    x, findings = feats(url)
    assert x[feature] > 0 and any(text in f for f in findings)


def test_ordinary_links_have_no_findings():
    for url in ("https://en.wikipedia.org/wiki/Phishing", "https://www.hdfcbank.com/personal/pay/cards",
                "https://github.com/ashisp9337-cell/Cyberdeck-AI"):
        assert feats(url)[1] == []


def test_bare_domains_have_no_structure():
    assert not M.has_structure("paypal.com") and not M.has_structure("https://www.paypal.com/")
    assert M.has_structure("paypal.com/signin") and M.has_structure("site.com/?q=1")


# ---- scanner wiring --------------------------------------------------------------------------
class FixedModel:
    def __init__(self, p):
        self.p = p

    def predict_proba(self, X):
        X = np.asarray(X)
        return np.column_stack([1 - np.full(len(X), self.p), np.full(len(X), self.p)])


@pytest.fixture()
def model_file(tmp_path, monkeypatch):
    path = tmp_path / "url_manipulation.joblib"
    monkeypatch.setattr(M, "MODEL_PATH", str(path))
    M._cache.clear()

    def write(p, features=None):
        joblib.dump({"kind": "cyberguard-url-manipulation", "version": 1, "features": features or list(M.FEATURES),
                     "model": FixedModel(p), "thr_alert": 0.9, "thr_verify": 0.7, "trained_at": "test"}, path)
        os.utime(path, (p * 1000 + 1, p * 1000 + 1))
    yield write
    M._cache.clear()


def scan(url, sub="url-manipulation"):
    return malicious_url.analyze_url(url, "URL Manipulation Detection", subtopic_id=sub, network=False)


def test_model_levels(model_file):
    model_file(0.95)
    r = scan("https://site.com/a/b/c?x=1")
    assert r["subtopicModel"]["level"] == "high" and r["riskScore"] >= 71
    model_file(0.8)
    assert scan("https://site.com/a/b/c?x=1")["subtopicModel"]["level"] == "medium"


def test_unambiguous_tricks_are_always_high(model_file):
    model_file(0.01)                       # even if the model is unsure
    for url in ("http://paypal.com@185.22.4.9/login", "http://3232235777/admin"):
        r = scan(url)
        assert r["subtopicModel"]["level"] == "high" and r["riskScore"] >= 71


def test_path_traversal_is_at_least_check_carefully(model_file):
    model_file(0.01)
    assert scan("https://site.com/%2e%2e/%2e%2e/etc/passwd")["subtopicModel"]["level"] == "medium"


def test_bare_domain_and_other_pages(model_file):
    model_file(0.99)
    assert "subtopicModel" not in scan("paypal.com")                         # nothing in the link to judge
    assert "subtopicModel" not in scan("https://site.com/a?x=1", sub="lookalike-domain")


def test_missing_or_old_model_falls_back(model_file):
    assert "subtopicModel" not in scan("https://site.com/a?x=1")
    model_file(0.99, features=["old"])
    assert "subtopicModel" not in scan("https://site.com/a?x=1")


# ---- training end to end on tiny made-up files -----------------------------------------------------
def test_training_writes_the_model(tmp_path, monkeypatch):
    from app.ml.training import train_url_manipulation as T
    rnd = random.Random(2)
    word = lambda n: "".join(rnd.choice("abcdefghijklmnop") for _ in range(n))     # noqa: E731
    lines = []
    for i in range(600):
        lines.append(f"legitimate\thttps://www.{word(7)}.com/{word(5)}/{word(6)}.html")
        lines.append(f"phishing\thttp://{word(9)}.xyz/{word(4)}/{word(30)}/login.php?id={word(25)}")
    (tmp_path / "d.txt").write_text("\n".join(lines))
    (tmp_path / "k.csv").write_text("url,label\n" + "".join(
        f"{word(6)}.org/{word(5)}/page{i}.html,good\nhttp://{rnd.randint(1, 200)}.{rnd.randint(1, 200)}.1.1/{word(4)}.exe,bad\n"
        for i in range(300)))
    out = tmp_path / "models"
    monkeypatch.setattr(sys, "argv", ["x", "--data", str(tmp_path / "d.txt"), str(tmp_path / "k.csv"),
                                      "--phiusiil", "", "--out", str(out), "--quick"])
    T.main()
    b = joblib.load(out / "url_manipulation.joblib")
    assert b["kind"] == "cyberguard-url-manipulation" and b["features"] == M.FEATURES
    assert 0 < b["thr_verify"] <= b["thr_alert"] <= 1 and (out / "url_manipulation.metrics.json").exists()
