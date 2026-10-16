"""URL Security -> Look-alike domains: name normalisation, features, scanner wiring and training."""
import io
import os
import sys
import zipfile

import joblib
import numpy as np
import pytest

pytest.importorskip("rapidfuzz")
from app.detectors import lookalike_domain as L          # noqa: E402
from app.detectors import malicious_url                   # noqa: E402

PROTECTED = [("paypal.com", 5), ("microsoft.com", 3), ("google.com", 1), ("hdfcbank.com", 900), ("amazon.in", 400),
             ("bing.com", 30), ("netflix.com", 20)]


def feats(domain, index=None):
    f, d = L.lookalike_features(domain, index or L.BrandIndex(PROTECTED))
    return (dict(zip(L.FEATURES, f)) if f else None), d


@pytest.mark.parametrize("label,brand", [
    ("pаypal", "paypal"),             # Cyrillic а
    ("xn--pypal-4ve", "paypal"),      # the same written as punycode
    ("rnicrosoft", "microsoft"),      # rn looks like m
    ("paypa1", "paypal"),             # 1 looks like l
    ("g00gle", "google"),             # 0 looks like o
    ("ƈitibank", "citibank"),         # c with hook (named by Unicode as a Latin c)
    ("hdfc-bank", "hdfcbank"),        # hyphens ignored
])
def test_skeleton_sees_what_a_reader_sees(label, brand):
    assert L.skeleton(label) == L.skeleton(brand)


def test_number_names_are_not_read_as_letters():
    assert L.skeleton("1984") == "1984" and L.skeleton("bet365") == "bet365" and L.skeleton("g00gle") == "google"


def test_unicode_input_is_handled_like_a_browser_does():
    assert L.split_domain("https://pаypal.com/login")[0] == "xn--pypal-4ve.com"
    assert L.split_domain("WWW.HDFCBANK.COM:443/x")[0] == "hdfcbank.com"
    assert L.split_domain("login.sbi.co.in")[0] == "sbi.co.in"


def test_tricks_are_named():
    x, d = feats("paypa1.com")
    assert x["digit_lookalike"] == 1 and x["dist_skel"] == 0 and d["brandDomain"] == "paypal.com"
    x, d = feats("xn--pypal-4ve.com")
    assert x["skeleton_identical"] == 1 and x["non_ascii"] == 1 and x["is_idn"] == 1
    assert "letters from another alphabet" in d["tricks"]
    x, d = feats("micorsoft.com")
    assert x["transposition"] == 1 and "two letters swapped" in d["tricks"]
    x, _ = feats("netflx.com")
    assert x["omission"] == 1
    x, _ = feats("gooogle.com")
    assert x["repetition"] == 1 and x["addition"] == 1
    x, d = feats("paypal.co")
    assert x["dist_skel"] == 0 and x["same_tld"] == 0 and any("different ending" in t for t in d["tricks"])


def test_protected_and_allowlisted_sites_are_never_judged():
    idx = L.BrandIndex(PROTECTED, allowlist={"king.com"})
    assert feats("paypal.com", idx)[0] is None
    assert feats("www.paypal.com", idx)[0] is None
    f, d = feats("king.com", idx)
    assert f is None and d["allowlisted"]
    f, d = feats("uidal.gov.in", L.BrandIndex(PROTECTED + [("uidai.gov.in", 900)]))
    assert f is None and d["controlledSuffix"]          # nobody but the government can register .gov.in


def test_far_names_have_no_brand():
    x, d = feats("rewildingargentina.org")
    assert d.get("noNearBrand") and x["dist_skel"] == L.UNK_DIST


def test_index_survives_saving():
    idx = L.BrandIndex(PROTECTED, allowlist={"king.com"})
    idx2 = L.BrandIndex.from_state(joblib.load(_dump(idx.to_state())))
    assert feats("paypa1.com", idx)[0] == feats("paypa1.com", idx2)[0]


def _dump(obj):
    buf = io.BytesIO()
    joblib.dump(obj, buf)
    buf.seek(0)
    return buf


# ---- scanner wiring --------------------------------------------------------------------------
class FixedModel:
    def __init__(self, p):
        self.p = p

    def predict_proba(self, X):
        X = np.asarray(X)
        return np.column_stack([1 - np.full(len(X), self.p), np.full(len(X), self.p)])


@pytest.fixture()
def model_file(tmp_path, monkeypatch):
    path = tmp_path / "lookalike_domain.joblib"
    monkeypatch.setattr(L, "MODEL_PATH", str(path))
    L._cache.clear()

    def write(p, features=None):
        joblib.dump({"kind": "cyberguard-lookalike", "version": 1, "features": features or list(L.FEATURES),
                     "model": FixedModel(p), "index": L.BrandIndex(PROTECTED, allowlist={"king.com"}).to_state(),
                     "thr_alert": 0.8, "thr_verify": 0.5, "trained_at": "test"}, path)
        os.utime(path, (p * 1000, p * 1000))        # new mtime -> reload
        return path
    yield write
    L._cache.clear()


def scan(url, sub="lookalike-domain"):
    return malicious_url.analyze_url(url, "Look-Alike Domain Detection", subtopic_id=sub, network=False)


def test_lookalike_page_uses_its_own_model(model_file):
    model_file(0.97)
    r = scan("http://paypa1.com/signin")
    m = r["subtopicModel"]
    assert m["subtopic"] == "lookalike-domain" and m["level"] == "high" and m["brandDomain"] == "paypal.com"
    assert r["riskScore"] >= 71 and "Look-alike domain model" in r["analysisEngine"]
    ind = next(i for i in r["indicators"] if i["label"].startswith("Look-alike domain model"))
    assert ind["triggered"] and "digits that look like letters" in ind["description"]


def test_medium_level_asks_to_check(model_file):
    model_file(0.6)
    r = scan("netflx.com")
    assert r["subtopicModel"]["level"] == "medium" and 51 <= r["riskScore"] <= 70


def test_same_name_other_ending_is_verify_not_alert(model_file):
    model_file(0.97)
    r = scan("paypal.co")
    assert r["subtopicModel"]["level"] == "medium" and r["subtopicModel"]["sameNameOtherEnding"]
    assert r["riskScore"] >= 51                                  # other rules may add more
    ind = next(i for i in r["indicators"] if i["label"].startswith("Look-alike domain model"))
    assert "WHOIS" in ind["description"]


def test_model_is_only_used_on_its_own_subtopic(model_file):
    model_file(0.97)
    assert "subtopicModel" not in scan("http://paypa1.com/signin", sub="malicious-url")
    assert "subtopicModel" not in scan("http://paypa1.com/signin", sub=None)


def test_real_sites_are_left_alone(model_file):
    model_file(0.97)
    for url in ("https://www.paypal.com/", "https://king.com/"):
        r = scan(url)
        assert "subtopicModel" not in r


def test_missing_or_old_model_falls_back_to_rules(model_file):
    r = scan("http://paypa1.com/signin")                  # no file yet
    assert "subtopicModel" not in r and r["riskScore"] > 0
    model_file(0.97, features=["old", "features"])
    assert "subtopicModel" not in scan("http://paypa1.com/signin")


# ---- training end to end on a tiny made-up ranking (the real Tranco list is too big for tests) -----
def test_training_writes_the_model(tmp_path, monkeypatch):
    pytest.importorskip("dnstwist")
    from app.ml.training import train_lookalike_domain as T
    import random
    rnd = random.Random(3)
    letters = "abcdefghijklmnoprstuvw"
    names = ["paypal", "microsoft", "netflix", "hdfcbank", "flipkart", "amazon", "google", "whatsapp", "linkedin",
             "dropbox", "github", "twitter", "spotify", "reddit", "airbnb", "wikipedia", "yahoo", "zoom", "adobe",
             "paytm", "icicibank", "axisbank", "swiggy", "zomato", "myntra"]
    names += ["".join(rnd.choice(letters) for _ in range(rnd.randint(6, 10))) for _ in range(500)]
    names += [n[:-1] + rnd.choice(letters) for n in names[:25]]          # genuine-looking close names
    lines = "".join(f"{i + 1},{n}.com\n" for i, n in enumerate(dict.fromkeys(names)))
    zpath = tmp_path / "tranco_test.csv.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("top-1m.csv", lines)
    out = tmp_path / "models"
    monkeypatch.setattr(sys, "argv", ["x", "--tranco", str(zpath), "--phiusiil", "", "--out", str(out), "--quick",
                                      "--protected", "40", "--allow", "60", "--workers", "1"])
    T.main()
    b = joblib.load(out / "lookalike_domain.joblib")
    assert b["kind"] == "cyberguard-lookalike" and b["features"] == L.FEATURES and 0 < b["thr_verify"] <= b["thr_alert"] <= 1
    assert (out / "lookalike_domain.metrics.json").exists()
