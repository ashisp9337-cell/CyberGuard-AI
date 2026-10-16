"""URL Security -> Domain spoofing: brand search, features, scanner wiring and training."""
import os
import sys
import zipfile

import joblib
import numpy as np
import pytest

from app.detectors import domain_spoofing as S
from app.detectors import malicious_url

WORDS = {w: i + 1 for i, w in enumerate(
    ["the", "my", "news", "world", "update", "secure", "login", "support", "bank", "group", "apple", "head", "lines",
     "gazette", "online", "help", "refund", "wallet", "verify", "account", "business", "outlet", "mellat", "date",
     "zone", "connect", "service"])}
BRANDS = {"paypal": (5, "paypal.com", "com", 5.5), "sbi": (900, "sbi.co.in", "co.in", 5.5),
          "icicibank": (950, "icicibank.com", "com", 5.5), "apple": (8, "apple.com", "com", 1.0),
          "tbank": (7000, "tbank.ru", "ru", 5.5), "datezone": (9000, "datezone.com", "com", 5.5),
          "coinbase": (300, "coinbase.com", "com", 5.5)}
OWNED = {"paypal": {"paypal.com", "paypal.me"}, "sbi": {"sbi.co.in", "onlinesbi.sbi"}, "apple": {"apple.com"}}


def table(**kw):
    return S.BrandTable(dict(BRANDS), {k: set(v) for k, v in OWNED.items()}, WORDS, {"com": 0.5, "in": 0.01, "xyz": 0.002},
                        allow={"google.com"}, curated={"paypal", "sbi", "icicibank"}, **kw)


def brand(domain):
    f, d = S.spoofing_features(domain, table())
    return d.get("brand"), (dict(zip(S.FEATURES, f)) if f else None), d


def test_letters_read_like_a_person():
    assert S.letters("paypa1-login") == "paypal-login"
    assert S.letters("g00gle") == "google"
    assert S.letters("netease-163mail") == "netease-163mail"        # digit runs stay digits
    assert S.letters("xn--pypal-4ve") == "paypal"                      # Cyrillic а


@pytest.mark.parametrize("domain,expected", [
    ("paypal-login-secure.com", "paypal"),
    ("securepaypal.net", "paypal"),            # after a whole word
    ("paypa1-support.com", "paypal"),          # look-alike letters
    ("sbi-kyc-update.in", "sbi"),              # short brand as its own part
    ("sbionline.xyz", "sbi"),                  # short brand followed by a word
    ("icici-bank-update.online", "icicibank"),  # hyphen inside the brand, whole parts
    ("coinbase-wallet.app", "coinbase"),
])
def test_brand_is_found(domain, expected):
    assert brand(domain)[0] == expected


@pytest.mark.parametrize("domain", [
    "mellatbank-iran.com",       # "tbank" glued inside another word
    "updatezone.org",            # "datezone" starts in the middle of "update"
    "newsbizarre.com",           # "sbi" inside a word
    "sbixq.com",                 # short brand not followed by a word or edge
])
def test_coincidental_matches_are_ignored(domain):
    assert brand(domain)[0] is None


def test_owned_known_and_government_sites_are_not_judged():
    assert brand("paypal.com")[2].get("allowlisted") is None and brand("paypal.com")[1] is None
    assert brand("paypal.me")[1] is None
    assert brand("onlinesbi.sbi")[2].get("ownedByBrand")
    assert brand("google.com")[2].get("allowlisted")
    assert brand("sbi-pension.gov.in")[2].get("controlledSuffix")


def test_features_describe_the_name():
    _, x, d = brand("paypa1-login-secure.xyz")
    assert x["security_words"] >= 2 and x["via_lookalike_letters"] == 1 and x["brand_at_start"] == 1
    assert x["n_hyphens"] == 2 and x["same_tld_as_brand"] == 0
    assert any("security" in sgn for sgn in d["signs"])


def test_brand_history_uses_the_right_prior():
    t = table(stats={"paypal": (90, 100)}, prior=0.1, prior_curated=0.8)
    rate, seen = t.brand_history("paypal")
    assert rate == pytest.approx((90 + 5 * 0.8) / 105) and seen > 2
    assert t.brand_history("sbi")[0] == pytest.approx(0.8)            # protected brand never seen -> curated prior
    assert t.brand_history("coinbase")[0] == pytest.approx(0.1)       # other brand never seen -> global prior
    assert S.BrandTable.from_state(t.to_state()).brand_history("paypal") == (rate, seen)


# ---- scanner wiring --------------------------------------------------------------------------
class FixedModel:
    def __init__(self, p):
        self.p = p

    def predict_proba(self, X):
        X = np.asarray(X)
        return np.column_stack([1 - np.full(len(X), self.p), np.full(len(X), self.p)])


@pytest.fixture()
def model_file(tmp_path, monkeypatch):
    path = tmp_path / "domain_spoofing.joblib"
    monkeypatch.setattr(S, "MODEL_PATH", str(path))
    S._cache.clear()

    def write(p, features=None):
        joblib.dump({"kind": "cyberguard-domain-spoofing", "version": 1, "features": features or list(S.FEATURES),
                     "model": FixedModel(p), "table": table().to_state(), "thr_alert": 0.8, "thr_verify": 0.5,
                     "trained_at": "test"}, path)
        os.utime(path, (p * 1000, p * 1000))
    yield write
    S._cache.clear()


def scan(url, sub="domain-spoofing"):
    return malicious_url.analyze_url(url, "Domain Spoofing Detection", subtopic_id=sub, network=False)


def test_spoofing_page_uses_its_own_model(model_file):
    model_file(0.97)
    r = scan("https://paypal-login-secure.com/verify")
    m = r["subtopicModel"]
    assert m["subtopic"] == "domain-spoofing" and m["level"] == "high" and m["brandDomain"] == "paypal.com"
    assert r["riskScore"] >= 71 and "Domain spoofing model" in r["analysisEngine"]
    ind = next(i for i in r["indicators"] if i["label"].startswith("Domain spoofing model"))
    assert ind["triggered"] and "open it yourself" in ind["description"]


def test_medium_level(model_file):
    model_file(0.6)
    r = scan("sbi-kyc-update.in")
    assert r["subtopicModel"]["level"] == "medium" and r["riskScore"] >= 51


def test_only_on_its_own_page_and_not_on_real_sites(model_file):
    model_file(0.97)
    assert "subtopicModel" not in scan("https://paypal-login-secure.com/verify", sub="malicious-url")
    assert "subtopicModel" not in scan("https://www.paypal.com/")
    assert "subtopicModel" not in scan("https://rewildingargentina.org")      # no brand name inside


def test_missing_or_old_model_falls_back_to_rules(model_file):
    r = scan("https://paypal-login-secure.com/verify")
    assert "subtopicModel" not in r and r["riskScore"] > 0
    model_file(0.97, features=["old"])
    assert "subtopicModel" not in scan("https://paypal-login-secure.com/verify")


# ---- training end to end on tiny made-up files -----------------------------------------------------
def test_training_writes_the_model(tmp_path, monkeypatch):
    pytest.importorskip("wordfreq")
    import random
    from app.ml.training import train_domain_spoofing as T
    rnd = random.Random(5)
    letters = "abcdefghijklmnoprstuvw"
    top = ["paypal", "coinbase", "netflix", "metamask", "shopee", "naver", "binance", "dropbox"]
    names = top + ["".join(rnd.choice(letters) for _ in range(rnd.randint(6, 10))) for _ in range(400)]
    tranco = [f"{n}.com" for n in names]
    tranco += [f"{b}{''.join(rnd.choice(letters) for _ in range(4))}.com" for b in top for _ in range(15)]  # genuine
    phish = [f"{b}-{w}-{rnd.randint(1, 999)}.xyz" for b in top for w in ("login", "verify", "wallet", "support")
             for _ in range(5)]
    legit = [f"https://www.{b}{w}.org" for b in top for w in ("fans", "news", "guide") for _ in range(1)]
    with zipfile.ZipFile(tmp_path / "tranco_t.csv.zip", "w") as z:
        z.writestr("top-1m.csv", "".join(f"{i + 1},{d}\n" for i, d in enumerate(dict.fromkeys(tranco))))
    with zipfile.ZipFile(tmp_path / "phiusiil_t.zip", "w") as z:
        z.writestr("PhiUSIIL.csv", "URL,Domain,label\n" + "".join(f"https://{d},{d},0\n" for d in phish)
                   + "".join(f"{u},{u.split('//')[1]},1\n" for u in legit))
    out = tmp_path / "models"
    monkeypatch.setattr(sys, "argv", ["x", "--tranco", str(tmp_path / "tranco_t.csv.zip"), "--phiusiil",
                                      str(tmp_path / "phiusiil_t.zip"), "--out", str(out), "--quick",
                                      "--protected", "20", "--allow", "10"])
    T.main()
    b = joblib.load(out / "domain_spoofing.joblib")
    assert b["kind"] == "cyberguard-domain-spoofing" and b["features"] == S.FEATURES
    assert 0 < b["thr_verify"] <= b["thr_alert"] <= 1 and (out / "domain_spoofing.metrics.json").exists()
