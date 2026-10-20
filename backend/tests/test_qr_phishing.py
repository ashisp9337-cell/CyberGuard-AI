"""QR code phishing: real QR images -> decode -> payload checks (UPI, Wi-Fi ...) + every trained URL model."""
import cv2
import pytest

from app.detectors import malicious_url, qr_analyzer
from app.detectors.qr_payload import classify_payload, payload_indicators, upi_indicators


def make_qr(tmp_path, text, name="code.png"):
    """A real QR image (OpenCV's encoder), enlarged and with a white border like a printed code."""
    img = cv2.QRCodeEncoder.create().encode(text)
    img = cv2.resize(img, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    img = cv2.copyMakeBorder(img, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    path = tmp_path / name
    cv2.imwrite(str(path), img)
    return str(path)


def scan(tmp_path, text):
    return qr_analyzer.analyze_qr(make_qr(tmp_path, text), "code.png", network=False)


def fired(result_or_inds):
    inds = result_or_inds["indicators"] if isinstance(result_or_inds, dict) else result_or_inds
    return {i["label"] for i in inds if i["triggered"]}


# ---- UPI payment codes ------------------------------------------------------------------------------
def upi(**fields):
    from urllib.parse import urlencode
    return classify_payload("upi://pay?" + urlencode(fields)).fields


def test_scam_words_and_fake_organisation_name():
    labels = fired(upi_indicators(upi(pa="9876543210@ybl", pn="SBI Customer Care", am="4999", tn="KYC verification")))
    assert "Scam words in the payee name or note" in labels
    assert "Payee name claims to be an organisation, but it is not a registered merchant" in labels


def test_registered_merchant_with_org_name_is_not_flagged():
    labels = fired(upi_indicators(upi(pa="bigbazaar.store@icici", pn="Big Bazaar", mc="5411", tr="BB123", am="450")))
    assert not labels


def test_unknown_handle_and_malformed_id():
    assert "Unrecognised UPI app / bank handle" in fired(upi_indicators(upi(pa="winner@xyzpay", pn="A")))
    assert "Malformed UPI ID" in fired(upi_indicators(upi(pa="not a upi id", pn="A")))
    assert "No UPI ID in the payment code" in fired(upi_indicators(upi(pn="A")))


def test_large_amount_and_foreign_currency():
    labels = fired(upi_indicators(upi(pa="shop@oksbi", pn="Shop", am="75000", cu="USD")))
    assert {"Large pre-filled amount", "Currency is not INR"} <= labels


def test_upi_scams_score_high_and_shops_stay_safe(tmp_path):
    scam = scan(tmp_path, "upi://pay?pa=bescom.bill@okaxis&pn=BESCOM%20Electricity%20Bill%20Update&am=10"
                          "&tn=Pay%20to%20avoid%20disconnection")
    shop = scan(tmp_path, "upi://pay?pa=chaiwala.ravi@oksbi&pn=Ravi%20Tea%20Stall")
    assert scam["riskScore"] >= 71
    assert shop["riskScore"] <= 25


# ---- links inside QR codes use every trained URL model ----------------------------------------------
class FakeModel:
    """Stands in for one trained URL model."""

    def __init__(self, name, level, p):
        self.name, self.level, self.p = name, level, p

    def __call__(self, url):
        return {"subtopic": self.name, "model": f"{self.name} model", "probability": self.p, "level": self.level,
                "thrAlert": 0.9, "thrVerify": 0.7, "domain": "x", "brandDomain": None, "tricks": [],
                "trainedAt": "test",
                "indicator": {"label": f"{self.name}: {self.level}", "description": "", "weight": 0,
                              "triggered": self.level != "low", "severity": "high"}}


def test_qr_links_run_all_url_models_and_the_strongest_decides(tmp_path, monkeypatch):
    monkeypatch.setattr(malicious_url, "SUBTOPIC_MODELS", {
        "lookalike-domain": FakeModel("lookalike-domain", "low", 0.1),
        "domain-spoofing": FakeModel("domain-spoofing", "high", 0.99),
        "url-manipulation": FakeModel("url-manipulation", "medium", 0.8)})
    r = scan(tmp_path, "https://example.org/account/update")
    assert r["riskScore"] >= 71
    assert {"domain-spoofing: high", "url-manipulation: medium"} <= fired(r)
    assert "lookalike-domain: low" not in {i["label"] for i in r["indicators"]}   # quiet models stay hidden
    # the URL pages themselves still use only their own model
    one = malicious_url.analyze_url("https://example.org/a", "x", subtopic_id="url-manipulation", network=False)
    assert one["subtopicModel"]["subtopic"] == "url-manipulation" and "urlModels" not in one


def test_qr_link_without_models_still_works(tmp_path, monkeypatch):
    monkeypatch.setattr(malicious_url, "SUBTOPIC_MODELS", {})
    r = scan(tmp_path, "http://paypal.com@203.0.113.9/login")
    assert r["riskScore"] >= 71                                  # the rules alone catch the '@' trick


# ---- other QR contents ------------------------------------------------------------------------------
@pytest.mark.parametrize("text,label", [
    ("WIFI:T:nopass;S:Free_Airport_WiFi;;", "Open Wi-Fi network (no encryption)"),
    ("SMSTO:56767:SUBSCRIBE", "SMS to a short code"),
    ("javascript:alert(1)", "Script or executable link scheme"),
    ("bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.5", "Cryptocurrency payment request"),
])
def test_other_payload_kinds(text, label):
    assert label in fired(payload_indicators(classify_payload(text)))


def test_unreadable_image_is_never_called_safe(tmp_path):
    blank = tmp_path / "blank.png"
    cv2.imwrite(str(blank), 255 * __import__("numpy").ones((200, 200), dtype="uint8"))
    r = qr_analyzer.analyze_qr(str(blank), "blank.png", network=False)
    assert r["classification"] == "unverified" and "Decode Failed" in r["analysisEngine"]


def test_general_link_pages_also_run_every_url_model(monkeypatch):
    monkeypatch.setattr(malicious_url, "SUBTOPIC_MODELS", {
        "lookalike-domain": FakeModel("lookalike-domain", "high", 0.99),
        "domain-spoofing": FakeModel("domain-spoofing", "low", 0.1)})
    for page in ("malicious-url", "fraudulent-website"):
        r = malicious_url.analyze_url("https://example.org/a", "x", subtopic_id=page, network=False)
        assert r["riskScore"] >= 71 and len(r["urlModels"]) == 2
