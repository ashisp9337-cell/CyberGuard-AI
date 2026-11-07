"""(4 Nov) A missing model file must never turn into a made-up verdict, and must never be skipped silently."""
import numpy as np
from PIL import Image

from app.detectors import ai_image as AI
from app.detectors import deepfake
from app.detectors import deepfake_image as DI


def _photo(tmp_path, name="photo.jpg"):
    path = tmp_path / name
    Image.fromarray((np.random.default_rng(1).random((480, 640, 3)) * 255).astype("uint8")).save(path)
    return str(path)


def _no_image_models(monkeypatch):
    monkeypatch.setattr(AI, "load", lambda: (_ for _ in ()).throw(AI.ModelUnavailable("not installed")))
    monkeypatch.setattr(DI, "load", lambda: (_ for _ in ()).throw(DI.ModelUnavailable("not installed")))


def test_image_without_models_gets_no_verdict_not_safe(tmp_path, monkeypatch):
    _no_image_models(monkeypatch)
    r = deepfake.analyze_media(_photo(tmp_path), "photo.jpg", "Image Analysis")
    assert r["classification"] == "unverified" and r["riskScore"] == 0 and r["confidenceScore"] == 0
    assert r["explanation"].startswith("No verdict") and "could not be used" in r["explanation"]
    assert not any(i["triggered"] for i in r["indicators"])           # metadata is info only, never a score
    assert any("image models" in x for x in r["recommendations"])
    assert not any("QR" in x for x in r["recommendations"])            # no QR advice on a photo


def test_png_without_models_is_not_called_safe(tmp_path, monkeypatch):
    _no_image_models(monkeypatch)
    path = tmp_path / "plain.png"
    Image.new("RGB", (256, 256), (120, 160, 200)).save(path)
    r = deepfake.analyze_media(str(path), "plain.png", "Image Analysis")
    assert r["classification"] != "safe" and r["classification"] == "unverified"


def test_missing_domain_registration_model_is_mentioned(monkeypatch, tmp_path):
    from app.detectors import domain_age
    monkeypatch.setattr(domain_age, "MODEL_PATH", str(tmp_path / "missing.joblib"))
    facts = {"ok": True, "created": "2026-10-30T00:00:00Z", "expires": "2027-10-30T00:00:00Z", "registrar": "X"}
    out = domain_age.assess("example-new-site.top", facts=facts)
    assert out["probability"] is None and out.get("modelMissing")
    assert any("not installed on this computer" in s for s in out["sentences"])


def test_missing_fake_login_model_is_reported_when_a_page_was_read(monkeypatch, tmp_path):
    from app.detectors import fake_login, malicious_url
    monkeypatch.setattr(fake_login, "MODEL_PATH", str(tmp_path / "missing.joblib"))
    page = {"html": "<html><form><input type=password></form></html>" * 10, "final_url": "https://x.example/login"}
    assert malicious_url._login_model_missing(page, "fake-login-page") is True
    assert malicious_url._login_model_missing({}, "fake-login-page") is False         # no page read: nothing to say
