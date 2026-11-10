"""(11 Nov) A BORDERLINE AI-image score (warning level, below the alert) on a photo that still carries a camera's full
shooting data is "check", not a warning - real Xiaomi phone photos scored 61-62% (warning from 59%). Everything else
is unchanged: no camera data, an editing app in "Software", or an alert-level score still warn. Generated pictures
only; no model files needed (the model results are stand-ins)."""
import numpy as np
import pytest
from PIL import Image

from app.detectors import ai_image as AI, deepfake

META = {"architecture": "CLIP", "dataset": "test", "results": {}}


def model(p, level):
    return lambda fp: ({"probability": p, "level": level, "meta": META, "thrAlert": 0.90, "thrVerify": 0.59,
                        "views": [p]}, None)


def photo(path, camera=True, software=None, shooting=("exposure", "aperture", "iso")):
    img = Image.fromarray((np.random.default_rng(3).random((240, 320, 3)) * 255).astype("uint8"))
    exif = Image.Exif()
    if camera:
        exif[271], exif[272] = "Xiaomi", "22101320I"
        ifd = exif.get_ifd(0x8769)
        ifd[36867] = "2024:06:12 14:42:12"
        if "exposure" in shooting:
            ifd[33434] = 0.01
        if "aperture" in shooting:
            ifd[33437] = 1.8
        if "iso" in shooting:
            ifd[34855] = 100
    if software:
        exif[305] = software
    img.save(path, "JPEG", exif=exif.tobytes(), quality=92)
    return str(path)


@pytest.fixture(autouse=True)
def no_face(monkeypatch):
    monkeypatch.setattr(deepfake, "_face_check", lambda fp: (None, "test: no face model"))


def score(monkeypatch, path, p=0.62, level="medium"):
    monkeypatch.setattr(deepfake, "_ai_check", model(p, level))
    r, why = deepfake._image_model_result(path, "Image Analysis")
    return r


def test_borderline_score_on_a_camera_photo_is_check_only(monkeypatch, tmp_path):
    assert AI.camera_capture(photo(tmp_path / "a.jpg")) == "Xiaomi 22101320I (exposure time, aperture, ISO)"
    r = score(monkeypatch, photo(tmp_path / "a.jpg"))
    assert r["riskScore"] < 51, r["explanation"]
    ind = next(i for i in r["indicators"] if "full camera data" in i["label"])
    assert ind["triggered"] is False and "not proof" in ind["description"]


def test_without_camera_data_the_same_score_still_warns(monkeypatch, tmp_path):
    assert score(monkeypatch, photo(tmp_path / "b.jpg", camera=False))["riskScore"] >= 51
    assert AI.camera_capture(photo(tmp_path / "c.jpg", shooting=("iso",))) is None      # 1 shooting field is not enough
    assert score(monkeypatch, photo(tmp_path / "c.jpg", shooting=("iso",)))["riskScore"] >= 51


def test_editing_app_in_software_keeps_the_warning(monkeypatch, tmp_path):
    for app in ("Adobe Photoshop 25.0", "Snapseed", "Meitu", "Remini"):
        assert score(monkeypatch, photo(tmp_path / "d.jpg", software=app))["riskScore"] >= 51, app


def test_alert_level_is_never_softened(monkeypatch, tmp_path):
    assert score(monkeypatch, photo(tmp_path / "e.jpg"), p=0.97, level="high")["riskScore"] >= 71
