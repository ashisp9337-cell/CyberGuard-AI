"""Deepfake -> Image Analysis: the Colab-trained ONNX model, face cropping, scoring and safe fall-backs."""
import json

import cv2
import numpy as np
import pytest

from app.detectors import ai_image as AI
from app.detectors import deepfake
from app.detectors import deepfake_image as DI

META = {"kind": "cyberguard-deepfake-image", "architecture": "EfficientNet-B0", "dataset": "test faces",
        "input_size": 224, "mean": [0.485, 0.456, 0.406], "std": [0.229, 0.224, 0.225], "face_margin": 0.25,
        "thr_alert": 0.8, "thr_verify": 0.5, "trained_at": "test",
        "results": {"test": {"n": 1000, "caught_at_alert": 0.9, "false_alarms_at_alert": 0.01}}}


@pytest.fixture(autouse=True)
def no_ai_image_model(tmp_path, monkeypatch):
    """These tests are about the face-swap model: keep the AI-image model (maybe installed on this PC) out."""
    monkeypatch.setattr(AI, "MODEL_PATH", str(tmp_path / "no_ai_image.onnx"))
    AI._cache.clear()


class FakeSession:
    """Stands in for onnxruntime.InferenceSession: returns a fixed logit."""

    def __init__(self, p):
        self.logit = float(np.log(p / (1 - p)))
        self.seen = []

    def get_inputs(self):
        return [type("I", (), {"name": "input"})()]

    def run(self, _outputs, feeds):
        self.seen.append(feeds["input"].shape)
        return [np.array([[self.logit]], dtype=np.float32)]


def image(tmp_path, name="photo.jpg", size=(480, 640)):
    img = (np.random.default_rng(0).random((*size, 3)) * 255).astype("uint8")
    path = tmp_path / name
    cv2.imwrite(str(path), img)
    return str(path)


@pytest.fixture()
def model(monkeypatch):
    def install(p, faces=((100, 120, 160, 160, 0.98),)):
        sess = FakeSession(p)
        monkeypatch.setattr(DI, "load", lambda: (sess, META))
        monkeypatch.setattr(DI, "find_faces", lambda bgr: list(faces))
        return sess
    return install


def test_manipulated_face_scores_high(tmp_path, model):
    sess = model(0.97)
    r = deepfake.analyze_media(image(tmp_path), "photo.jpg", "Image Analysis")
    assert r["riskScore"] >= 71 and r["deepfakeModel"]["level"] == "high"
    assert "Colab-trained" in r["analysisEngine"] and sess.seen[0] == (1, 3, 224, 224)
    assert any(i["label"].startswith("Face 1:") for i in r["indicators"])


def test_real_face_scores_low_and_medium_is_verify(tmp_path, model):
    model(0.05)
    assert deepfake.analyze_media(image(tmp_path), "photo.jpg", "x")["riskScore"] <= 25
    model(0.6)
    r = deepfake.analyze_media(image(tmp_path), "photo.jpg", "x")
    assert r["deepfakeModel"]["level"] == "medium" and 51 <= r["riskScore"] <= 70


def test_most_suspicious_face_decides(tmp_path, monkeypatch):
    probs = iter([0.1, 0.95, 0.2])
    monkeypatch.setattr(DI, "load", lambda: (None, META))
    monkeypatch.setattr(DI, "find_faces", lambda bgr: [(10, 10, 80, 80, .9), (200, 10, 80, 80, .9), (10, 200, 80, 80, .9)])
    monkeypatch.setattr(DI, "fake_probability", lambda s, m, crop: next(probs))
    a = DI.assess_image(image(tmp_path))
    assert a["probability"] == 0.95 and a["level"] == "high" and len(a["faces"]) == 3


def test_no_face_judges_whole_image_with_lower_confidence(tmp_path, model):
    model(0.9, faces=())
    r = deepfake.analyze_media(image(tmp_path), "photo.jpg", "x")
    assert r["deepfakeModel"]["wholeImage"] and "No face was found" in r["explanation"]


def test_missing_model_falls_back_to_metadata_and_says_why(tmp_path, monkeypatch):
    monkeypatch.setattr(DI, "MODEL_PATH", str(tmp_path / "missing.onnx"))
    DI._cache.clear()
    r = deepfake.analyze_media(image(tmp_path), "photo.jpg", "x")
    assert "Metadata-Only" in r["analysisEngine"] and "could not be used" in r["explanation"]
    assert "deepfakeModel" not in r


def test_videos_are_not_judged_by_the_image_model(tmp_path, model):
    model(0.99)
    r = deepfake.analyze_media(str(tmp_path / "clip.mp4"), "clip.mp4", "x")
    assert "Model Unavailable" in r["analysisEngine"] and r["riskScore"] == 0


def test_preprocess_matches_training():
    meta = dict(META, input_size=64)
    x = DI.preprocess(np.full((100, 50, 3), 255, dtype=np.uint8), meta)
    assert x.shape == (1, 3, 64, 64) and x.dtype == np.float32
    # white pixel: (1 - mean) / std, channel order RGB
    assert np.allclose(x[0, :, 0, 0], (1 - np.array(META["mean"])) / np.array(META["std"]), atol=1e-5)


def test_face_crop_is_square_with_margin_and_inside_the_image():
    bgr = np.zeros((300, 400, 3), dtype=np.uint8)
    crop = DI.crop_face(bgr, (150, 100, 100, 100), 0.25)
    assert crop.shape[:2] == (150, 150)
    edge = DI.crop_face(bgr, (0, 0, 100, 100), 0.25)
    assert edge.shape[0] > 0 and edge.shape[1] > 0


def test_meta_file_of_another_kind_is_refused(tmp_path, monkeypatch):
    pytest.importorskip("onnxruntime")
    (tmp_path / "m.onnx").write_bytes(b"x")
    (tmp_path / "m.json").write_text(json.dumps({"kind": "something-else"}))
    monkeypatch.setattr(DI, "MODEL_PATH", str(tmp_path / "m.onnx"))
    monkeypatch.setattr(DI, "META_PATH", str(tmp_path / "m.json"))
    DI._cache.clear()
    with pytest.raises(DI.ModelUnavailable):
        DI.load()


def test_real_onnx_model_end_to_end(tmp_path, monkeypatch):
    """A tiny real ONNX graph (mean of the input) run by onnxruntime, so the whole path is exercised."""
    onnx = pytest.importorskip("onnx")
    pytest.importorskip("onnxruntime")
    from onnx import TensorProto, helper
    graph = helper.make_graph(
        [helper.make_node("ReduceMean", ["input"], ["m"], keepdims=0, axes=[1, 2, 3]),
         helper.make_node("Unsqueeze", ["m", "ax"], ["logit"])],
        "g", [helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, 3, 224, 224])],
        [helper.make_tensor_value_info("logit", TensorProto.FLOAT, [None, 1])],
        [helper.make_tensor("ax", TensorProto.INT64, [1], [1])])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.save(model, str(tmp_path / "deepfake_image.onnx"))
    (tmp_path / "deepfake_image.json").write_text(json.dumps(META))
    monkeypatch.setattr(DI, "MODEL_PATH", str(tmp_path / "deepfake_image.onnx"))
    monkeypatch.setattr(DI, "META_PATH", str(tmp_path / "deepfake_image.json"))
    monkeypatch.setattr(DI, "FACE_DETECTOR_PATH", str(tmp_path / "no_detector.onnx"))
    DI._cache.clear()
    a = DI.assess_image(image(tmp_path))
    assert 0 < a["probability"] < 1 and a["wholeImage"] and not a["faceDetector"]
    DI._cache.clear()
