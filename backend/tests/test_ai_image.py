"""Deepfake -> AI-generated images: provenance proof, the CLIP-based model, and how all image checks combine."""
import io
import json
import struct
import zlib

import numpy as np
import pytest
from PIL import Image

from app.detectors import ai_image as AI
from app.detectors import deepfake
from app.detectors import deepfake_image as DI

META = {"kind": "cyberguard-ai-image", "architecture": "CLIP ViT-L/14 + linear", "dataset": "test images",
        "input_size": 224, "mean": [0.48145466, 0.4578275, 0.40821073], "std": [0.26862954, 0.26130258, 0.27577711],
        "thr_alert": 0.8, "thr_verify": 0.5, "trained_at": "test",
        "results": {"test": {"n": 1000, "caught_at_alert": 0.9, "false_alarms_at_alert": 0.01}}}


# ---- helpers: real image files with real metadata ------------------------------------------------------
def photo(tmp_path, name="photo.jpg", size=(640, 480), **save):
    img = Image.fromarray((np.random.default_rng(0).random((size[1], size[0], 3)) * 255).astype("uint8"))
    path = tmp_path / name
    img.save(path, **save)
    return str(path)


def jpeg_with_segment(tmp_path, marker: int, payload: bytes, name="c.jpg"):
    """A JPEG with one extra APPn segment right after SOI (where C2PA / XMP live)."""
    buf = io.BytesIO()
    Image.new("RGB", (64, 64), (120, 130, 140)).save(buf, "JPEG")
    data = buf.getvalue()
    seg = bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload
    path = tmp_path / name
    path.write_bytes(data[:2] + seg + data[2:])
    return str(path)


def png_with_text(tmp_path, key, value, name="g.png", compressed=False):
    from PIL import PngImagePlugin
    info = PngImagePlugin.PngInfo()
    (info.add_itxt if compressed else info.add_text)(key, value, **({"zip": True} if compressed else {}))
    path = tmp_path / name
    Image.new("RGB", (64, 64), (10, 20, 30)).save(path, pnginfo=info)
    return str(path)


# ---- 1. provenance --------------------------------------------------------------------------------------
def test_c2pa_ai_declaration_is_proof(tmp_path):
    payload = b"JP\x00\x00jumbc2pa ... c2pa.actions digitalSourceType http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
    pr = AI.provenance(jpeg_with_segment(tmp_path, 0xEB, payload))
    assert pr["proof"] and pr["hasContentCredentials"]
    assert pr["findings"][0]["label"] == "Content Credentials: made with AI"


def test_generative_fill_is_partly_ai(tmp_path):
    xmp = b"http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta>Iptc4xmpExt:DigitalSourceType=compositeWithTrainedAlgorithmicMedia</x:xmpmeta>"
    pr = AI.provenance(jpeg_with_segment(tmp_path, 0xE1, xmp))
    assert pr["proof"] and "partly" in pr["findings"][0]["label"]


def test_camera_content_credentials_are_not_ai(tmp_path):
    pr = AI.provenance(jpeg_with_segment(tmp_path, 0xEB, b"JP\x00\x00jumbc2pa c2pa.actions created digitalCapture"))
    assert not pr["proof"] and pr["hasContentCredentials"] and pr["findings"][0]["label"] == "Content Credentials present"


@pytest.mark.parametrize("key,value,compressed", [
    ("parameters", "a cat in space\nNegative prompt: blurry\nSteps: 30, Sampler: DPM++ 2M, CFG scale: 7, Seed: 1", False),
    ("prompt", '{"3": {"class_type": "KSampler", "inputs": {"steps": 20}}}', False),
    ("workflow", '{"nodes": [{"type": "CheckpointLoaderSimple"}]}', True),
])
def test_generator_settings_in_png_are_proof(tmp_path, key, value, compressed):
    pr = AI.provenance(png_with_text(tmp_path, key, value, compressed=compressed))
    assert pr["proof"] and any(f["label"] == "AI generation settings stored in the image" for f in pr["findings"])


def test_generator_name_in_exif_software(tmp_path):
    exif = Image.Exif()
    exif[305] = "Adobe Firefly"
    path = tmp_path / "f.jpg"
    Image.new("RGB", (64, 64)).save(path, exif=exif)
    pr = AI.provenance(str(path))
    assert pr["proof"] and "Adobe Firefly" in pr["findings"][-1]["detail"]


def test_normal_photos_have_no_findings(tmp_path):
    exif = Image.Exif()
    exif[271], exif[272], exif[305] = "Samsung", "SM-A546E", "A546EXXU5CXK1"
    for p in (photo(tmp_path, "a.jpg", exif=exif), photo(tmp_path, "b.png"), photo(tmp_path, "c.webp")):
        assert AI.provenance(p) == {"proof": False, "findings": [], "hasContentCredentials": False}


def test_pixels_are_never_searched(tmp_path):
    """Generator names inside the compressed picture data must not count - only real metadata does."""
    path = tmp_path / "x.png"
    Image.new("RGB", (64, 64)).save(path)
    data = path.read_bytes()
    i = data.index(b"IDAT") - 4
    body = b"midjourney openai trainedAlgorithmicMedia"
    fake_chunk = struct.pack(">I", len(body)) + b"abCd" + body + struct.pack(">I", zlib.crc32(b"abCd" + body))
    path.write_bytes(data[:i] + fake_chunk + data[i:])
    assert not AI.provenance(str(path))["proof"]


# ---- 2. the model -----------------------------------------------------------------------------------------
class FakeSession:
    def __init__(self, logits):
        self.logits, self.seen = list(logits), []

    def get_inputs(self):
        return [type("I", (), {"name": "input"})()]

    def run(self, _o, feeds):
        self.seen.append(feeds["input"].shape)
        return [np.array([[self.logits.pop(0) if len(self.logits) > 1 else self.logits[0]]], dtype=np.float32)]


def logit(p):
    return float(np.log(p / (1 - p)))


@pytest.fixture()
def models(monkeypatch):
    def install(ai_p=None, face_p=None, faces=((100, 120, 160, 160, 0.98),)):
        if ai_p is None:
            monkeypatch.setattr(AI, "load", lambda: (_ for _ in ()).throw(AI.ModelUnavailable("not installed")))
        else:
            ps = ai_p if isinstance(ai_p, (list, tuple)) else [ai_p]
            sess = FakeSession([logit(p) for p in ps])
            monkeypatch.setattr(AI, "load", lambda: (sess, META))
        if face_p is None:
            monkeypatch.setattr(DI, "load", lambda: (_ for _ in ()).throw(DI.ModelUnavailable("not installed")))
        else:
            fs = type("S", (), {"get_inputs": lambda self: [type("I", (), {"name": "input"})()],
                                "run": lambda self, o, f: [np.array([[logit(face_p)]], dtype=np.float32)]})()
            monkeypatch.setattr(DI, "load", lambda: (fs, dict(kind="cyberguard-deepfake-image", input_size=224,
                                                             thr_alert=0.8, thr_verify=0.5, face_margin=0.25)))
            monkeypatch.setattr(DI, "find_faces", lambda bgr: list(faces))
    return install


def test_views_cover_wide_and_tall_pictures():
    for size, n in (((300, 300), 1), ((1200, 400), 3), ((400, 1200), 3), ((260, 224), 1)):
        v = AI.views(Image.new("RGB", size), 224)
        assert len(v) == n and all(c.size == (224, 224) for c in v)


def test_to_tensor_uses_clip_normalisation():
    x = AI.to_tensor(Image.new("RGB", (224, 224), (255, 255, 255)), META)
    assert x.shape == (1, 3, 224, 224) and x.dtype == np.float32
    assert np.allclose(x[0, :, 0, 0], (1 - np.array(META["mean"])) / np.array(META["std"]), atol=1e-5)


def test_ai_generated_picture_scores_high(tmp_path, models):
    models(ai_p=0.97)
    r = deepfake.analyze_media(photo(tmp_path), "photo.jpg", "AI-Generated Multimedia Detection")
    assert r["riskScore"] >= 71 and r["aiImageModel"]["level"] == "high"
    assert "AI-image model" in r["analysisEngine"] and r["explanation"].startswith("AI-image model: 97%")


def test_most_ai_looking_part_decides(tmp_path, models):
    models(ai_p=[0.1, 0.9, 0.2])
    r = deepfake.analyze_media(photo(tmp_path, size=(1200, 400)), "wide.jpg", "x")
    assert r["aiImageModel"]["views"] == [0.1, 0.9, 0.2] and r["aiImageModel"]["probability"] == pytest.approx(0.9)


def test_real_photo_is_low_and_says_it_is_not_proof(tmp_path, models):
    models(ai_p=0.05, face_p=0.05)
    r = deepfake.analyze_media(photo(tmp_path), "photo.jpg", "x")
    assert r["riskScore"] <= 25 and "cannot prove" in r["explanation"]


def test_face_swap_decides_when_it_is_stronger(tmp_path, models):
    models(ai_p=0.1, face_p=0.97)
    r = deepfake.analyze_media(photo(tmp_path), "photo.jpg", "x")
    assert r["riskScore"] >= 71 and r["explanation"].startswith("Face-swap model")
    assert "AI-image model" in r["analysisEngine"] and "Face-swap model" in r["analysisEngine"]


def test_without_a_face_the_face_model_does_not_decide(tmp_path, models):
    models(ai_p=0.1, face_p=0.97, faces=())
    r = deepfake.analyze_media(photo(tmp_path), "landscape.jpg", "x")
    assert r["riskScore"] <= 25 and r["deepfakeModel"]["wholeImage"]


def test_provenance_proof_works_without_any_model(tmp_path, models):
    models()
    path = png_with_text(tmp_path, "parameters", "a castle\nSteps: 25, Sampler: Euler a, CFG scale: 7, Seed: 5")
    r = deepfake.analyze_media(path, "castle.png", "x")
    assert r["riskScore"] == 95 and r["provenance"]["proof"] and r["explanation"].startswith("The file itself declares")


def test_nothing_installed_falls_back_to_metadata(tmp_path, models):
    models()
    r = deepfake.analyze_media(photo(tmp_path), "photo.jpg", "x")
    assert "Metadata-Only" in r["analysisEngine"] and "AI-image model: not installed" in r["explanation"]


def test_wrong_meta_kind_is_refused(tmp_path, monkeypatch):
    pytest.importorskip("onnxruntime")
    (tmp_path / "m.onnx").write_bytes(b"x")
    (tmp_path / "m.json").write_text(json.dumps({"kind": "cyberguard-deepfake-image"}))
    monkeypatch.setattr(AI, "MODEL_PATH", str(tmp_path / "m.onnx"))
    monkeypatch.setattr(AI, "META_PATH", str(tmp_path / "m.json"))
    AI._cache.clear()
    with pytest.raises(AI.ModelUnavailable):
        AI.load()
    AI._cache.clear()


def test_real_onnx_model_end_to_end(tmp_path, monkeypatch):
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
    onnx.save(model, str(tmp_path / "ai_image.onnx"))
    (tmp_path / "ai_image.json").write_text(json.dumps(META))
    monkeypatch.setattr(AI, "MODEL_PATH", str(tmp_path / "ai_image.onnx"))
    monkeypatch.setattr(AI, "META_PATH", str(tmp_path / "ai_image.json"))
    AI._cache.clear()
    a = AI.assess(photo(tmp_path, size=(900, 300)))
    assert 0 < a["probability"] < 1 and len(a["views"]) == 3
    AI._cache.clear()


def test_normal_photo_with_high_raw_face_score_stays_safe(tmp_path, monkeypatch):
    """Real case (18 Oct): a normal camera photo got a raw face-swap score of 79%, but the face model only warns from
    99.9998% - it must be 'safe', explained as 'no manipulation found', with no metadata warnings counted."""
    sess = FakeSession([logit(0.001)])
    monkeypatch.setattr(AI, "load", lambda: (sess, dict(META, thr_alert=0.9023, thr_verify=0.5941)))
    fs = type("S", (), {"get_inputs": lambda self: [type("I", (), {"name": "input"})()],
                        "run": lambda self, o, f: [np.array([[logit(0.79)]], dtype=np.float32)]})()
    monkeypatch.setattr(DI, "load", lambda: (fs, dict(kind="cyberguard-deepfake-image", input_size=224, face_margin=0.25,
                                                     thr_alert=0.9999999957001577, thr_verify=0.9999976932934962)))
    monkeypatch.setattr(DI, "find_faces", lambda bgr: [(100, 120, 160, 160, 0.98)])
    path = tmp_path / "whatsapp.jpg"
    Image.new("RGB", (640, 480), (90, 120, 160)).save(path, "JPEG")           # no EXIF, like a WhatsApp photo
    r = deepfake.analyze_media(str(path), "whatsapp.jpg", "Image Analysis")
    assert r["riskScore"] <= 5 and r["classification"] == "safe"
    assert r["explanation"].startswith("No check found signs of AI generation or face manipulation")
    assert "79% likely manipulated" not in r["explanation"] and "99.9998%" in r["explanation"]
    assert not [i for i in r["indicators"] if i["triggered"]]
    assert any(i["label"].endswith("(info only)") for i in r["indicators"])
    assert any(i["label"] == "Face 1: looks normal" for i in r["indicators"])


def test_low_scores_use_the_raw_model_output():
    assert DI._low_score(0.79, 0.9999976932934962) <= 3          # far below the warning level in model terms
    assert DI._low_score(0.999999, 0.9999976932934962) == 25     # just below it
    assert AI._low_score(0.3, 0.5941) == 0 and AI._low_score(0.58, 0.5941) > 20
