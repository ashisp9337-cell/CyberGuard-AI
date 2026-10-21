"""
Deepfake IMAGE detection (Deepfake module -> "Image Analysis") with a model trained on Google Colab.

    uploaded image --YuNet face detector--> each face, cropped with a margin
                   --EfficientNet-B0 (ONNX)--> probability that the face is manipulated
                   --highest face decides--> score + plain-language result

Files (all three come from the Colab notebook docs/colab/CyberGuard_Deepfake_Image_Colab.ipynb and go into
backend/app/ml/models/):
    deepfake_image.onnx                   the trained model (EfficientNet-B0, exported to ONNX)
    deepfake_image.json                   how to use it: input size, colour normalisation, alert levels, test results
    face_detection_yunet_2023mar.onnx     OpenCV's YuNet face detector (OpenCV 5 no longer ships the old one)

Runs on the CPU with onnxruntime (pip install onnxruntime) -- no GPU and no PyTorch needed on the PC.
If a file or onnxruntime is missing, the module reports "model not installed" and the old metadata-only check
is used, never a made-up verdict.
"""
from __future__ import annotations

import json
import os

import numpy as np

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "models")
MODEL_PATH = os.path.join(MODELS_DIR, "deepfake_image.onnx")
META_PATH = os.path.join(MODELS_DIR, "deepfake_image.json")
FACE_DETECTOR_PATH = os.path.join(MODELS_DIR, "face_detection_yunet_2023mar.onnx")
MAX_FACES = 5
MIN_FACE = 40            # pixels; smaller faces are too blurry to judge

_cache: dict = {}


class ModelUnavailable(Exception):
    """A file or onnxruntime is missing, so no verdict can be made."""


def _mtime(path):
    return os.path.getmtime(path) if os.path.exists(path) else None


def load():
    """-> (onnx session, metadata dict). Reloads when the files change (drop new files in, no restart)."""
    if not os.path.exists(MODEL_PATH) or not os.path.exists(META_PATH):
        raise ModelUnavailable("deepfake_image.onnx / deepfake_image.json are not in app/ml/models yet")
    key = (_mtime(MODEL_PATH), _mtime(META_PATH))
    if _cache.get("key") != key:
        try:
            import onnxruntime as ort
        except ImportError as e:
            raise ModelUnavailable("onnxruntime is not installed (pip install onnxruntime)") from e
        with open(META_PATH, encoding="utf-8") as f:
            meta = json.load(f)
        if meta.get("kind") != "cyberguard-deepfake-image":
            raise ModelUnavailable("deepfake_image.json is not a CyberGuard deepfake-image model description")
        sess = ort.InferenceSession(MODEL_PATH, providers=["CPUExecutionProvider"])
        _cache.update(key=key, session=sess, meta=meta)
    return _cache["session"], _cache["meta"]


def _face_detector(width, height):
    if not os.path.exists(FACE_DETECTOR_PATH):
        return None
    import cv2
    if not hasattr(cv2, "FaceDetectorYN"):
        return None
    from app.detectors.video_frames import create_yunet
    det = create_yunet(cv2, FACE_DETECTOR_PATH, (width, height))
    return det


def find_faces(bgr: np.ndarray) -> list[tuple[int, int, int, int, float]]:
    """-> [(x, y, w, h, score)] largest first. Empty list if no detector or no face."""
    h, w = bgr.shape[:2]
    det = _face_detector(w, h)
    if det is None:
        return []
    det.setInputSize((w, h))
    _, faces = det.detect(bgr)
    if faces is None:
        return []
    out = [(int(f[0]), int(f[1]), int(f[2]), int(f[3]), float(f[14])) for f in faces]
    out = [f for f in out if f[2] >= MIN_FACE and f[3] >= MIN_FACE]
    return sorted(out, key=lambda f: -(f[2] * f[3]))[:MAX_FACES]


def crop_face(bgr: np.ndarray, box, margin: float) -> np.ndarray:
    """Square crop around the face with a margin, like the face crops the model was trained on."""
    x, y, w, h = box[:4]
    side = int(max(w, h) * (1 + 2 * margin))
    cx, cy = x + w // 2, y + h // 2
    x0, y0 = max(cx - side // 2, 0), max(cy - side // 2, 0)
    x1, y1 = min(x0 + side, bgr.shape[1]), min(y0 + side, bgr.shape[0])
    return bgr[y0:y1, x0:x1]


def preprocess(bgr: np.ndarray, meta: dict) -> np.ndarray:
    """BGR image -> 1x3xHxW float32, exactly as in training (resize, RGB, /255, mean/std)."""
    import cv2
    size = int(meta.get("input_size", 224))
    img = cv2.resize(bgr, (size, size), interpolation=cv2.INTER_LINEAR)
    img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
    mean = np.array(meta.get("mean", [0.485, 0.456, 0.406]), dtype=np.float32)
    std = np.array(meta.get("std", [0.229, 0.224, 0.225]), dtype=np.float32)
    img = (img - mean) / std
    return np.transpose(img, (2, 0, 1))[None].astype(np.float32)


def fake_probability(session, meta, crop: np.ndarray) -> float:
    x = preprocess(crop, meta)
    out = session.run(None, {session.get_inputs()[0].name: x})[0]
    logit = float(np.clip(np.asarray(out).reshape(-1)[0], -50, 50))   # very sure answers: no overflow warning
    return float(1.0 / (1.0 + np.exp(-logit)))


def assess_image(file_path: str) -> dict:
    """-> {"probability", "level", "faces": [...], "thrAlert", "thrVerify", "wholeImage", "meta"}.
    Raises ModelUnavailable if the model is not installed; ValueError if the image cannot be read."""
    import cv2
    session, meta = load()
    data = np.fromfile(file_path, dtype=np.uint8)          # works with non-ASCII Windows paths
    bgr = cv2.imdecode(data, cv2.IMREAD_COLOR)
    if bgr is None:
        raise ValueError("the file is not an image OpenCV can read")
    margin = float(meta.get("face_margin", 0.25))
    faces = find_faces(bgr)
    results = []
    for box in faces:
        crop = crop_face(bgr, box, margin)
        if crop.size:
            results.append({"box": list(box[:4]), "probability": round(fake_probability(session, meta, crop), 4)})
    whole = not results
    if whole:                                               # no face found: judge the whole picture (less reliable)
        results.append({"box": None, "probability": round(fake_probability(session, meta, bgr), 4)})
    p = max(r["probability"] for r in results)
    ta, tv = float(meta["thr_alert"]), float(meta["thr_verify"])
    level = "high" if p >= ta else "medium" if p >= tv else "low"
    return {"probability": p, "level": level, "faces": results, "thrAlert": ta, "thrVerify": tv,
            "wholeImage": whole, "faceDetector": os.path.exists(FACE_DETECTOR_PATH), "meta": meta}


def score_from(a: dict) -> int:
    """Alert level -> 71-100, verify level -> 51-70, below -> 0-25."""
    p, ta, tv = a["probability"], a["thrAlert"], a["thrVerify"]
    if a["level"] == "high":
        return min(100, 71 + round(29 * (p - ta) / max(1 - ta, 1e-6)))
    if a["level"] == "medium":
        return min(70, 51 + round(19 * (p - tv) / max(ta - tv, 1e-6)))
    return _low_score(p, tv)


def _low_score(p: float, tv: float) -> int:
    """Below the verify level -> 0-25 ("safe"). Measured on the raw model output (logit), because these models are
    very sure of themselves: a real photo can get a raw 79% while the warning only starts at 99.9998%."""
    if tv <= 0.5:
        return round(25 * min(p, tv) / max(tv, 1e-6))
    lp = float(np.log(max(p, 1e-12) / max(1 - p, 1e-12)))
    lt = float(np.log(tv / max(1 - tv, 1e-12)))
    return round(25 * min(max(lp, 0.0) / lt, 1.0))
