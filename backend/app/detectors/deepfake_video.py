"""
Deepfake VIDEO detection (Deepfake module -> Video Analysis / AI-Generated Multimedia) with the model trained on Kaggle
(docs/colab/CyberGuard_Deepfake_Video_Kaggle.ipynb, Celeb-DF v2).

    video --16 frames spread over its length--> the largest face in each frame (YuNet, video_frames.py - the SAME
    code the training notebook used) --> each face scored by EfficientNet-B0 --> video score = mean face score

What it detects: face swap / face re-enactment. NOT fully AI-generated scenes (Sora, Veo ...), NOT lip-sync, NOT voice.
Fewer than 3 faces found -> no verdict (never a guess). Runs on the CPU with onnxruntime; nothing leaves the PC.

Files in backend/app/ml/models/: deepfake_video.onnx + deepfake_video.json (+ face_detection_yunet_2023mar.onnx).
"""
from __future__ import annotations

import json
import os

import numpy as np

from app.detectors import video_frames as VF

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "models")
MODEL_PATH = os.path.join(MODELS_DIR, "deepfake_video.onnx")
META_PATH = os.path.join(MODELS_DIR, "deepfake_video.json")
FACE_DETECTOR_PATH = os.path.join(MODELS_DIR, "face_detection_yunet_2023mar.onnx")
KIND = "cyberguard-deepfake-video"

_cache: dict = {}


class ModelUnavailable(Exception):
    """A model file or onnxruntime is missing, so no verdict can be made."""


def _mtime(path):
    return os.path.getmtime(path) if os.path.exists(path) else None


def load():
    """-> (onnx session, metadata). Reloads when the files change (drop new files in, no restart)."""
    for p, what in ((MODEL_PATH, "deepfake_video.onnx"), (META_PATH, "deepfake_video.json"),
                    (FACE_DETECTOR_PATH, "face_detection_yunet_2023mar.onnx")):
        if not os.path.exists(p):
            raise ModelUnavailable(f"{what} is not in app/ml/models yet")
    key = (_mtime(MODEL_PATH), _mtime(META_PATH))
    if _cache.get("key") != key:
        try:
            import onnxruntime as ort
        except ImportError as e:
            raise ModelUnavailable("onnxruntime is not installed (pip install onnxruntime)") from e
        with open(META_PATH, encoding="utf-8") as f:
            meta = json.load(f)
        if meta.get("kind") != KIND:
            raise ModelUnavailable("deepfake_video.json is not a CyberGuard deepfake-video model description")
        sess = ort.InferenceSession(MODEL_PATH, providers=["CPUExecutionProvider"])
        _cache.update(key=key, session=sess, meta=meta)
    return _cache["session"], _cache["meta"]


def prepare(crop: np.ndarray, meta: dict) -> np.ndarray:
    """Face crop -> 3xHxW float32, exactly like training: the notebook stored each crop as a 256x256 JPEG (quality
    95), then resized it to the model size -> RGB -> /255 -> mean/std."""
    import cv2
    face = cv2.resize(crop, (256, 256), interpolation=cv2.INTER_AREA)
    face = cv2.imdecode(cv2.imencode(".jpg", face, [cv2.IMWRITE_JPEG_QUALITY, 95])[1], cv2.IMREAD_COLOR)
    size = int(meta.get("input_size", 224))
    img = cv2.resize(face, (size, size), interpolation=cv2.INTER_LINEAR)
    img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
    img = (img - np.array(meta["mean"], np.float32)) / np.array(meta["std"], np.float32)
    return np.transpose(img, (2, 0, 1)).astype(np.float32)


def assess_video(file_path: str) -> dict:
    """-> {"probability", "level" (high/medium/low/None = no verdict), "faces": [{"second", "probability"}],
           "framesWithFace", "framesChecked", "thrAlert", "thrVerify", "meta"}.
    Raises ModelUnavailable if the model is not installed."""
    session, meta = load()
    k = int(meta.get("frames_per_video", VF.FRAMES))
    detector = VF.make_detector(FACE_DETECTOR_PATH)
    frames = VF.read_frames(file_path, k)
    faces = []
    for _, sec, frame in frames:
        box = VF.largest_face(frame, detector)
        if box is not None:
            crop = VF.crop_face(frame, box, float(meta.get("face_margin", VF.MARGIN)))
            if crop.size:
                faces.append((sec, crop))
    ta, tv = float(meta["thr_alert"]), float(meta["thr_verify"])
    out = {"framesChecked": len(frames), "framesWithFace": len(faces), "thrAlert": ta, "thrVerify": tv,
           "meta": meta, "faces": [], "probability": None, "level": None}
    if len(faces) < int(meta.get("min_faces_for_verdict", 3)):
        return out
    batch = np.stack([prepare(c, meta) for _, c in faces])
    logits = session.run(None, {session.get_inputs()[0].name: batch})[0].reshape(-1).astype(np.float64)
    probs = 1.0 / (1.0 + np.exp(-logits))
    p = float(probs.mean())
    out.update(probability=p, level="high" if p >= ta else "medium" if p >= tv else "low",
               faces=[{"second": round(float(s), 1), "probability": round(float(q), 4)}
                      for (s, _), q in zip(faces, probs)])
    return out


def score_from(a: dict) -> int:
    """Alert level -> 71-100, verify level -> 51-70, below -> 0-25 (same scale as the image models)."""
    p, ta, tv = a["probability"], a["thrAlert"], a["thrVerify"]
    if a["level"] == "high":
        return min(100, 71 + round(29 * (p - ta) / max(1 - ta, 1e-6)))
    if a["level"] == "medium":
        return min(70, 51 + round(19 * (p - tv) / max(ta - tv, 1e-6)))
    return round(25 * min(p, tv) / max(tv, 1e-6))
