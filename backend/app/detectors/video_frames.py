"""
Frames and faces from a video - ONE implementation shared by the Kaggle training notebook
(docs/colab/CyberGuard_Deepfake_Video_Kaggle.ipynb copies this file word for word) and the scanner on the PC,
so the model sees exactly the same kind of face crops in training and in real use.

  video --16 frames spread evenly over its length--> each frame: the LARGEST face (OpenCV YuNet detector)
        --> square crop with a 25% margin  (same crop as the deepfake IMAGE model)

Only OpenCV + NumPy. Very large frames are shrunk to MAX_SIDE first (4K videos stay fast and use little memory).
Long videos are not decoded frame by frame: the reader jumps to the next wanted frame.
"""
from __future__ import annotations

import numpy as np

FRAMES = 16           # frames looked at per video
MIN_FACE = 40         # pixels: smaller faces are too blurry to judge (same as the image model)
MARGIN = 0.25         # crop margin around the face box (same as the image model)
MAX_SIDE = 1280       # larger frames are shrunk to this before face detection
JUMP = 90             # if the next wanted frame is further away than this, seek instead of decoding every frame
MAX_FRAMES_UNKNOWN = 3000   # containers that do not report a length: read at most this many frames


def sample_indices(n_frames: int, k: int = FRAMES) -> list[int]:
    """k frame numbers spread evenly from the first to the last frame."""
    if n_frames <= 0:
        return []
    if n_frames <= k:
        return list(range(n_frames))
    return sorted({int(round(x)) for x in np.linspace(0, n_frames - 1, k)})


def _shrink(bgr):
    import cv2
    h, w = bgr.shape[:2]
    s = MAX_SIDE / max(h, w)
    if s < 1:
        bgr = cv2.resize(bgr, (max(1, int(w * s)), max(1, int(h * s))), interpolation=cv2.INTER_AREA)
    return bgr


def read_frames(path: str, k: int = FRAMES) -> list[tuple[int, float, np.ndarray]]:
    """-> [(frame_number, seconds, bgr_frame)] for up to k frames spread over the video."""
    import cv2
    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        return []
    try:
        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        if not (0 < fps < 1000):
            fps = 25.0
        n = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        if n <= 0:                                                   # length unknown: read, then pick
            frames = []
            while len(frames) < MAX_FRAMES_UNKNOWN:
                ok, f = cap.read()
                if not ok:
                    break
                frames.append(f)
            return [(i, i / fps, _shrink(frames[i])) for i in sample_indices(len(frames), k)]
        out, pos = [], 0
        for idx in sample_indices(n, k):
            if idx - pos > JUMP:
                cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
                pos = idx
            while pos < idx:
                if not cap.grab():
                    break
                pos += 1
            ok, f = cap.read()
            pos += 1
            if not ok or f is None:
                continue
            out.append((idx, idx / fps, _shrink(f)))
        return out
    finally:
        cap.release()


def make_detector(model_path: str):
    import cv2
    return create_yunet(cv2, model_path, (320, 320))


def create_yunet(cv2, model_path: str, size):
    """YuNet face detector. OpenCV 5 prints a harmless "Targets are not supported by the new graph engine" warning
    while creating it (the detector asks for the default CPU target, which the new engine already uses). Only that
    creation step runs with OpenCV's log level at ERROR; the previous level is restored right after, so no other
    OpenCV warning is hidden."""
    log = getattr(getattr(cv2, "utils", None), "logging", None)
    old = None
    try:
        if log is not None:
            old = log.getLogLevel()
            log.setLogLevel(log.LOG_LEVEL_ERROR)
        return cv2.FaceDetectorYN.create(model_path, "", size, 0.7, 0.3, 5000)
    finally:
        if log is not None and old is not None:
            log.setLogLevel(old)


def largest_face(bgr: np.ndarray, detector):
    """-> (x, y, w, h, score) of the largest face, or None."""
    h, w = bgr.shape[:2]
    detector.setInputSize((w, h))
    _, faces = detector.detect(bgr)
    if faces is None:
        return None
    boxes = [(int(f[0]), int(f[1]), int(f[2]), int(f[3]), float(f[14])) for f in faces]
    boxes = [b for b in boxes if b[2] >= MIN_FACE and b[3] >= MIN_FACE]
    return max(boxes, key=lambda b: b[2] * b[3]) if boxes else None


def crop_face(bgr: np.ndarray, box, margin: float = MARGIN) -> np.ndarray:
    """Square crop around the face with a margin (identical to deepfake_image.crop_face)."""
    x, y, w, h = box[:4]
    side = int(max(w, h) * (1 + 2 * margin))
    cx, cy = x + w // 2, y + h // 2
    x0, y0 = max(cx - side // 2, 0), max(cy - side // 2, 0)
    x1, y1 = min(x0 + side, bgr.shape[1]), min(y0 + side, bgr.shape[0])
    return bgr[y0:y1, x0:x1]


def video_faces(path: str, detector, k: int = FRAMES, margin: float = MARGIN) -> list[tuple[float, np.ndarray]]:
    """-> [(seconds, face_crop)] - one crop (the largest face) per sampled frame that has a face."""
    out = []
    for _, sec, frame in read_frames(path, k):
        box = largest_face(frame, detector)
        if box is not None:
            crop = crop_face(frame, box, margin)
            if crop.size:
                out.append((sec, crop))
    return out
