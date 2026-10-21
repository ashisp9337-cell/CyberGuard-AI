"""Video Analysis with the face-swap video model (21 Oct). The model's answers are simulated here, so the tests do
not depend on the model files being present; the real model is checked separately on real videos."""
import pytest

from app.detectors import deepfake_video as DV
from app.detectors.deepfake import analyze_media

META = {"kind": DV.KIND, "thr_alert": 0.70, "thr_verify": 0.45, "min_faces_for_verdict": 3,
        "results": {"test_celebdf_half_B_honest": {"n": 259, "caught_at_alert": 0.87, "false_alarms_at_alert": 0.0},
                    "test_dfdc_independent": {"n": 400, "auc": 0.72}}, "trained_at": "2026-10-20T20:04:58+00:00"}


def fake(monkeypatch, p, n_faces=16, checked=16):
    level = None if n_faces < 3 else "high" if p >= 0.70 else "medium" if p >= 0.45 else "low"
    out = {"probability": p if level else None, "level": level, "framesWithFace": n_faces, "framesChecked": checked,
           "thrAlert": 0.70, "thrVerify": 0.45, "meta": META,
           "faces": [{"second": float(i), "probability": p} for i in range(n_faces)] if level else []}
    monkeypatch.setattr(DV, "assess_video", lambda path: out)


def video(tmp_path):
    p = tmp_path / "clip.mp4"
    p.write_bytes(b"\x00\x00\x00\x18ftypisom" + b"\x00" * 64)
    return str(p)


def test_a_face_swapped_video_is_flagged_with_the_suspicious_moments(tmp_path, monkeypatch):
    fake(monkeypatch, 0.93)
    r = analyze_media(video(tmp_path), "clip.mp4", "Video Analysis")
    assert r["riskScore"] >= 71 and "looks manipulated" in r["explanation"]
    assert any("Most suspicious moments" in i["description"] and i["triggered"] for i in r["indicators"])
    assert r["deepfakeVideoModel"]["level"] == "high"


def test_verify_level(tmp_path, monkeypatch):
    fake(monkeypatch, 0.55)
    assert 51 <= analyze_media(video(tmp_path), "clip.mp4", "Video Analysis")["riskScore"] <= 70


def test_a_real_looking_video_is_low_but_never_called_proven_real(tmp_path, monkeypatch):
    fake(monkeypatch, 0.05)
    r = analyze_media(video(tmp_path), "clip.mp4", "Video Analysis")
    assert r["riskScore"] <= 25 and "cannot prove the video is genuine" in r["explanation"]
    assert "DFDC" in " ".join(i["description"] for i in r["indicators"])         # the honest limit is shown


def test_too_few_faces_is_no_verdict_not_safe(tmp_path, monkeypatch):
    fake(monkeypatch, 0.0, n_faces=1)
    r = analyze_media(video(tmp_path), "clip.mp4", "Video Analysis")
    assert r["classification"] == "unverified" and r["riskScore"] == 0 and "No Verdict" in r["analysisEngine"]


def test_provenance_proof_wins_over_a_low_face_score(tmp_path, monkeypatch):
    import struct
    fake(monkeypatch, 0.05)
    t = b"Made with Sora"
    tag = struct.pack(">I", 12 + len(t)) + b"\xa9cmt" + struct.pack(">HH", len(t), 0) + t
    udta = struct.pack(">I", 8 + len(tag)) + b"udta" + tag
    moov = struct.pack(">I", 8 + len(udta)) + b"moov" + udta
    p = tmp_path / "sora.mp4"
    p.write_bytes(b"\x00\x00\x00\x10ftypisom\x00\x00\x02\x00" + moov)
    r = analyze_media(str(p), "sora.mp4", "Video Analysis")
    assert r["riskScore"] >= 90 and "made with AI" in r["explanation"]


def test_scan_details_show_the_video_model(tmp_path, monkeypatch):
    from app.services.scan_store import detail_fields
    fake(monkeypatch, 0.93)
    r = analyze_media(video(tmp_path), "clip.mp4", "Video Analysis")
    names = [m["name"] for m in detail_fields(r).get("modelDetails", [])]
    assert "Face-swap video model (EfficientNet-B0, Celeb-DF v2)" in names


@pytest.mark.skipif(not all(__import__("os").path.exists(p) for p in (DV.MODEL_PATH, DV.META_PATH, DV.FACE_DETECTOR_PATH)),
                    reason="video model files not installed")
def test_the_installed_model_loads_and_gives_no_verdict_without_faces(tmp_path):
    import cv2
    import numpy as np
    p = tmp_path / "noface.avi"
    w = cv2.VideoWriter(str(p), cv2.VideoWriter_fourcc(*"MJPG"), 25, (320, 240))
    for i in range(50):
        w.write(np.full((240, 320, 3), i * 4, dtype=np.uint8))
    w.release()
    a = DV.assess_video(str(p))
    assert a["framesChecked"] == 16 and a["framesWithFace"] == 0 and a["level"] is None
    assert a["meta"]["kind"] == DV.KIND
