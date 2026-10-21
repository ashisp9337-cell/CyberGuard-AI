"""Shared video frame/face code (used by the Kaggle training notebook and, later, the video scanner)."""
import numpy as np

from app.detectors import deepfake_image as DI
from app.detectors import video_frames as V


def test_sixteen_frames_spread_from_first_to_last():
    idx = V.sample_indices(300)
    assert len(idx) == 16 and idx[0] == 0 and idx[-1] == 299 and idx == sorted(set(idx))
    assert V.sample_indices(5) == [0, 1, 2, 3, 4] and V.sample_indices(0) == []


def test_face_crop_is_identical_to_the_image_models_crop():
    img = np.random.default_rng(0).integers(0, 255, (480, 640, 3), dtype=np.uint8)
    for box in [(100, 80, 120, 150), (5, 5, 60, 60), (560, 400, 80, 79)]:
        assert np.array_equal(V.crop_face(img, box, 0.25), DI.crop_face(img, box, 0.25))


def _write_video(path, n, size=(320, 240)):
    import cv2
    w = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"MJPG"), 25, size)
    for i in range(n):
        frame = np.full((size[1], size[0], 3), i % 255, dtype=np.uint8)
        w.write(frame)
    w.release()


def test_reads_sixteen_frames_with_times_and_jumps_through_long_videos(tmp_path):
    p = tmp_path / "clip.avi"
    _write_video(p, 400)
    frames = V.read_frames(str(p))
    assert len(frames) == 16
    assert frames[0][0] == 0 and frames[-1][0] == 399
    assert abs(frames[-1][1] - 399 / 25) < 0.01
    for idx, _, img in frames:                     # really the wanted frames (MJPG shifts colours by 1-2 levels)
        assert abs(int(img[0, 0, 0]) - idx % 255) <= 3, idx


def test_big_frames_are_shrunk_and_broken_files_give_nothing(tmp_path):
    p = tmp_path / "big.avi"
    _write_video(p, 20, size=(1920, 1080))
    assert max(V.read_frames(str(p))[0][2].shape[:2]) == V.MAX_SIDE
    bad = tmp_path / "bad.mp4"
    bad.write_bytes(b"not a video")
    assert V.read_frames(str(bad)) == []
