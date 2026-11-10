"""(10 Nov) Lip-sync check: does the mouth move with the voice? Tested on made-up signals (no real person's video):
a mouth that opens with the speech must count as 'in sync', the same mouth against the sound of other moments as
'mismatch', and missing face / speech as 'not checked'. In the video result it can only ask to verify (55)."""
import numpy as np
import pytest

from app.detectors import lip_sync as L


def _speech(n=200, seed=0):
    rng = np.random.default_rng(seed)
    env, t = np.zeros(n), 0
    while t < n:                                   # syllable-like bursts of sound
        d = rng.integers(2, 6)
        env[t:t + d] = rng.uniform(0.5, 1.0)
        t += d + rng.integers(1, 5)
    energy = -60 + 40 * env + rng.normal(0, 1, n)  # dB
    return env, energy


def _mouth(env, seed=1, delay=0):
    rng = np.random.default_rng(seed)
    opens = np.roll(env, delay) * 2 + rng.normal(0, 0.3, len(env))
    moves = np.abs(np.diff(opens, prepend=opens[0])) + rng.normal(0, 0.05, len(env))
    return moves, opens


def _check(monkeypatch, moves, opens, energy):
    t = np.arange(len(energy)) * L.STEP
    monkeypatch.setattr(L, "mouth_series", lambda p, d: (t, moves, opens))
    monkeypatch.setattr(L, "speech_energy", lambda p, times: energy)
    return L.check("x.mp4", "det.onnx")


def test_mouth_that_follows_the_voice_is_in_sync(monkeypatch):
    env, energy = _speech()
    moves, opens = _mouth(env, delay=1)            # 0.08 s late: normal for phone videos
    r = _check(monkeypatch, moves, opens, energy)
    assert r["status"] == "in_sync" and r["r"] > r["chanceHigh"]


def test_mouth_from_another_moment_is_a_mismatch(monkeypatch):
    env, energy = _speech()
    moves, opens = _mouth(np.roll(env, 70))        # the voice was laid over another part of the video
    r = _check(monkeypatch, moves, opens, energy)
    assert r["status"] == "mismatch"


@pytest.mark.parametrize("case", ["no_face", "no_speech", "too_short", "no_sound"])
def test_not_enough_to_compare_is_not_checked(monkeypatch, case):
    env, energy = _speech()
    moves, opens = _mouth(env)
    if case == "no_face":
        moves[::2] = np.nan
        opens[::2] = np.nan
    elif case == "no_speech":
        energy = -60 + np.random.default_rng(3).normal(0, 0.5, len(energy))
    elif case == "too_short":
        env, energy = _speech(60)
        moves, opens = _mouth(env)
    else:
        energy = np.full(len(energy), np.nan)
    r = _check(monkeypatch, moves, opens, energy)
    assert r["status"] == "not_checked" and r["reason"]


def test_video_result_uses_lip_sync_only_as_a_verify_hint(monkeypatch, tmp_path):
    from app.detectors import deepfake
    av = pytest.importorskip("av")
    p = tmp_path / "talk.mp4"
    with av.open(str(p), "w") as c:
        s = c.add_stream("mpeg4", rate=10)
        s.width, s.height, s.pix_fmt = 64, 48, "yuv420p"
        for i in range(5):
            for pk in s.encode(av.VideoFrame.from_ndarray(np.zeros((48, 64, 3), np.uint8), format="rgb24")):
                c.mux(pk)
        for pk in s.encode():
            c.mux(pk)
    monkeypatch.setattr(deepfake, "_video_face_check", lambda fp: (None, "test: no face model"))
    monkeypatch.setattr(deepfake, "_lip_sync_check", lambda fp: {"status": "mismatch", "r": 0.05, "chance": 0.12,
                                                                  "chanceHigh": 0.2, "lagSeconds": 0.0})
    r = deepfake.analyze_media(str(p), "talk.mp4", "Video Analysis")
    assert r["riskScore"] == 55 and r["lipSync"]["status"] == "mismatch"
    assert any(i["label"].startswith("Lip-sync: the mouth does not follow") and i["triggered"] for i in r["indicators"])
    monkeypatch.setattr(deepfake, "_lip_sync_check", lambda fp: {"status": "in_sync", "r": 0.6, "chance": 0.12,
                                                                  "chanceHigh": 0.2, "lagSeconds": 0.0})
    r = deepfake.analyze_media(str(p), "talk.mp4", "Video Analysis")
    assert r["riskScore"] == 0 and not [i for i in r["indicators"] if i["triggered"]]
