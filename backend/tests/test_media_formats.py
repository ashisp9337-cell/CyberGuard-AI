"""Upgrade #5 (30 Oct): more photo and recording formats on the Deepfake module - WebP / GIF / BMP / iPhone HEIC photos
and phone call recordings (.amr, sound-only .3gp). All test files are made here (random pixels, a tone, random AMR
frames); nothing real or personal is used."""
import io

import numpy as np
import pytest
from PIL import Image

from app.detectors import deepfake
from app.services.subtopic_router import file_kind

av = pytest.importorskip("av")
RNG = np.random.default_rng(0)


def _picture():
    return Image.fromarray((RNG.random((120, 160, 3)) * 255).astype("uint8"))


def _amr(seconds=3):
    """AMR-NB file: '#!AMR' + 20 ms frames of mode 7 (12.2 kbit/s: 1 header byte + 31 bytes)."""
    return b"#!AMR\n" + b"".join(bytes([0x3C]) + bytes(RNG.integers(0, 256, 31, dtype=np.uint8))
                                 for _ in range(seconds * 50))


def _3gp(path, video):
    sr = 16000
    tone = (0.3 * np.sin(2 * np.pi * 220 * np.arange(sr * 3) / sr)).astype(np.float32)
    c = av.open(str(path), "w", format="3gp")
    vs = None
    if video:
        vs = c.add_stream("mpeg4", rate=10)
        vs.width, vs.height, vs.pix_fmt = 176, 144, "yuv420p"
    a = c.add_stream("aac", rate=sr)
    a.layout = "mono"
    if vs:
        for _ in range(10):
            fr = av.VideoFrame.from_ndarray((RNG.random((144, 176, 3)) * 255).astype("uint8"), format="rgb24")
            for p in vs.encode(fr):
                c.mux(p)
        for p in vs.encode(None):
            c.mux(p)
    fr = av.AudioFrame.from_ndarray(tone.reshape(1, -1), format="flt", layout="mono")
    fr.sample_rate = sr
    for p in a.encode(fr):
        c.mux(p)
    for p in a.encode(None):
        c.mux(p)
    c.close()


# ---- recordings ----------------------------------------------------------------------------------------------------
def test_amr_call_recording_is_audio_and_decodes(tmp_path):
    from app.detectors import voice_audio
    p = tmp_path / "call.amr"
    p.write_bytes(_amr())
    assert file_kind(str(p), "call.amr") == "audio"
    x, sr = voice_audio.decode(str(p))
    assert x.size / sr == pytest.approx(3.0, abs=0.1)


def test_3gp_with_sound_only_is_audio_and_with_picture_is_video(tmp_path):
    call, clip = tmp_path / "call.3gp", tmp_path / "clip.3gp"
    _3gp(call, video=False)
    _3gp(clip, video=True)
    assert file_kind(str(call), "call.3gp") == "audio"
    assert file_kind(str(clip), "clip.3gp") == "video"


def test_router_sends_recordings_to_voice_analysis(tmp_path):
    from app.services import subtopic_router
    p = tmp_path / "rec.amr"
    p.write_bytes(_amr())
    c = subtopic_router.classify(module_id="deepfake", text_input=None, url_input=None, file_path=str(p),
                                 file_name="Call_2026-10-30.amr", extra_field_values=None)
    assert c.subtopic_id == "audio-analysis"


# ---- pictures ------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("fmt,ext", [("WEBP", ".webp"), ("BMP", ".bmp"), ("GIF", ".gif")])
def test_pictures_are_images_and_temporary_copies_are_removed(tmp_path, fmt, ext):
    p = tmp_path / f"photo{ext}"
    _picture().save(p, fmt)
    assert file_kind(str(p), p.name) == "image"
    before = set(tmp_path.iterdir())
    r = deepfake.analyze_media(str(p), p.name, "Image Analysis")
    # any real verdict is fine here (random pixels are not a photo, so the AI-image model may call them suspicious);
    # the point is that the picture was read and judged
    assert r["classification"] in ("safe", "low_risk", "suspicious", "high_risk", "critical", "unverified")
    assert set(tmp_path.iterdir()) == before                          # the PNG copy for the models is deleted
    if fmt == "GIF":
        assert "GIF" in r["explanation"]


def test_animated_gif_first_frame_is_checked(tmp_path):
    p = tmp_path / "anim.gif"
    a, b = _picture(), _picture()
    a.save(p, save_all=True, append_images=[b], duration=100, loop=0)
    path, note, temporary = deepfake._model_copy(str(p))
    try:
        assert temporary and path.endswith(".png") and "first frame" in note
        assert Image.open(path).size == (160, 120)
    finally:
        import os
        os.remove(path)


def test_still_webp_and_jpeg_are_read_as_they_are(tmp_path):
    for fmt, ext in (("WEBP", ".webp"), ("JPEG", ".jpg")):
        p = tmp_path / f"x{ext}"
        _picture().save(p, fmt)
        assert deepfake._model_copy(str(p)) == (str(p), "", False)


def test_heic_photo(tmp_path):
    pillow_heif = pytest.importorskip("pillow_heif")
    pillow_heif.register_heif_opener()
    p = tmp_path / "IMG_0001.heic"
    _picture().save(p, "HEIF")
    assert file_kind(str(p), p.name) == "image"                       # not mistaken for an MP4 video
    path, note, temporary = deepfake._model_copy(str(p))
    try:
        assert temporary and "HEIC" in note and Image.open(path).format == "PNG"
    finally:
        import os
        os.remove(path)


def test_heic_without_its_reader_says_so_and_never_real(tmp_path, monkeypatch):
    p = tmp_path / "IMG_0002.heic"
    p.write_bytes(b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic" + b"\x00" * 200)   # unreadable HEIC
    monkeypatch.setitem(deepfake._HEIF, "tried", True)
    monkeypatch.setitem(deepfake._HEIF, "ok", False)
    assert file_kind(str(p), p.name) == "image"
    r = deepfake.analyze_media(str(p), p.name, "Image Analysis")
    assert r["classification"] == "unverified" and "pillow-heif" in r["explanation"]
    assert not any("QR" in x for x in r["recommendations"])


# ---- uploads through the API -----------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["photo.webp", "anim.gif", "scan.bmp", "call.amr", "rec.3gp"])
def test_deepfake_accepts_the_new_formats(auth_client, tmp_path, name):
    if name.endswith(".amr"):
        data = _amr()
    elif name.endswith(".3gp"):
        _3gp(tmp_path / name, video=False)
        data = (tmp_path / name).read_bytes()
    else:
        buf = io.BytesIO()
        _picture().save(buf, {"webp": "WEBP", "gif": "GIF", "bmp": "BMP"}[name.rsplit(".", 1)[1]])
        data = buf.getvalue()
    sub = "audio-analysis" if name.endswith((".amr", ".3gp")) else "image-analysis"
    r = auth_client.post("/api/analysis/scan", data={"moduleId": "deepfake", "subtopicId": sub, "subtopicTitle": sub},
                         files={"file": (name, io.BytesIO(data), "application/octet-stream")})
    assert r.status_code == 200, r.text


def test_other_modules_still_refuse_these_formats(auth_client):
    r = auth_client.post("/api/analysis/scan", data={"moduleId": "phishing", "subtopicId": "sms-analysis",
                                                      "subtopicTitle": "SMS"},
                         files={"file": ("call.amr", io.BytesIO(_amr()), "application/octet-stream")})
    assert r.status_code == 400
