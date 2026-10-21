"""Video provenance (Deepfake -> Video Analysis, step A, 20 Oct): proof from the file's own metadata only."""
import struct

from app.detectors import video_provenance as VP
from app.detectors.deepfake import analyze_media


def box(btype: bytes, body: bytes) -> bytes:
    return struct.pack(">I", 8 + len(body)) + btype + body


def mp4(tmp_path, name, *, udta=b"", top=b"", mdat=b"\x00" * 2000, stbl=b""):
    ftyp = box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2mp41")
    trak = box(b"trak", box(b"mdia", box(b"minf", box(b"stbl", stbl or b"\x00" * 64))))
    moov = box(b"moov", box(b"mvhd", b"\x00" * 100) + trak + (box(b"udta", udta) if udta else b""))
    p = tmp_path / name
    p.write_bytes(ftyp + moov + box(b"mdat", mdat) + top)
    return str(p)


def tag(key: bytes, text: str) -> bytes:                      # QuickTime-style text tag: (c)too / (c)cmt
    t = text.encode()
    return box(key, struct.pack(">HH", len(t), 0) + t)


def test_a_normal_phone_or_ffmpeg_video_has_no_proof(tmp_path):
    r = VP.provenance(mp4(tmp_path, "normal.mp4", udta=tag(b"\xa9too", "Lavf61.7.100")))
    assert r["proof"] is False and r["findings"] == []


def test_an_ai_generator_named_in_the_metadata_is_proof(tmp_path):
    r = VP.provenance(mp4(tmp_path, "sora.mp4", udta=tag(b"\xa9cmt", "Generated with OpenAI Sora")))
    assert r["proof"] and r["kind"] == "ai"
    assert any("Sora" in f["detail"] for f in r["findings"])


def test_c2pa_content_credentials_declaring_ai_are_proof(tmp_path):
    manifest = b"\x00\x00jumb\x00c2pa\x00 c2pa.actions digitalSourceType http://cv.iptc.org/newscodes/" \
               b"digitalsourcetype/trainedAlgorithmicMedia \x00"
    c2pa_uuid = bytes.fromhex("d8fec3d61b0e483c92975828877ec481")
    r = VP.provenance(mp4(tmp_path, "c2pa.mp4", top=box(b"uuid", c2pa_uuid + manifest)))
    assert r["proof"] and r["hasContentCredentials"]
    assert r["findings"][0]["label"] == "Content Credentials: video made with AI"


def test_c2pa_from_a_camera_is_not_proof(tmp_path):
    r = VP.provenance(mp4(tmp_path, "camera.mp4", top=box(b"uuid", b"\x00" * 16 + b"jumb c2pa claim Samsung camera")))
    assert r["proof"] is False and r["hasContentCredentials"]


def test_a_face_swap_tool_name_is_proof_of_manipulation(tmp_path):
    r = VP.provenance(mp4(tmp_path, "swap.mp4", udta=tag(b"\xa9too", "FaceFusion 3.1")))
    assert r["proof"] and r["kind"] == "faceswap"


def test_words_inside_the_picture_data_or_sample_tables_are_never_read(tmp_path):
    r = VP.provenance(mp4(tmp_path, "trap.mp4", mdat=b"xx made with sora by runway kling xx" * 50,
                          stbl=b"openai sora facefusion" * 4))
    assert r["proof"] is False


def test_damaged_or_random_files_do_not_crash(tmp_path):
    p = tmp_path / "junk.mp4"
    p.write_bytes(b"\x00\x00\x00\x10ftypisom" + b"\xff" * 100)
    assert VP.provenance(str(p))["proof"] is False
    q = tmp_path / "clip.webm"
    q.write_bytes(b"\x1a\x45\xdf\xa3" + b"\x00" * 100 + b"ENCODER Lavf + made with Runway Gen-4 " + b"\x00" * 100)
    assert VP.provenance(str(q))["proof"] is True


def test_video_analysis_uses_proof_and_otherwise_gives_no_verdict(tmp_path):
    ai = analyze_media(mp4(tmp_path, "a.mp4", udta=tag(b"\xa9cmt", "Created with Google Veo 3")), "a.mp4", "Video Analysis")
    assert ai["riskScore"] >= 90 and "made with AI" in ai["explanation"]
    normal = analyze_media(mp4(tmp_path, "b.mp4", udta=tag(b"\xa9too", "Lavf61")), "b.mp4", "Video Analysis")
    assert normal["riskScore"] == 0 and "NOT 'not a deepfake'" in normal["explanation"]


def test_ordinary_words_and_names_in_a_title_are_not_proof(tmp_path):
    for title in ("sora beach trip", "Runway show Paris", "Kling family dinner", "Roop birthday", "my dream machine",
                  "minimax algorithm lecture", "d-id card scan"):
        r = VP.provenance(mp4(tmp_path, "t.mp4", udta=tag(b"\xa9nam", title)))
        assert r["proof"] is False, title


def test_the_real_generator_names_still_count(tmp_path):
    for text, name in (("Made with Sora", "OpenAI Sora"), ("Runway Gen-4 Turbo", "Runway"), ("Kling AI 2.1", "Kling"),
                       ("roop-unleashed 4.0", "roop"), ("Luma Dream Machine", "Luma")):
        r = VP.provenance(mp4(tmp_path, "g.mp4", udta=tag(b"\xa9too", text)))
        assert r["proof"] and any(name in f["detail"] for f in r["findings"]), text
