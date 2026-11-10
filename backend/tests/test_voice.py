"""Voice & Audio Analysis: decoding real formats (WhatsApp .ogg/opus, .m4a, .mp3, .wav), clips, the scoring of the
AI-voice model (with a stand-in model session - the real one is trained in Colab), the speech scam check, the voice
match, file metadata, honest messages when a model is missing, and uploads through the API (files deleted after).
No trained voice model is needed."""
import io
import os

import numpy as np
import pytest

av = pytest.importorskip("av")

from app.detectors import voice, voice_audio as V        # noqa: E402

SR = V.SR


def tone(seconds=6.0, f0=150.0, noise=0.03, seed=0):
    t = np.arange(int(SR * seconds)) / SR
    r = np.random.default_rng(seed)
    s = sum(np.sin(2 * np.pi * f0 * k * t) / k for k in range(1, 8)) * (0.5 + 0.5 * np.sin(2 * np.pi * 3 * t) ** 2)
    s = s + r.normal(0, noise, t.size)
    return (0.3 * s / np.abs(s).max()).astype(np.float32)


def write(path, x, fmt="ogg", enc="libopus", rate=48_000, tags=None):
    out = av.open(str(path), "w", format=fmt)
    st = out.add_stream(enc, rate=rate)
    st.layout = "mono"
    if tags:
        out.metadata.update(tags)
    res = av.AudioResampler(format=st.format.name, layout="mono", rate=rate)
    fr = av.AudioFrame.from_ndarray(x.reshape(1, -1), format="flt", layout="mono")
    fr.sample_rate = SR
    for f in res.resample(fr) + res.resample(None):
        for p in st.encode(f):
            out.mux(p)
    for p in st.encode(None):
        out.mux(p)
    out.close()
    return str(path)


@pytest.fixture
def note(tmp_path):
    x = np.concatenate([np.zeros(SR, np.float32), tone(6.0), np.zeros(SR // 2, np.float32)])
    return write(tmp_path / "note.ogg", x)


# ---- audio decoding ----------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name,fmt,enc,rate", [("a.ogg", "ogg", "libopus", 48_000), ("a.opus", "opus", "libopus", 48_000),
                                               ("a.m4a", "mp4", "aac", 44_100), ("a.mp3", "mp3", "libmp3lame", 44_100),
                                               ("a.wav", "wav", "pcm_s16le", 22_050), ("a.flac", "flac", "flac", 16_000)])
def test_every_voice_note_format_decodes_to_trimmed_16k_speech(tmp_path, name, fmt, enc, rate):
    x = np.concatenate([np.zeros(SR, np.float32), tone(5.0), np.zeros(SR, np.float32)])
    p = write(tmp_path / name, x, fmt, enc, rate)
    s = V.speech(p)
    assert abs(s.size / SR - 5.0) < 0.3                    # the silent ends are cut
    cl = V.clips(s)
    assert len(cl) == 2 and all(c.shape == (V.CLIP,) for c in cl)
    assert abs(float(cl[0].mean())) < 1e-3 and abs(float(cl[0].std()) - 1) < 1e-2
    assert V.file_facts(p)["sampleRate"] == rate


def test_clips_short_long_and_garbage():
    assert V.clips(np.ones(SR // 2, np.float32)) == []                       # under 1 s of speech
    assert len(V.clips(tone(2.0))) == 1                                       # 1-4 s: repeated up to 4 s
    assert len(V.clips(np.random.randn(SR * 600).astype(np.float32))) == V.MAX_CLIPS
    with pytest.raises(ValueError):
        V.decode(b"OggS" + os.urandom(300))


def test_codec_round_trips_keep_the_length():
    x = tone(3.0)
    for codec in ("opus", "mp3", "aac"):
        assert V.codec_roundtrip(x, codec, 16_000).shape == x.shape
    assert V.telephone(x).shape == x.shape


# ---- the AI-voice model (stand-in session; same maths as the real one) ------------------------------------------
class FakeSession:
    def __init__(self, value):
        self.value = value

    def run(self, _outputs, feeds):
        n = feeds["wav"].shape[0]
        return [np.full((n, 4), self.value, np.float32)]


def fake_ai(value):
    meta = {"scaler_mean": [0, 0, 0, 0], "scaler_scale": [1, 1, 1, 1], "coef": [1, 1, 1, 1], "intercept": 0.0,
            "levels": {"alert": 0.9, "verify": 0.7},
            "results": {"In-the-Wild (real-world, outside test)": {"AUC": 0.9, "fake caught at alert": 0.5,
                                                                   "real flagged at alert (false alarms)": 0.02}}}
    return lambda: (FakeSession(value), meta)


@pytest.fixture
def no_speech_model(monkeypatch):
    monkeypatch.setattr(voice, "transcribe", lambda x: None)
    monkeypatch.setattr(voice, "whisper_available", lambda: True)


def test_ai_voice_high_score_is_flagged_and_low_score_never_called_real(monkeypatch, note, no_speech_model):
    monkeypatch.setattr(voice, "ai_model", fake_ai(1.0))                        # sigmoid(4) = 0.982 -> above alert
    r = voice.analyze_voice(note, "note.ogg")
    # (11 Nov) the model ALONE is "check carefully" (51-70), never critical: it flags ~1 in 4 real phone recordings
    assert 51 <= r["riskScore"] <= voice.MODEL_ONLY_MAX and r["voiceAnalysis"]["aiVoice"]["score"] > 0.98
    assert r["voiceAnalysis"]["modelOnlyCapped"] is True and "check carefully" in r["explanation"]
    assert any(i["triggered"] and "AI-generated" in i["label"] and i["severity"] == "medium" for i in r["indicators"])
    assert "In-the-Wild" in next(i["description"] for i in r["indicators"] if "AI-generated" in i["label"])
    monkeypatch.setattr(voice, "ai_model", fake_ai(-1.0))                       # sigmoid(-4) = 0.018
    low = voice.analyze_voice(note, "note.ogg")
    assert low["riskScore"] < 51 and "does not prove the voice is genuine" in low["explanation"]
    assert "Nothing here proves the recording is genuine" in low["explanation"]


def test_model_points_scale():
    assert voice._model_points(0.95, 0.9, 0.7) >= 71 and voice._model_points(0.8, 0.9, 0.7) in range(51, 71)
    assert voice._model_points(0.35, 0.9, 0.7) == 25 and voice._model_points(1.0, 0.9, 0.7) == 100


def test_missing_model_is_said_plainly(monkeypatch, note, no_speech_model):
    monkeypatch.setattr(voice, "AI_ONNX", "/nonexistent/voice_ai.onnx")
    r = voice.analyze_voice(note, "note.ogg")
    assert r["riskScore"] == 0 and "AI-voice model is not available" in r["explanation"]
    assert "Colab" in r["voiceAnalysis"]["aiVoiceUnavailable"]


def test_mismatched_model_files_are_refused(monkeypatch, tmp_path):
    onnx, meta = tmp_path / "voice_ai.onnx", tmp_path / "voice_ai.json"
    onnx.write_bytes(b"not the right model")
    meta.write_text('{"onnx_sha256": "0000"}')
    monkeypatch.setattr(voice, "AI_ONNX", str(onnx))
    monkeypatch.setattr(voice, "AI_JSON", str(meta))
    sess, why = voice.ai_model()
    assert sess is None and "does not belong" in why


def test_unreadable_audio_is_reported_not_crashed(tmp_path):
    p = tmp_path / "broken.ogg"
    p.write_bytes(b"OggS" + os.urandom(400))
    r = voice.analyze_voice(str(p), "broken.ogg")
    assert r["riskScore"] == 0 and "could not be read as audio" in r["explanation"]


def test_metadata_naming_an_ai_voice_tool(monkeypatch, tmp_path, no_speech_model):
    monkeypatch.setattr(voice, "ai_model", fake_ai(-1.0))
    p = write(tmp_path / "x.mp3", tone(5.0), "mp3", "libmp3lame", 44_100, tags={"comment": "Generated with ElevenLabs"})
    r = voice.analyze_voice(p, "x.mp3")
    assert r["riskScore"] >= 80 and any(i["label"] == "File metadata names an AI voice tool" for i in r["indicators"])


def test_aigc_label_in_the_file_is_proof_and_label_2_is_a_hint(monkeypatch, tmp_path, no_speech_model):
    """(11 Nov) China's AI-content label (GB 45438-2025), as MiniMax writes it into an mp3 - the real-world clone that
    the voice model alone could not tell from a real phone recording."""
    monkeypatch.setattr(voice, "ai_model", fake_ai(-1.0))                       # the model sees nothing
    tag = '{"Label":"1","ContentProducer":"MiniMax","ProduceID":"0742965299","ReservedCode1":"{\\"SecurityData\\":1}"}'
    p = write(tmp_path / "clone.mp3", tone(5.0), "mp3", "libmp3lame", 32_000, tags={"AIGC": tag})
    r = voice.analyze_voice(p, "clone.mp3")
    assert r["riskScore"] >= 90, r["explanation"]
    ind = next(i for i in r["indicators"] if i["label"].startswith("AI-content label"))
    assert ind["triggered"] and "MiniMax" in ind["description"] and r["voiceAnalysis"]["aigcLabel"]["label"] == "1"
    p2 = write(tmp_path / "maybe.mp3", tone(5.0), "mp3", "libmp3lame", 32_000,
               tags={"AIGC": '{"Label":"2","ContentProducer":"X"}'})
    assert 51 <= voice.analyze_voice(p2, "maybe.mp3")["riskScore"] <= 70


def test_content_credentials_and_more_tool_names_in_audio(monkeypatch, tmp_path, no_speech_model):
    """(11 Nov) C2PA inside the audio file and the names of more voice tools are proof, whatever the model says."""
    monkeypatch.setattr(voice, "ai_model", fake_ai(-1.0))
    c2pa = write(tmp_path / "c.mp3", tone(5.0), "mp3", "libmp3lame", 32_000,
                 tags={"comment": "c2pa jumb DigitalSourceType trainedAlgorithmicMedia"})
    r = voice.analyze_voice(c2pa, "c.mp3")
    assert r["riskScore"] >= 95 and r["voiceAnalysis"]["contentCredentials"] == "ai"
    for tool in ("Exported from HeyGen", "Kokoro voice", "Amazon Polly"):
        p = write(tmp_path / "t.mp3", tone(5.0), "mp3", "libmp3lame", 32_000, tags={"comment": tool})
        assert voice.analyze_voice(p, "t.mp3")["riskScore"] >= 80, tool


def test_audio_metadata_is_shown_as_information_only(monkeypatch, tmp_path, no_speech_model):
    monkeypatch.setattr(voice, "ai_model", fake_ai(-1.0))
    p = write(tmp_path / "rec.m4a", tone(5.0), "mp4", "aac", 48_000, tags={"title": "class notes"})
    r = voice.analyze_voice(p, "rec.m4a")
    meta = next(i for i in r["indicators"] if i["label"] == "File metadata (info only)")
    assert meta["triggered"] is False and "MP4 / M4A" in meta["description"] and "48 kHz" in meta["description"]
    assert "title: class notes" in meta["description"] and r["riskScore"] < 51


def test_model_with_backing_keeps_its_full_score(monkeypatch, tmp_path, no_speech_model):
    monkeypatch.setattr(voice, "ai_model", fake_ai(1.0))
    p = write(tmp_path / "clone.mp3", tone(5.0), "mp3", "libmp3lame", 32_000,
              tags={"AIGC": '{"Label":"1","ContentProducer":"MiniMax"}'})
    r = voice.analyze_voice(p, "clone.mp3")
    assert r["riskScore"] >= 92 and not r["voiceAnalysis"].get("modelOnlyCapped")


def test_a_phone_recording_without_tags_is_not_mistaken_for_a_label(monkeypatch, tmp_path, no_speech_model):
    monkeypatch.setattr(voice, "ai_model", fake_ai(-1.0))
    p = write(tmp_path / "rec.m4a", tone(5.0), "mp4", "aac", 48_000, tags={"title": "Label 1 - lecture notes"})
    r = voice.analyze_voice(p, "rec.m4a")
    assert r["riskScore"] < 51 and "aigcLabel" not in r["voiceAnalysis"]


# ---- speech content: a real voice reading a scam script is still a scam ------------------------------------------
def test_scam_words_raise_the_verdict_even_for_a_real_sounding_voice(monkeypatch, note):
    monkeypatch.setattr(voice, "ai_model", fake_ai(-1.0))
    script = ("This is inspector Sharma from Mumbai cyber crime police. A parcel in your name has drugs and your "
              "Aadhaar is linked to money laundering. You are under digital arrest. Do not disconnect and do not tell "
              "your family. Transfer 50,000 rupees to the RBI verification account now or we will arrest you today.")
    monkeypatch.setattr(voice, "transcribe", lambda x: {"text": script, "language": "hi", "languageProbability": 0.9})
    r = voice.analyze_voice(note, "note.ogg")
    assert r["riskScore"] >= 51, r["explanation"]
    ind = next(i for i in r["indicators"] if i["label"] == "Scam script in the spoken words")
    assert "translated to English" in ind["description"] and r["voiceAnalysis"]["speech"]["language"] == "hi"
    calm = "Hi beta, I reached home safely. Call me after dinner, we will talk about the trip on Sunday."
    monkeypatch.setattr(voice, "transcribe", lambda x: {"text": calm, "language": "en", "languageProbability": 0.9})
    assert voice.analyze_voice(note, "note.ogg")["riskScore"] < 51


def test_without_speech_to_text_installed_it_says_how_to_add_it(monkeypatch, note):
    monkeypatch.setattr(voice, "ai_model", fake_ai(-1.0))
    monkeypatch.setattr(voice, "WHISPER_DIR", "/nonexistent")
    r = voice.analyze_voice(note, "note.ogg")
    assert "fetch_whisper" in r["explanation"] and r["voiceAnalysis"]["speech"] is None


# ---- voice match -------------------------------------------------------------------------------------------------
def fake_vp(monkeypatch, same):
    monkeypatch.setattr(voice, "voiceprint_model", lambda: (object(), {"mismatch_level": 0.4, "results": {}}))
    vecs = iter([np.array([1.0, 0.0]), np.array([1.0, 0.0]) if same else np.array([0.0, 1.0])])
    monkeypatch.setattr(voice, "voiceprint", lambda x: next(vecs))


def test_voice_mismatch_is_a_strong_warning_and_a_match_proves_nothing(monkeypatch, tmp_path, note, no_speech_model):
    monkeypatch.setattr(voice, "ai_model", fake_ai(-1.0))
    ref = write(tmp_path / "genuine.m4a", tone(6.0, f0=210, seed=3), "mp4", "aac", 44_100)
    fake_vp(monkeypatch, same=False)
    r = voice.analyze_voice(note, "note.ogg", reference_path=ref)
    assert r["riskScore"] >= 71 and r["voiceAnalysis"]["voiceMatch"]["match"] is False
    fake_vp(monkeypatch, same=True)
    ok = voice.analyze_voice(note, "note.ogg", reference_path=ref)
    assert ok["riskScore"] < 51 and "a good clone can match too" in ok["explanation"]


def test_voice_match_needs_enough_speech(monkeypatch, tmp_path, note, no_speech_model):
    monkeypatch.setattr(voice, "ai_model", fake_ai(-1.0))
    fake_vp(monkeypatch, same=True)
    short = write(tmp_path / "short.wav", tone(1.2), "wav", "pcm_s16le", 16_000)
    r = voice.analyze_voice(note, "note.ogg", reference_path=short)
    assert r["voiceAnalysis"]["voiceMatch"]["done"] is False and "less than 2 seconds" in r["explanation"]


# ---- through the API ---------------------------------------------------------------------------------------------
def _uploads_left(ext):
    from app.core.config import get_settings
    folder = get_settings().UPLOAD_DIR
    return [n for n in (os.listdir(folder) if os.path.isdir(folder) else []) if n.endswith(ext)]


def test_uploading_a_voice_note_with_a_genuine_recording(auth_client, monkeypatch, tmp_path, no_speech_model):
    monkeypatch.setattr(voice, "ai_model", fake_ai(1.0))
    fake_vp(monkeypatch, same=False)
    data = open(write(tmp_path / "n.ogg", tone(6.0)), "rb").read()
    ref = open(write(tmp_path / "r.ogg", tone(6.0, f0=220, seed=2)), "rb").read()
    r = auth_client.post("/api/analysis/scan", data={"moduleId": "deepfake", "subtopicId": "audio-analysis",
                                                      "subtopicTitle": "Voice & Audio Analysis"},
                         files={"file": ("voice-note.ogg", io.BytesIO(data), "audio/ogg"),
                                "referenceFile": ("dad-genuine.ogg", io.BytesIO(ref), "audio/ogg")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["riskScore"] >= 71 and body["voiceAnalysis"]["aiVoice"]["score"] > 0.9
    assert body["voiceAnalysis"]["voiceMatch"]["match"] is False
    assert _uploads_left(".ogg") == []                    # both recordings deleted from the server


def test_reference_recording_is_refused_outside_voice_analysis(auth_client, tmp_path):
    ref = open(write(tmp_path / "r.ogg", tone(3.0)), "rb").read()
    r = auth_client.post("/api/analysis/scan", data={"moduleId": "phishing", "subtopicId": "sms-analysis",
                                                      "subtopicTitle": "SMS", "textInput": "hello"},
                         files={"referenceFile": ("r.ogg", io.BytesIO(ref), "audio/ogg")})
    assert r.status_code == 400 and _uploads_left(".ogg") == []


def test_voice_note_with_auto_detect(auth_client, monkeypatch, tmp_path, no_speech_model):
    monkeypatch.setattr(voice, "ai_model", fake_ai(-1.0))
    data = open(write(tmp_path / "n.m4a", tone(5.0), "mp4", "aac", 44_100), "rb").read()
    r = auth_client.post("/api/analysis/scan", data={"moduleId": "deepfake", "subtopicId": "auto",
                                                      "subtopicTitle": "Auto-detect"},
                         files={"file": ("call.m4a", io.BytesIO(data), "audio/mp4")})
    assert r.status_code == 200, r.text
    assert r.json()["subtopicId"] == "audio-analysis" and r.json()["riskScore"] < 51
    assert _uploads_left(".m4a") == []


def test_stored_voice_summary_is_small_and_has_no_audio():
    from app.services import scan_store
    va = {"speechSeconds": 12.0, "clipsScored": 3, "aiVoice": {"score": 0.97, "clipScores": [0.9] * 3,
          "levels": {"alert": 0.9, "verify": 0.7}}, "speech": {"language": "hi", "transcriptExcerpt": "x" * 900,
          "contentScore": 85}, "voiceMatch": {"done": True, "similarity": 0.1, "mismatchLevel": 0.4, "match": False}}
    out = scan_store.detail_fields({"voiceAnalysis": va})["voiceAnalysis"]
    assert len(out["speech"]["transcriptExcerpt"]) == 200 and out["aiVoice"] == {"score": 0.97, "alert": 0.9, "verify": 0.7,
                                                                                   "clipScores": [0.9, 0.9, 0.9]}
    big = scan_store.detail_fields({"voiceAnalysis": va | {"aiVoice": {"score": 0.5, "clipScores": [0.5] * 99,
                                                                       "levels": {}}}})["voiceAnalysis"]
    assert len(big["aiVoice"]["clipScores"]) == 15                    # (11 Nov) the timeline is kept small
    assert out["voiceMatch"]["match"] is False
