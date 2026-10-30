"""Upgrade #12 (30 Oct): the voice / image / video models are loaded in the background at startup, so the first voice
scan in a demo is not slow - but only when enough memory is free, and a missing or broken model never breaks startup."""
from app.services import analysis_service as A


def test_free_ram_is_read():
    free = A.free_ram_gb()
    assert free is None or free > 0


def test_skipped_when_memory_is_short():
    out = A.warm_up_media(min_free_gb=1_000_000)
    assert list(out) == ["skipped"] and "load on first scan" in out["skipped"]


def test_loads_what_is_installed_and_never_raises(monkeypatch):
    out = A.warm_up_media(min_free_gb=0)
    assert set(out) == {"voice: AI-voice model", "voice: voiceprint", "voice: speech-to-text", "image models",
                        "video model"}
    for v in out.values():                       # milliseconds, or a short note - never an exception
        assert isinstance(v, (int, str))


def test_a_broken_model_is_reported_not_raised(monkeypatch):
    from app.detectors import voice

    def boom():
        raise RuntimeError("broken file")
    monkeypatch.setattr(voice, "ai_model", boom)
    out = A.warm_up_media(min_free_gb=0)
    assert out["voice: AI-voice model"] == "not loaded: RuntimeError"


def test_first_voice_scan_uses_the_loaded_model(monkeypatch):
    from app.detectors import voice
    A.warm_up_media(min_free_gb=0)
    sess_before = voice.ai_model()[0]
    if sess_before is None:
        return                                    # model not installed here: nothing to compare
    assert voice.ai_model()[0] is sess_before     # the scan reuses the session the warm-up made


def test_onnx_runtime_telemetry_is_switched_off():
    import os

    import app
    assert os.environ.get("ORT_DISABLE_TELEMETRY") == "1"
    env = {"ORT_DISABLE_TELEMETRY": "0"}                 # a value the user set on purpose is kept
    app._no_onnx_telemetry(env)
    assert env["ORT_DISABLE_TELEMETRY"] == "0"
    env = {}
    app._no_onnx_telemetry(env)
    assert env == {"ORT_DISABLE_TELEMETRY": "1"}
