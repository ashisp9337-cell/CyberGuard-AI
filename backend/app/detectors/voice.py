"""Voice & audio analysis (deepfake module): is this an AI-generated / cloned voice, is it a scam call, and is it
really the person it claims to be?

  1. AI-voice model   voice_ai.onnx + voice_ai.json (trained in docs/colab/CyberGuard_Voice_Colab.ipynb): XLS-R speech
                      features (frozen) + logistic regression over 4-second clips; the recording's score is the average
                      of its clips. Alert / verify levels = scores only 1% / 5% of real validation recordings reach.
  2. Speech content   faster-whisper (offline, models/whisper-small) turns the speech into English text (it also
                      translates Hindi and many other languages); the existing scam-SMS and impersonation models judge
                      it - a real voice reading a scam script is still a scam call.
  3. Voice match      (only when a genuine recording of the person is uploaded too) voiceprint.onnx (ECAPA): if the two
                      voices do not match, that is a strong warning. A match never proves the voice is real - a good
                      clone is made to match.
  4. File facts       format / codec / sample rate, and metadata naming an AI voice tool (e.g. ElevenLabs).
The audio is only decoded (PyAV); nothing is played or run. The verdict never says "proven real".
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid

import numpy as np

from app.detectors.base import build_result

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(HERE, "..", "ml", "models")
AI_ONNX, AI_JSON = os.path.join(MODELS, "voice_ai.onnx"), os.path.join(MODELS, "voice_ai.json")
VP_ONNX, VP_JSON = os.path.join(MODELS, "voiceprint.onnx"), os.path.join(MODELS, "voiceprint.json")
WHISPER_DIR = os.path.join(MODELS, "whisper-small")
TRANSCRIBE_SECONDS = 60
MATCH_SECONDS = 30
MIN_MATCH_SPEECH_S = 2.0
AI_TOOL_TAG = re.compile(r"eleven ?labs|play\.?ht|resemble\.?ai|murf\.?ai|speechify|descript|voicemod|uberduck|fakeyou|"
                         r"\btortoise\b|\bxtts\b|coqui|\bbark\b|\brvc\b|so-?vits|vall-?e|openvoice|fish ?audio|cartesia|"
                         r"\bsuno\b|text.?to.?speech|\btts\b", re.I)

_CACHE: dict = {}


def _stamp(path: str):
    st = os.stat(path)
    return st.st_mtime_ns, st.st_size


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _load_pair(onnx_path: str, json_path: str, key: str):
    """(onnx session, metadata) or (None, reason). The ONNX file must be the one its JSON was made with."""
    try:
        stamp = (_stamp(onnx_path), _stamp(json_path))
    except OSError:
        return None, "the model files are not installed (train them with docs/colab/CyberGuard_Voice_Colab.ipynb)"
    cached = _CACHE.get(key)
    if cached and cached[0] == stamp:
        return cached[1], cached[2]
    try:
        with open(json_path, encoding="utf-8") as f:
            meta = json.load(f)
        if meta.get("onnx_sha256") and meta["onnx_sha256"] != _sha256(onnx_path):
            out = (None, f"{os.path.basename(onnx_path)} does not belong to {os.path.basename(json_path)} - "
                         "copy both files from the same Colab run")
        else:
            import onnxruntime as ort
            out = (ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"]), meta)
    except Exception as exc:   # noqa: BLE001 - a broken model file never breaks a scan
        out = (None, f"the model could not be loaded ({type(exc).__name__})")
    _CACHE[key] = (stamp, out[0], out[1])
    return out


def ai_model():
    return _load_pair(AI_ONNX, AI_JSON, "ai")


def voiceprint_model():
    return _load_pair(VP_ONNX, VP_JSON, "vp")


# ---- 1. AI voice -------------------------------------------------------------------------------------------------
def ai_voice_score(clips: list[np.ndarray]) -> dict | None:
    sess, meta = ai_model()
    if sess is None or not clips:
        return None
    feats = np.concatenate([sess.run(None, {"wav": np.stack(clips[i:i + 4]).astype(np.float32)})[0]
                            for i in range(0, len(clips), 4)])
    z = (feats - np.asarray(meta["scaler_mean"])) / np.asarray(meta["scaler_scale"])
    p = 1 / (1 + np.exp(-(z @ np.asarray(meta["coef"]) + meta["intercept"])))
    return {"score": float(p.mean()), "clipScores": [round(float(v), 4) for v in p], "levels": meta["levels"],
            "results": meta.get("results", {})}


def _model_points(p: float, alert: float, verify: float) -> int:
    """Model score on the 0-100 scale: alert level -> 71-100, verify level -> 51-70, below verify -> 0-50."""
    if p >= alert:
        return min(100, 71 + round(29 * (p - alert) / max(1 - alert, 1e-6)))
    if p >= verify:
        return min(70, 51 + round(19 * (p - verify) / max(alert - verify, 1e-6)))
    return max(0, round(50 * p / max(verify, 1e-6)))


# ---- 2. speech content -------------------------------------------------------------------------------------------
def whisper_available() -> bool:
    return os.path.isfile(os.path.join(WHISPER_DIR, "model.bin"))


def transcribe(x: np.ndarray) -> dict | None:
    """English text of the first minute of speech (translated when spoken in another language), or None."""
    if not whisper_available():
        return None
    try:
        from faster_whisper import WhisperModel
        if "whisper" not in _CACHE:
            _CACHE["whisper"] = WhisperModel(WHISPER_DIR, device="cpu", compute_type="int8")
        segs, info = _CACHE["whisper"].transcribe(x[: 16_000 * TRANSCRIBE_SECONDS].astype(np.float32), task="translate",
                                                  beam_size=1, vad_filter=True, condition_on_previous_text=False)
        text = " ".join(s.text.strip() for s in segs).strip()[:3000]
        return {"text": text, "language": info.language, "languageProbability": round(float(info.language_probability), 3)}
    except Exception as exc:   # noqa: BLE001
        return {"text": "", "language": None, "error": type(exc).__name__}


def content_check(text: str) -> dict | None:
    """The existing scam-message and impersonation detectors on the spoken words; the strongest verdict counts."""
    if not text or len(text) < 15:
        return None
    results = []
    try:
        from app.detectors import phishing
        results.append(("scam message detector",
                        phishing.analyze_text(text, subtopic_title="Voice call", subtopic_id="sms-analysis",
                                              scan_links=False)))
    except Exception:          # noqa: BLE001
        pass
    try:
        from app.services.analysis_service import _impersonation_category_unknown
        results.append(("impersonation detectors", _impersonation_category_unknown(text, {}, "Voice call")))
    except Exception:          # noqa: BLE001
        pass
    if not results:
        return None
    name, best = max(results, key=lambda r: r[1].get("riskScore", 0))
    top = [i["label"] for i in sorted((i for i in best.get("indicators", []) if i.get("triggered")),
                                      key=lambda i: -i.get("weight", 0))][:3]
    return {"riskScore": int(best.get("riskScore", 0)), "detector": name, "signs": top}


# ---- 3. voice match ----------------------------------------------------------------------------------------------
def voiceprint(x: np.ndarray) -> np.ndarray | None:
    sess, meta = voiceprint_model()
    if sess is None:
        return None
    e = sess.run(None, {"wav": x[None, : 16_000 * MATCH_SECONDS].astype(np.float32)})[0][0]
    return e / (np.linalg.norm(e) + 1e-9)


def voice_match(x: np.ndarray, ref_path: str) -> dict:
    from app.detectors import voice_audio as V
    sess, meta = voiceprint_model()
    if sess is None:
        return {"done": False, "reason": meta}
    try:
        ref = V.speech(ref_path)
    except ValueError as exc:
        return {"done": False, "reason": f"the genuine recording could not be read ({exc})"}
    if min(x.size, ref.size) < V.SR * MIN_MATCH_SPEECH_S:
        return {"done": False, "reason": "one of the recordings has less than 2 seconds of speech"}
    sim = float(voiceprint(x) @ voiceprint(ref))
    level = float(meta["mismatch_level"])
    return {"done": True, "similarity": round(sim, 3), "mismatchLevel": round(level, 3), "match": sim >= level,
            "results": meta.get("results", {})}


# ---- whole recording -----------------------------------------------------------------------------------------------
def _ind(triggered, label, desc, severity, weight, mitre=None):
    return {"label": label, "description": desc, "severity": severity, "weight": weight, "triggered": bool(triggered),
            "mitre": mitre, "id": f"IND_{uuid.uuid4().hex[:12]}"}


def analyze_voice(file_path: str, file_name: str = "recording", subtopic_title: str = "Voice & Audio Analysis",
                  reference_path: str | None = None) -> dict:
    from app.detectors import voice_audio as V
    try:
        facts = V.file_facts(file_path)
        x = V.speech(file_path)
    except (ValueError, ImportError) as exc:
        return build_result(indicators=[], base_score=0, confidence=0, threat_type=subtopic_title,
                            engine_name="CYBERGUARD Voice Engine",
                            explanation=f"{file_name} could not be read as audio ({exc}). Upload a voice note or "
                                        "recording (.ogg / .opus / .m4a / .mp3 / .wav / .aac / .flac).")
    indicators, floors, parts = [], [], []
    speech_s = round(x.size / V.SR, 1)
    clips = V.clips(x)
    va = {"file": {k: facts.get(k) for k in ("container", "codec", "sampleRate", "channels", "seconds")},
          "speechSeconds": speech_s, "clipsScored": len(clips)}

    # 4. metadata naming an AI voice tool
    tag_hits = sorted({m.group(0) for v in (facts.get("tags") or {}).values() for m in AI_TOOL_TAG.finditer(str(v))})
    if tag_hits:
        indicators.append(_ind(True, "File metadata names an AI voice tool",
                               f"The file's own metadata mentions: {', '.join(tag_hits)}. Audio exported from AI voice "
                               "tools often carries their name.", "critical", 40, ["T1656"]))
        floors.append(80)
        parts.append(f"its metadata names an AI voice tool ({', '.join(tag_hits)})")

    # 1. AI voice model
    if not clips:
        parts.append("there is less than 1 second of speech, so the voice could not be judged")
        va["aiVoice"] = None
    else:
        ai = ai_voice_score(clips)
        va["aiVoice"] = ai and {k: ai[k] for k in ("score", "clipScores", "levels")}
        if ai is None:
            _, why = ai_model()
            parts.append(f"the AI-voice model is not available ({why})")
            va["aiVoiceUnavailable"] = why
        else:
            lv = ai["levels"]
            pts = _model_points(ai["score"], lv["alert"], lv["verify"])
            sev = "critical" if pts >= 80 else "high" if pts >= 71 else "medium" if pts >= 51 else "low"
            itw = (ai.get("results") or {}).get("In-the-Wild (real-world, outside test)") or {}
            perf = (f" On real-world deepfakes it never saw (In-the-Wild) this model has AUC {itw['AUC']:.2f}, catches "
                    f"{itw.get('fake caught at alert', 0):.0%} at this level and wrongly flags "
                    f"{itw.get('real flagged at alert (false alarms)', 0):.0%} of real recordings.") if itw.get("AUC") else ""
            indicators.append(_ind(pts >= 51, "AI-generated / cloned voice (voice model)",
                                   f"Voice model score {ai['score']:.2f} over {len(clips)} clip(s) of 4 s "
                                   f"(alert {lv['alert']:.2f}, check-carefully {lv['verify']:.2f}).{perf}",
                                   sev if pts >= 51 else "low", min(pts, 60), ["T1656"]))
            floors.append(pts if pts >= 51 else 0)
            parts.append(f"the voice model scored it {ai['score']:.2f} - "
                         + ("typical of AI-generated or cloned speech" if pts >= 71 else
                            "possibly AI-generated - check carefully" if pts >= 51 else
                            "no sign of an AI voice (this does not prove the voice is genuine)"))

    # 2. speech content
    tr = transcribe(x) if x.size >= V.SR else None
    if tr is None:
        va["speech"] = None
        if not whisper_available():
            parts.append("speech-to-text is not installed, so the words were not checked "
                         "(run: python -m app.ml.training.fetch_whisper)")
    else:
        cc = content_check(tr.get("text", ""))
        va["speech"] = {"language": tr.get("language"), "transcriptExcerpt": tr.get("text", "")[:300],
                        "contentScore": cc and cc["riskScore"], "contentDetector": cc and cc["detector"]}
        if cc and cc["riskScore"] >= 51:
            sev = "critical" if cc["riskScore"] >= 80 else "high" if cc["riskScore"] >= 71 else "medium"
            lang = f" (spoken in {tr['language']}, translated to English)" if tr.get("language") not in (None, "en") else ""
            indicators.append(_ind(True, "Scam script in the spoken words",
                                   f"What is said{lang} looks like a scam to the {cc['detector']} (score "
                                   f"{cc['riskScore']}): {', '.join(cc['signs']) or 'see the transcript'}. A real voice "
                                   f"reading a scam script is still a scam call. Words: \"{tr['text'][:160]}\"",
                                   sev, 35, ["T1566.004"]))
            floors.append(cc["riskScore"])
            parts.append(f"the words sound like a scam script (score {cc['riskScore']})")
        elif cc:
            parts.append("the words did not look like a scam script")

    # 3. voice match with a genuine recording
    if reference_path:
        vm = voice_match(x, reference_path)
        va["voiceMatch"] = {k: vm.get(k) for k in ("done", "similarity", "mismatchLevel", "match", "reason")}
        if not vm["done"]:
            parts.append(f"the voice match could not run ({vm['reason']})")
        elif not vm["match"]:
            indicators.append(_ind(True, "Voice does not match the genuine recording",
                                   f"Voice similarity {vm['similarity']:.2f} is below {vm['mismatchLevel']:.2f}: only 1% "
                                   "of recordings of the same person score that low. This is probably not the person "
                                   "it claims to be.", "high", 35, ["T1656"]))
            floors.append(75)
            parts.append("the voice does NOT match the genuine recording of the person")
        else:
            indicators.append(_ind(False, "Voice matches the genuine recording",
                                   f"Voice similarity {vm['similarity']:.2f} (level {vm['mismatchLevel']:.2f}). A good "
                                   "voice clone is built to match, so this alone does not prove the caller is real.",
                                   "low", 0, None))
            parts.append("the voice matches the genuine recording (a good clone can match too)")

    score = max(floors) if floors else 0
    triggered = [i for i in indicators if i["triggered"]]
    confidence = 45 + min(len(triggered) * 10, 35) + (10 if va.get("aiVoice") else 0)
    head = (f"Read {speech_s:.1f} s of speech ({len(clips)} clip(s) judged). "
            if speech_s else "No speech was found in the recording. ")
    body = "; ".join(parts)
    explanation = head + (body[:1].upper() + body[1:] + "." if body else "")
    if score < 51:
        explanation += " Nothing here proves the recording is genuine - for money or OTP requests, call the person back " \
                       "on a number you already know."
    result = build_result(indicators=indicators, base_score=score, confidence=confidence,
                          engine_name="CYBERGUARD Voice Engine - XLS-R AI-voice model"
                                      + (" + speech-to-text scam check" if va.get("speech") else "")
                                      + (" + voiceprint match" if (va.get("voiceMatch") or {}).get("done") else ""),
                          threat_type=subtopic_title, explanation=explanation)
    result["voiceAnalysis"] = va
    return result
