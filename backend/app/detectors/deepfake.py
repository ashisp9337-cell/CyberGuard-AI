"""
Deepfake / synthetic-media detector.

IMAGES: three independent checks, the strongest decides (see _image_model_result):
  1. provenance  - C2PA / IPTC / generator settings written into the file       (app/detectors/ai_image.py)
  2. AI-image    - CLIP-based model: was the whole picture made by an AI generator? (app/detectors/ai_image.py)
  3. face-swap   - EfficientNet-B0 on every face found by YuNet                  (app/detectors/deepfake_image.py)
Both models are trained on Google Colab (docs/colab/). If no check can run, the old static metadata check is
used and the result clearly says why -- never a made-up verdict.

VIDEOS: no trained video model yet (next subtopic) -> reported as "model unavailable", not as "real".
"""
import uuid
from app.detectors.base import build_result

def _ind(label, description, severity, triggered):
    return {"label": label, "description": description, "severity": severity, "weight": 0,
            "triggered": bool(triggered), "id": f"IND_{uuid.uuid4().hex[:12]}"}


def _pct(x):
    """0.79 -> '79%', 0.99999769 -> '99.9998%' (levels this close to 100% must not be rounded to 100%)."""
    if x >= 0.995:
        return f"{x * 100:.4f}".rstrip("0").rstrip(".") + "%"
    return f"{x * 100:.0f}%"


def _perf(meta, what):
    test = (meta.get("results") or {}).get("test") or {}
    if not test:
        return ""
    return (f" On {test.get('n', 'held-out')} test images it never saw it caught {test.get('caught_at_alert', 0) * 100:.0f}% "
            f"of {what} at {test.get('false_alarms_at_alert', 0) * 100:.1f}% false alarms.")


def _face_check(file_path):
    from app.detectors import deepfake_image as DI
    try:
        return DI.assess_image(file_path), None
    except DI.ModelUnavailable as e:
        return None, f"face-swap model: {e}"
    except Exception as e:                                   # unreadable image etc.: never crash
        return None, f"face-swap model could not read the image ({e.__class__.__name__})"


def _ai_check(file_path):
    from app.detectors import ai_image as AI
    try:
        return AI.assess(file_path), None
    except AI.ModelUnavailable as e:
        return None, f"AI-image model: {e}"
    except Exception as e:
        return None, f"AI-image model could not read the image ({e.__class__.__name__})"


def _image_model_result(file_path: str, subtopic_title: str):
    """Every image check -> one result where the strongest check decides, or (None, reason) if none can run.

    1. provenance  - the file itself declares AI generation (C2PA / IPTC / generator settings)   -> proof
    2. AI-image    - CLIP-based model: was the WHOLE picture made by an AI generator?
    3. face-swap   - EfficientNet model on each face: was a real person's face swapped / manipulated?
    """
    from app.detectors import ai_image as AI
    from app.detectors import deepfake_image as DI
    face, why_face = _face_check(file_path)
    ai, why_ai = _ai_check(file_path)
    prov = AI.provenance(file_path)
    if face is None and ai is None and not prov["proof"]:
        return None, f"{why_face}; {why_ai}"

    candidates, indicators, engines = [], [], []

    # 1. provenance -------------------------------------------------------------------------------------
    for f in prov["findings"]:
        indicators.append(_ind(f["label"], f["detail"], "critical" if f["proof"] else "low", True))
    if prov["proof"]:
        first = next(f for f in prov["findings"] if f["proof"])
        candidates.append((95, 99, f"The file itself declares that it was made with AI: {first['detail']}"))
    engines.append("Provenance check (C2PA / IPTC / generator metadata)")

    # 2. AI-generated (whole picture) -------------------------------------------------------------------
    if ai:
        p, level, meta = ai["probability"], ai["level"], ai["meta"]
        indicators.append(_ind(
            {"high": "AI-image model: looks AI-generated", "medium": "AI-image model: possibly AI-generated - verify",
             "low": "AI-image model: looks like a real photo"}[level],
            f"The AI-image model ({meta.get('architecture', 'CLIP ViT-L/14 + linear layer')}, trained on "
            f"{meta.get('dataset', 'real photos vs images from many AI generators')}) rates the picture at "
            f"{_pct(p)} likely AI-generated (it warns from {_pct(ai['thrVerify'])}, alert from {_pct(ai['thrAlert'])})."
            + (f" {len(ai['views'])} parts of the picture were checked; the most AI-looking one decides." if len(ai["views"]) > 1 else "")
            + _perf(meta, "AI-generated images"),
            "critical" if level == "high" and p >= 0.95 else {"high": "high", "medium": "medium"}.get(level, "low"),
            level != "low"))
        candidates.append((AI.score_from(ai), 60 + abs(p - 0.5) * 60, {
            "high": f"AI-image model: {_pct(p)} likely AI-generated.",
            "medium": f"AI-image model: {_pct(p)} - possibly AI-generated, verify the source.",
            "low": f"AI-image model: looks like a real photo (raw score {_pct(p)}, below its warning level)."}[level]))
        engines.append(f"AI-image model ({meta.get('architecture', 'CLIP')}, Colab-trained, ONNX)")
    else:
        indicators.append(_ind("AI-image model not installed", f"Not used: {why_ai}.", "low", False))

    # 3. face swap / manipulation -------------------------------------------------------------------------
    if face:
        p, level, meta = face["probability"], face["level"], face["meta"]
        where = ("No face was found, so the whole picture was judged (less reliable: the model was trained on faces)."
                 if face["wholeImage"] else f"{len(face['faces'])} face(s) found; the most suspicious face decides.")
        indicators.append(_ind(
            {"high": "Face-swap model: face looks manipulated", "medium": "Face-swap model: possible manipulation - verify",
             "low": "Face-swap model: no face manipulation found"}[level],
            f"The face-swap model ({meta.get('architecture', 'EfficientNet-B0')}, trained on "
            f"{meta.get('dataset', 'OpenForensics face images')}) gives a raw score of {_pct(p)} (it warns from "
            f"{_pct(face['thrVerify'])}, alert from {_pct(face['thrAlert'])} - this model is very confident, so "
            f"normal faces often get high raw scores). {where}" + _perf(meta, "face manipulations"),
            "critical" if level == "high" and p >= 0.95 else {"high": "high", "medium": "medium"}.get(level, "low"),
            level != "low"))
        for i, f in enumerate(face["faces"][:5]):
            if f["box"] is not None:
                fp = f["probability"]
                state = ("manipulation likely" if fp >= face["thrAlert"] else "possible manipulation"
                         if fp >= face["thrVerify"] else "looks normal")
                indicators.append(_ind(f"Face {i + 1}: {state}",
                                       f"Face at x={f['box'][0]}, y={f['box'][1]}, size {f['box'][2]}x{f['box'][3]} px; "
                                       f"raw score {_pct(fp)} (warns from {_pct(face['thrVerify'])}).",
                                       "high" if f["probability"] >= face["thrAlert"] else "low",
                                       f["probability"] >= face["thrVerify"]))
        # without a face the face model is guessing; when the AI-image model ran, it does not decide
        if not (face["wholeImage"] and ai):
            candidates.append((DI.score_from(face), (55 if face["wholeImage"] else 65) + abs(p - 0.5) * 60, {
                "high": f"Face-swap model: {_pct(p)} likely manipulated. {where}",
                "medium": f"Face-swap model: possible face manipulation ({_pct(p)}) - verify the source. {where}",
                "low": f"Face-swap model: no face manipulation found (raw score {_pct(p)}, below its warning level "
                       f"of {_pct(face['thrVerify'])}). {where}"}[level]))
        engines.append(f"Face-swap model ({meta.get('architecture', 'EfficientNet-B0')}, Colab-trained, ONNX) + YuNet face detector")
    else:
        indicators.append(_ind("Face-swap model not installed", f"Not used: {why_face}.", "low", False))

    for m in _image_metadata_signals(file_path):              # context only: never decides, never "triggered"
        if m["triggered"]:
            m.update(weight=0, triggered=False, severity="low", label=m["label"] + " (info only)",
                     description=m["description"] + " Normal for photos sent over WhatsApp / social media, "
                     "screenshots and downloads - not used for the score.")
            indicators.append(m)

    score, confidence, decider = max(candidates, key=lambda c: c[0]) if candidates else (0, 30, "No check could decide.")
    others = [c[2] for c in candidates if c[2] != decider]
    if score >= 51:
        explanation = decider + (" Other checks: " + " ".join(others) if others else "")
        explanation += (" Treat this as a strong warning: do not trust or share the image without checking its source."
                        if score >= 71 else " Check where the picture came from before trusting it.")
    else:
        explanation = ("No check found signs of AI generation or face manipulation. " + " ".join(c[2] for c in candidates)
                       + " This lowers the risk but cannot prove the picture is genuine - new generators and heavy "
                       "editing can still slip through.")
    result = build_result(indicators=indicators, base_score=score, confidence=min(confidence, 99),
                          engine_name="CYBERGUARD Deepfake Engine — " + " + ".join(engines),
                          threat_type=subtopic_title, explanation=explanation)
    result["provenance"] = prov
    if ai:
        result["aiImageModel"] = {"probability": round(ai["probability"], 4), "level": ai["level"], "views": ai["views"],
                                  "alertThreshold": ai["thrAlert"], "verifyThreshold": ai["thrVerify"],
                                  "trainedAt": ai["meta"].get("trained_at")}
    if face:
        result["deepfakeModel"] = {"probability": round(face["probability"], 4), "level": face["level"],
                                   "faces": face["faces"], "wholeImage": face["wholeImage"],
                                   "alertThreshold": face["thrAlert"], "verifyThreshold": face["thrVerify"],
                                   "trainedAt": face["meta"].get("trained_at")}
    return result, None


def _video_face_check(file_path):
    from app.detectors import deepfake_video as DV
    try:
        return DV.assess_video(file_path), None
    except DV.ModelUnavailable as e:
        return None, f"face-swap video model: {e}"
    except Exception as e:                                   # unreadable video etc.: never crash
        return None, f"face-swap video model could not read the video ({e.__class__.__name__})"


def _clock(sec) -> str:
    sec = int(sec or 0)
    return f"{sec // 60}:{sec % 60:02d}"


def _video_perf(meta) -> str:
    r = meta.get("results") or {}
    t, d = r.get("test_celebdf_half_B_honest") or {}, r.get("test_dfdc_independent") or {}
    out = ""
    if t:
        out += (f" On {t.get('n')} Celeb-DF test videos it never saw it caught {t.get('caught_at_alert', 0) * 100:.0f}% of "
                f"face-swaps at {t.get('false_alarms_at_alert', 0) * 100:.0f}% false alarms")
    if d:
        out += (f"; on a different dataset (DFDC, {d.get('n')} videos) it is much weaker (AUC {d.get('auc', 0):.2f}), "
                "so a low score is not proof that a video is real")
    return out + "." if out else ""


def _video_result(file_path: str | None, subtopic_title: str) -> dict:
    """Videos: the strongest check decides.
    1. provenance (20 Oct)  - the file declares AI generation / names an AI or face-swap tool -> proof
    2. face-swap model (21 Oct, Celeb-DF v2) - 16 frames, the largest face in each, mean score
    Without proof and without enough faces the result says 'no verdict', never 'not a deepfake'."""
    from app.detectors import deepfake_video as DV
    from app.detectors import video_provenance as VP
    prov = VP.provenance(file_path) if file_path else {"proof": False, "kind": None, "findings": [],
                                                       "hasContentCredentials": False}
    face, why_face = _video_face_check(file_path) if file_path else (None, "no file was uploaded")
    indicators = [_ind(f["label"], f["detail"], "critical" if f["proof"] else "low", True) for f in prov["findings"]]
    engines = ["Provenance check (C2PA Content Credentials / generator metadata)"]
    candidates = []
    if prov["proof"]:
        first = next(f for f in prov["findings"] if f["proof"])
        what = "a face-swap tool was used on it" if prov["kind"] == "faceswap" else "it was made with AI"
        candidates.append((95, 99, f"The video file itself shows that {what}: {first['detail']} This is proof from "
                                   "the file, not a guess."))

    if face and face["level"]:
        p, level, meta = face["probability"], face["level"], face["meta"]
        top = sorted(face["faces"], key=lambda f: -f["probability"])[:3]
        moments = ", ".join(f"{_clock(f['second'])} ({f['probability'] * 100:.0f}%)" for f in top)
        indicators.append(_ind(
            {"high": "Face-swap video model: the face looks manipulated",
             "medium": "Face-swap video model: the face may be manipulated - verify",
             "low": "Face-swap video model: no face manipulation found"}[level],
            f"The face-swap video model (EfficientNet-B0, trained on Celeb-DF v2) checked the largest face in "
            f"{face['framesWithFace']} of {face['framesChecked']} frames spread over the video. Average: {_pct(p)} "
            f"likely manipulated (it warns from {_pct(face['thrVerify'])}, alerts from {_pct(face['thrAlert'])}). "
            f"Most suspicious moments: {moments}." + _video_perf(meta),
            "critical" if level == "high" else "medium" if level == "medium" else "low", level != "low"))
        candidates.append((DV.score_from(face), 60 + abs(p - 0.5) * 60, {
            "high": f"Face-swap video model: the face looks manipulated ({_pct(p)} on average; most suspicious at {moments}).",
            "medium": f"Face-swap video model: the face may be manipulated ({_pct(p)} on average) - check the source.",
            "low": f"Face-swap video model: no face manipulation found ({_pct(p)} on average)."}[level]))
        engines.append("Face-swap video model (EfficientNet-B0, Celeb-DF v2)")
    elif face:
        indicators.append(_ind("Not enough faces for the face-swap model",
                               f"A clear face (at least 40 pixels) was found in {face['framesWithFace']} of "
                               f"{face['framesChecked']} checked frames; the model needs at least "
                               f"{face['meta'].get('min_faces_for_verdict', 3)}. Videos without people, very small "
                               "faces or screen recordings get no face verdict.", "low", False))
        engines.append("Face-swap video model (no verdict: too few faces)")
    else:
        indicators.append(_ind("Face-swap video model not installed", f"Not used: {why_face}.", "low", False))

    if candidates:
        score, confidence, decider = max(candidates, key=lambda c: c[0])
        others = [c[2] for c in candidates if c[2] != decider]
        if score >= 51:
            explanation = decider + (" Other checks: " + " ".join(others) if others else "")
            explanation += (" Treat this as a strong warning: do not trust or share the video as real footage."
                            if score >= 71 else " Check where the video came from before trusting it.")
        else:
            explanation = (" ".join(c[2] for c in candidates) + " This lowers the risk but cannot prove the video "
                           "is genuine: this model checks face swaps only - not fully AI-generated videos (Sora, Veo, "
                           "Kling ...), lip-sync changes or cloned voices.")
        engine = "CYBERGUARD Deepfake Engine — " + " + ".join(engines)
    else:
        score, confidence = 0, 0
        note = (" It carries Content Credentials that do not declare AI." if prov["hasContentCredentials"] else
                " It carries no Content Credentials or AI-tool names - normal for most videos, because re-uploading, "
                "screen recording and messaging apps remove them, so this proves nothing.")
        reason = ("too few clear faces were found for the face-swap model" if face else
                  "the trained video model is not installed")
        explanation = ("The video's metadata was checked for AI provenance and found no proof." + note +
                       f" No verdict is given on the picture itself because {reason}: this is 'no verdict', "
                       "NOT 'not a deepfake'.")
        engine = "CYBERGUARD Deepfake Engine — " + " + ".join(engines) + (
            " — No Verdict" if face else " — Video Model Unavailable")
    result = build_result(indicators=indicators, base_score=score, confidence=min(confidence, 99),
                          engine_name=engine, threat_type=subtopic_title, explanation=explanation)
    if not candidates:                       # no verdict is NOT "safe": shown as "unable to verify"
        result.update(classification="unverified", severity="info", recommendations=[
            "Check where the video came from: the original account or channel, the date, other reliable sources.",
            "For a face check, upload a version where a face is clearly visible for several seconds.",
            "Do not forward the video as real until its source is confirmed."])
    result["provenance"] = prov
    if face:
        result["deepfakeVideoModel"] = {
            "probability": round(face["probability"], 4) if face["probability"] is not None else None,
            "level": face["level"], "faces": face["faces"], "framesWithFace": face["framesWithFace"],
            "framesChecked": face["framesChecked"], "alertThreshold": face["thrAlert"],
            "verifyThreshold": face["thrVerify"], "trainedAt": face["meta"].get("trained_at")}
    return result


def _image_metadata_signals(file_path: str) -> list[dict]:
    indicators = []

    def add(triggered, label, desc, severity, weight):
        indicators.append({"label": label, "description": desc, "severity": severity, "weight": weight, "triggered": bool(triggered), "id": f"IND_{uuid.uuid4().hex[:12]}"})

    try:
        from PIL import Image
        img = Image.open(file_path)
        exif = img.getexif()
        has_exif = bool(exif and len(exif) > 0)
        add(not has_exif, "Missing camera EXIF metadata",
            "Image has no camera/device EXIF data — common in screenshots, re-saves, and AI-generated images (also common for legitimately stripped images).",
            "low", 8)

        software_tag = exif.get(305) if exif else None  # 305 = Software tag
        editing_software = bool(software_tag) and any(
            kw in str(software_tag).lower() for kw in ["photoshop", "gimp", "stable diffusion", "midjourney", "dall-e", "generated"]
        )
        add(editing_software, "Editing/generation software tag present",
            f"EXIF Software tag indicates: {software_tag}", "medium", 15)

        fmt_jpeg = img.format == "JPEG"
        add(fmt_jpeg and not has_exif, "Re-encoded JPEG without metadata",
            "JPEG re-encoding without EXIF is consistent with a saved/exported image rather than an original camera capture.",
            "low", 6)
    except Exception:
        add(True, "Unable to read image metadata",
            "The file could not be parsed as a standard image for metadata analysis.", "low", 4)

    return indicators


def analyze_media(file_path: str | None, file_name: str, subtopic_title: str = "Deepfake Detection") -> dict:
    is_video = file_name.lower().endswith((".mp4", ".mov", ".avi", ".mkv", ".webm"))

    why_no_model = "no file was uploaded"
    if file_path and not is_video:
        model_result, why_no_model = _image_model_result(file_path, subtopic_title)
        if model_result:
            return model_result

    if is_video:
        return _video_result(file_path, subtopic_title)

    indicators = _image_metadata_signals(file_path) if file_path else []
    triggered = [i for i in indicators if i["triggered"]]
    score = sum(i["weight"] for i in indicators if i["triggered"])
    confidence = 25 + min(len(triggered) * 5, 20)  # deliberately capped — this is a weak signal

    if triggered:
        names = ", ".join(i["label"].lower() for i in triggered)
        explanation = (
            f"The trained image models could not be used ({why_no_model}), so this result is based only on "
            f"static metadata analysis: {names}. This is a weak signal, not a manipulation verdict — "
            f"treat this result as inconclusive."
        )
    else:
        explanation = (
            f"The trained image models could not be used ({why_no_model}). Static metadata analysis found "
            "nothing notable, but this does NOT confirm the media is authentic."
        )

    return build_result(
        indicators=indicators, base_score=score, confidence=confidence,
        engine_name="CYBERGUARD Deepfake Engine — Metadata-Only (Model Unavailable)",
        threat_type=subtopic_title, explanation=explanation,
    )
