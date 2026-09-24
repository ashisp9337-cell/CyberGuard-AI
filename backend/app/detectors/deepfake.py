"""
Deepfake / synthetic-media detector.

HONESTY NOTE: this project does not ship a trained deepfake-detection
model (that requires a large labeled video/image corpus and GPU training
— out of scope for this delivery). What IS implemented here is real:
static file/metadata analysis using Pillow (resave/compression artifacts,
EXIF presence, editing-software tags). This is a legitimate but weak
signal, explicitly reported with lower confidence — it never fabricates
a "deepfake" verdict from randomness.

To plug in a real model: implement `run_trained_model(file_path) ->
(probability, confidence)` below and set DEEPFAKE_MODEL_PATH in .env;
this function is the single integration point.
"""
import os
import uuid
from app.detectors.base import build_result

MODEL_AVAILABLE = bool(os.environ.get("DEEPFAKE_MODEL_PATH"))


def run_trained_model(file_path: str):
    """Plug a real model in here. Returns (probability_synthetic, confidence) or None."""
    return None


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

    model_result = run_trained_model(file_path) if (file_path and MODEL_AVAILABLE) else None

    if model_result:
        proba, confidence = model_result
        engine = "CYBERGUARD Deepfake Engine — Trained Model"
        indicators = []
        score = proba * 100
        explanation = f"Trained model assessed a {proba*100:.0f}% probability of synthetic/manipulated media."
        return build_result(indicators=indicators, base_score=score, confidence=confidence,
                             engine_name=engine, threat_type=subtopic_title, explanation=explanation)

    if is_video:
        explanation = (
            "No trained video deepfake-detection model is configured on this server, so no "
            "manipulation verdict is produced. Video deepfake detection requires a dedicated "
            "trained model (see app/detectors/deepfake.py). This is reported as 'model unavailable', "
            "not as 'not a deepfake'."
        )
        return build_result(
            indicators=[], base_score=0, confidence=0,
            engine_name="CYBERGUARD Deepfake Engine — Model Unavailable",
            threat_type=subtopic_title, explanation=explanation,
        )

    indicators = _image_metadata_signals(file_path) if file_path else []
    triggered = [i for i in indicators if i["triggered"]]
    score = sum(i["weight"] for i in indicators if i["triggered"])
    confidence = 25 + min(len(triggered) * 5, 20)  # deliberately capped — this is a weak signal

    if triggered:
        names = ", ".join(i["label"].lower() for i in triggered)
        explanation = (
            f"No trained GAN/deepfake model is configured, so this result is based only on static "
            f"metadata analysis: {names}. This is a weak signal, not a manipulation verdict — "
            f"treat this result as inconclusive."
        )
    else:
        explanation = (
            "No trained GAN/deepfake model is configured. Static metadata analysis found nothing "
            "notable, but this does NOT confirm the media is authentic — configure a trained model "
            "for a real verdict."
        )

    return build_result(
        indicators=indicators, base_score=score, confidence=confidence,
        engine_name="CYBERGUARD Deepfake Engine — Metadata-Only (Model Unavailable)",
        threat_type=subtopic_title, explanation=explanation,
    )
