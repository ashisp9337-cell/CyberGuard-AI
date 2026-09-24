"""
Real malicious URL detector: trained RandomForest over structural/lexical
URL features, combined with deterministic rule indicators computed from
the actual submitted URL.

Each URL-based phishing subtopic (QR code / fraudulent website / malicious
URL) can have its own independently-trained model file — see MODEL_FILES
below. Subtopics not listed fall back to the shared DEFAULT_MODEL_FILE.
"""
import os
import uuid
import joblib

from app.core.config import get_settings
from app.detectors.base import build_result
from app.detectors.url_features import extract_url_features, explain_url_features
from app.detectors.url_features_v2 import extract_features_v2

settings = get_settings()

# subtopic_id -> model filename (relative to settings.MODELS_DIR).
# Train each with: python -m app.ml.training.train_url --data <file> --out <filename>
MODEL_FILES = {
    "qr-phishing": "url_qr.joblib",
    "fraudulent-website": "url_fraudulent_website.joblib",
    "malicious-url": "url_general.joblib",
}
DEFAULT_MODEL_FILE = "url_model.joblib"

_model_cache: dict[str, tuple[float, object]] = {}  # filename -> (mtime, model)


def _get_model(subtopic_id: str | None):
    """
    Loads the model for a subtopic, auto-reloading it if the .joblib file
    on disk has changed since it was last cached (so a freshly retrained
    model is picked up without needing to restart the backend). If the
    file is missing, unreadable, or fails to load, returns None — the
    caller falls back to rule-based-only scoring rather than crashing.
    """
    filename = MODEL_FILES.get(subtopic_id or "", DEFAULT_MODEL_FILE)
    path = os.path.join(settings.MODELS_DIR, filename)

    if not os.path.exists(path):
        _model_cache.pop(filename, None)
        return None

    mtime = os.path.getmtime(path)
    cached = _model_cache.get(filename)
    if cached and cached[0] == mtime:
        return cached[1]

    try:
        model = joblib.load(path)
    except Exception:
        model = None
    _model_cache[filename] = (mtime, model)
    return model


def analyze_url(url: str, subtopic_title: str = "Malicious URL Analysis", subtopic_id: str | None = None) -> dict:
    url = (url or "").strip()
    if not url:
        return build_result(
            indicators=[], base_score=0, confidence=0,
            engine_name="CYBERGUARD URL Engine", threat_type=subtopic_title,
            explanation="No URL was submitted to analyze.",
        )

    features = extract_url_features(url)
    indicators = explain_url_features(url, features)
    rule_score = sum(i["weight"] for i in indicators if i["triggered"])

    # Model inference uses the v2 feature set (bias-fixed: v1 leaked "has_https"
    # as a spurious "malicious" signal because training data over-represented
    # HTTPS on the phishing side). v1 features above still drive the
    # human-readable "Detected Indicators" — that explainability layer is
    # unaffected by which feature set the model itself uses.
    features_v2 = extract_features_v2(url)

    model = _get_model(subtopic_id)
    model_used = model is not None
    proba = None
    if model_used:
        try:
            proba = float(model.predict_proba([features_v2])[0][1])
            model_score = proba * 100
            blended = 0.65 * model_score + 0.35 * min(rule_score, 100)
            confidence = 70 + abs(proba - 0.5) * 55
        except Exception:
            # A corrupt, incompatible, or otherwise broken model file must
            # never crash a scan — fall back to rule-based-only scoring.
            model_used = False
            blended = min(rule_score, 100)
            confidence = 45 + min(rule_score, 45)
    else:
        blended = min(rule_score, 100)
        confidence = 45 + min(rule_score, 45)

    triggered = [i for i in indicators if i["triggered"]]
    for ind in indicators:
        ind["id"] = f"IND_{uuid.uuid4().hex[:12]}"

    if triggered:
        top = sorted(triggered, key=lambda i: -i["weight"])[:3]
        names = ", ".join(i["label"].lower() for i in top)
        model_note = f" The trained classifier assessed a {proba*100:.0f}% probability of malicious intent." if model_used else " (Trained model unavailable — assessment is rule-based only.)"
        explanation = f"Structural analysis flagged {len(triggered)} indicator(s) for this URL, most notably: {names}.{model_note}"
    elif model_used:
        explanation = f"No structural red flags were found, and the trained classifier assessed a {proba*100:.0f}% probability of malicious intent."
    else:
        explanation = "No structural red flags were found in this URL. (Trained model unavailable — assessment is rule-based only.)"

    return build_result(
        indicators=indicators,
        base_score=blended,
        confidence=confidence,
        engine_name=f"CYBERGUARD URL Engine — {'RandomForest' if model_used else 'Rule-Based (model unavailable)'}",
        threat_type=subtopic_title,
        explanation=explanation,
    )