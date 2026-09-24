"""
Shared detection-output builder. Every detector returns the same shape so
the API layer and frontend AnalysisResult contract stay uniform.
"""
from app.services.risk_scoring import classify_risk, severity_from_classification, recommendations_for


def build_result(
    *, indicators: list[dict], base_score: float, confidence: float,
    engine_name: str, threat_type: str, explanation: str,
    extra_recommendations: list[str] | None = None,
) -> dict:
    score = max(0, min(100, round(base_score)))
    classification = classify_risk(score)
    severity = severity_from_classification(classification)
    recs = recommendations_for(classification, threat_type)
    if extra_recommendations:
        recs = extra_recommendations + recs

    return {
        "riskScore": score,
        "classification": classification,
        "severity": severity,
        "confidenceScore": max(0, min(100, round(confidence))),
        "analysisEngine": engine_name,
        "threatType": threat_type,
        "indicators": indicators,
        "explanation": explanation,
        "recommendations": recs,
    }


def indicators_from_triggered(pool: list[dict]) -> list[dict]:
    """Assigns generateId-equivalent ids; pool items already have triggered set."""
    import uuid
    out = []
    for item in pool:
        out.append({**item, "id": f"IND_{uuid.uuid4().hex[:12]}"})
    return out


def score_from_indicators(indicators: list[dict]) -> float:
    """Weighted sum of triggered indicator weights, scaled into 0-100ish."""
    triggered_weight = sum(i["weight"] for i in indicators if i["triggered"])
    return triggered_weight

def build_unverified_result(*, engine_name: str, threat_type: str, explanation: str,
                             extra_recommendations: list[str] | None = None) -> dict:
    """
    For inputs that could not be read at all (e.g. an undecodable QR image).
    This is deliberately NOT "safe" — we don't know what the content is, so
    we say so, instead of guessing. classification "unverified" is separate
    from the risk-score classifications and always carries riskScore 0 /
    confidenceScore 0 so it can never be mistaken for a real safe result.
    """
    recs = (extra_recommendations or []) + [
        "Retake the photo in good lighting with the QR code filling the frame.",
        "Make sure all four corners of the QR code are visible, without glare or blur.",
        "If the code is printed, check that it isn't damaged, folded, or partly covered.",
    ]
    return {
        "riskScore": 0,
        "classification": "unverified",
        "severity": "info",
        "confidenceScore": 0,
        "analysisEngine": engine_name,
        "threatType": threat_type,
        "indicators": [],
        "explanation": explanation,
        "recommendations": recs,
    }