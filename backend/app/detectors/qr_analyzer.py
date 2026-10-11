"""
QR code phishing analysis, end to end:

    image --decode--> payload text --classify--> kind (url / upi / wifi / sms / ...)
          --analyse--> URL engine (+ trained url_qr model when present)
                       or payload rules
          --merge----> QR-specific indicators --> one uniform result dict

If nothing can be decoded, QRDecodeError is raised. A QR image that cannot be
read must never be reported as "safe".
"""
from __future__ import annotations

import uuid

from app.detectors import malicious_url, phishing
from app.detectors.base import build_result, build_unverified_result, build_unverified_result
from app.detectors.qr_decoder import decode_qr_image, MAX_CODES
from app.detectors.qr_payload import (
    Payload, classify_payload, extra_recommendations, payload_indicators, url_context_indicators,
)
from app.services.risk_scoring import classify_risk


class QRDecodeError(Exception):
    """The uploaded image could not be read or contains no decodable QR code."""


def _with_ids(indicators: list[dict]) -> list[dict]:
    return [{**i, "id": f"IND_{uuid.uuid4().hex[:12]}"} for i in indicators]


def _text_rule_result(p: Payload, subtopic_title: str, subtopic_id: str) -> dict:
    """Plain-text QR payloads: rule-based text checks only (no ML model is used for QR text)."""
    indicators = phishing._rule_indicators(p.raw, sender=None, reply_to=None)
    link = phishing._link_destination_indicator(p.raw, subtopic_id)
    if link:
        indicators.append(link)
    score = min(100, sum(i["weight"] for i in indicators if i["triggered"]))
    triggered = [i for i in indicators if i["triggered"]]
    return build_result(
        indicators=_with_ids(indicators), base_score=score, confidence=40 + min(score, 50),
        engine_name="CYBERGUARD QR Engine — Text Rules", threat_type=subtopic_title,
        explanation=(
            f"The QR contains plain text; {len(triggered)} rule-based phishing indicator(s) matched."
            if triggered else "The QR contains plain text and no rule-based phishing indicators matched."
        ),
    )


def _analyze_payload(text: str, subtopic_title: str, subtopic_id: str,
                     network: bool = True) -> tuple[Payload, dict, list[dict]]:
    p = classify_payload(text)
    if p.kind == "url":
        base = malicious_url.analyze_url(p.url, subtopic_title, subtopic_id=subtopic_id, network=network)
        extra = url_context_indicators(p) + payload_indicators(p)
    elif p.kind == "text":
        base = _text_rule_result(p, subtopic_title, subtopic_id)
        extra = []
    else:
        base = build_result(
            indicators=[], base_score=0, confidence=60,
            engine_name="CYBERGUARD QR Engine — Payload Rules", threat_type=subtopic_title, explanation="",
        )
        extra = payload_indicators(p)
    return p, base, extra


def _finalize(p: Payload, base: dict, extra: list[dict], *, decoder: str, n_codes: int,
              subtopic_title: str) -> dict:
    indicators = list(base["indicators"]) + _with_ids(extra)
    extra_weight = sum(i["weight"] for i in extra if i["triggered"])
    score = min(100, base["riskScore"] + extra_weight)

    extra_names = [i["label"].lower() for i in sorted((i for i in extra if i["triggered"]), key=lambda i: -i["weight"])[:3]]
    explanation = f"Decoded a {p.label} from the QR image ({decoder})."
    if n_codes > 1:
        explanation += f" The image holds {n_codes} QR codes; this is the highest-risk one."
    if base["explanation"]:
        explanation += " " + base["explanation"]
    if extra_names:
        explanation += " QR-specific findings: " + ", ".join(extra_names) + "."

    recs = extra_recommendations(p)
    if p.kind == "url" and classify_risk(round(score)) not in ("safe", "low_risk"):
        recs = ["Do not open the link from the QR; type the official website address yourself instead."] + recs

    engine = base["analysisEngine"].replace("CYBERGUARD ", "", 1)
    return build_result(
        indicators=indicators, base_score=score, confidence=base["confidenceScore"],
        engine_name=f"CYBERGUARD QR Engine — decoder: {decoder}; {engine}",
        threat_type=subtopic_title, explanation=explanation, extra_recommendations=recs,
    )


def analyze_qr(file_path: str | None, file_name: str | None,
               subtopic_title: str = "QR Code Phishing Detection",
               subtopic_id: str = "qr-phishing", network: bool = True) -> dict:
    if not file_path:
        raise QRDecodeError("No image was uploaded.")

    decoded = decode_qr_image(file_path)
    if not decoded.codes:
        return build_unverified_result(
            engine_name="CYBERGUARD QR Engine — Decode Failed",
            threat_type=subtopic_title,
            explanation=decoded.error or "No QR code could be detected in this image.",
        ) | {"_target": file_name or "QR image", "_target_type": "file"}

    n_codes = len(decoded.codes)
    best: tuple[Payload, dict] | None = None
    for code in decoded.codes[:MAX_CODES]:
        p, base, extra = _analyze_payload(code.text, subtopic_title, subtopic_id, network=network)
        if n_codes > 1:
            extra = extra + [{
                "label": "Several QR codes in one image",
                "description": "Images with more than one QR code are used to hide a malicious code next to a harmless one.",
                "severity": "medium", "weight": 15, "triggered": True,
            }]
        result = _finalize(p, base, extra, decoder=code.engine, n_codes=n_codes, subtopic_title=subtopic_title)
        if best is None or result["riskScore"] > best[1]["riskScore"]:
            best = (p, result)

    assert best is not None
    p, result = best
    return result | {"_target": p.display or (file_name or "QR image"), "_target_type": "url" if p.kind == "url" else "text"}