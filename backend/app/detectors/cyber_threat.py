"""
Real, deterministic rule engine for general cyber-threat/event analysis
(module 6: "Intelligent Cyber Threat Detection"). Operates on the actual
submitted event text/fields — no randomness.
"""
import re
import uuid
from app.detectors.base import build_result

MALWARE_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
SUSPICIOUS_KEYWORDS = ["powershell -enc", "base64", "reverse shell", "mimikatz", "cmd.exe /c",
                        "wscript", "regsvr32", "certutil -urlcache", "invoke-expression"]


def analyze_event_text(text: str, extra_fields: dict | None = None, subtopic_title: str = "Intelligent Cyber Threat Detection") -> dict:
    text = (text or "").strip()
    extra_fields = extra_fields or {}
    lower = text.lower()

    indicators = []

    def add(triggered, label, desc, severity, weight):
        indicators.append({"label": label, "description": desc, "severity": severity, "weight": weight, "triggered": bool(triggered), "id": f"IND_{uuid.uuid4().hex[:12]}"})

    hashes = MALWARE_HASH_RE.findall(text)
    add(len(hashes) > 0, "File hash referenced",
        f"{len(hashes)} file hash(es) found in the event — cross-check against threat intelligence.",
        "high", 14)

    cmd_hit = any(kw in lower for kw in SUSPICIOUS_KEYWORDS)
    add(cmd_hit, "Suspicious command/process pattern",
        "Event text contains command patterns commonly associated with post-exploitation tooling.",
        "critical", 26)

    def gi(key, default=0):
        try:
            return int(extra_fields.get(key, default) or default)
        except (ValueError, TypeError):
            return default

    request_rate = gi("requestsPerMinute", 0)
    add(request_rate > 500, "Excessive API request rate",
        f"{request_rate} requests/minute far exceeds a typical baseline.", "medium", 12)

    data_transfer_mb = gi("dataTransferMb", 0)
    add(data_transfer_mb > 500, "Large unscheduled data transfer",
        f"{data_transfer_mb}MB transferred — review whether this matches expected business activity.",
        "high", 18)

    off_hours = str(extra_fields.get("offHours", "")).strip().lower() in ("1", "true", "yes")
    add(off_hours, "Activity outside business hours",
        "Event occurred outside the organization's normal operating hours.", "low", 8)

    obfuscation_markers = lower.count("%") + lower.count("\\x")
    add(obfuscation_markers > 5, "Obfuscated payload indicators",
        "Content shows signs of encoding/obfuscation commonly used to evade detection.", "high", 16)

    triggered = [i for i in indicators if i["triggered"]]
    score = sum(i["weight"] for i in indicators if i["triggered"])
    confidence = 50 + min(len(triggered) * 7, 35) if (text or extra_fields) else 0

    if not text and not extra_fields:
        explanation = "No event content or metadata was submitted to analyze."
    elif triggered:
        top = sorted(triggered, key=lambda i: -i["weight"])[:3]
        names = ", ".join(i["label"].lower() for i in top)
        explanation = f"Rule engine flagged {len(triggered)} indicator(s), most notably: {names}."
    else:
        explanation = "No rule-based threat indicators were detected in the submitted event."

    return build_result(
        indicators=indicators, base_score=score, confidence=confidence,
        engine_name="CYBERGUARD Cyber Threat Engine — Rule-Based",
        threat_type=subtopic_title, explanation=explanation,
    )
