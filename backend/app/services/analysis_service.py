"""
Routes a scan request to the correct detector based on moduleId, mirroring
the six CyberGuard modules and their subtopics defined in the frontend's
src/data/modules.ts. This is the single place that decides "what kind of
analysis does this input need" — detectors themselves stay generic.
"""
from app.detectors import phishing, malicious_url, deepfake, impersonation, account_takeover, cyber_threat, email_parser, qr_analyzer


def _try_decode_qr(file_path: str) -> str | None:
    try:
        from pyzbar.pyzbar import decode
        from PIL import Image
        results = decode(Image.open(file_path))
        if results:
            return results[0].data.decode("utf-8", errors="ignore")
    except Exception:
        return None
    return None


def run_scan(
    *, module_id: str, subtopic_id: str, subtopic_title: str,
    text_input: str | None, url_input: str | None,
    file_path: str | None, file_name: str | None,
    extra_field_values: dict | None,
) -> dict:
    extra_field_values = extra_field_values or {}

    if module_id == "phishing":
        if subtopic_id == "qr-phishing" and file_path:
            return qr_analyzer.analyze_qr(file_path, file_name, subtopic_title, subtopic_id)
        if subtopic_id in ("fraudulent-website", "malicious-url") or url_input:
            target = url_input or text_input or ""
            result = malicious_url.analyze_url(target, subtopic_title, subtopic_id=subtopic_id)
            return result | {"_target": target, "_target_type": "url"}
        sender = extra_field_values.get("sender")
        reply_to = None
        target_text = text_input or ""

        # Fix: previously, if the user uploaded a .eml/.msg/.txt file
        # instead of pasting text, the file was saved to disk but never
        # actually read for analysis. Now it's really parsed.
        if not target_text and file_path:
            try:
                with open(file_path, "rb") as f:
                    raw = f.read()
                parsed = email_parser.parse_email_file(raw)
                target_text = parsed["body"]
                if not sender and parsed.get("from_address"):
                    sender = parsed["from_address"]
                reply_to = parsed.get("reply_to_address") or None
            except Exception:
                pass

        result = phishing.analyze_text(target_text, sender=sender, subtopic_title=subtopic_title, subtopic_id=subtopic_id, reply_to=reply_to)
        return result | {"_target": target_text[:80] or (file_name or "submission"), "_target_type": "email" if subtopic_id == "email-analysis" else "text"}

    if module_id == "deepfake":
        result = deepfake.analyze_media(file_path, file_name or "media file", subtopic_title)
        return result | {"_target": file_name or "uploaded media", "_target_type": "file"}

    if module_id == "impersonation":
        result = impersonation.analyze_identity(text_input or "", extra_field_values, subtopic_title)
        target = (text_input or "")[:80] or "identity submission"
        return result | {"_target": target, "_target_type": "identity"}

    if module_id == "credential":
        fields = dict(extra_field_values)
        result = account_takeover.analyze_event(fields, subtopic_title)
        target = text_input[:80] if text_input else "account security event"
        return result | {"_target": target, "_target_type": "identity" if subtopic_id != "password-spraying" and subtopic_id != "session-activity" and subtopic_id != "behavior-changes" else "text"}

    if module_id == "url-security":
        target = url_input or text_input or ""
        result = malicious_url.analyze_url(target, subtopic_title)
        return result | {"_target": target, "_target_type": "url"}

    if module_id == "cyber-threat":
        result = cyber_threat.analyze_event_text(text_input or "", extra_field_values, subtopic_title)
        target = (text_input or "")[:80] or (file_name or "event submission")
        return result | {"_target": target, "_target_type": "file" if file_name else "text"}

    return {
        "riskScore": 0, "classification": "safe", "severity": "info", "confidenceScore": 0,
        "analysisEngine": "CYBERGUARD Engine", "threatType": subtopic_title, "indicators": [],
        "recommendations": [], "explanation": f"Unknown module '{module_id}'.",
        "_target": "unknown", "_target_type": "text",
    }