"""
Routes a scan request to the correct detector based on moduleId, mirroring
the six CyberGuard modules and their subtopics defined in the frontend's
src/data/modules.ts. This is the single place that decides "what kind of
analysis does this input need" — detectors themselves stay generic.
"""
from app.detectors import phishing, malicious_url, deepfake, impersonation, account_takeover, cyber_threat, email_parser, qr_analyzer, known_contact_impersonation, financial_impersonation, brand_impersonation, teacher_university_impersonation, senior_management_impersonation, government_impersonation, financial_impersonation, known_contact_impersonation, known_contact_impersonation


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
    db=None, user_id: str | None = None,
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

        # Email Analysis -> full Email Intelligence Pipeline: headers/SPF/DKIM/DMARC,
        # every link, attachment and QR image, all 6 impersonation detectors,
        # account-takeover signals, fused into one verdict.
        if subtopic_id == "email-analysis":
            from app.email_pipeline import analyze_email
            from app.email_pipeline.store import record_email
            raw = target_text
            if file_path and not target_text:
                with open(file_path, "rb") as f:
                    raw = f.read()
            result = analyze_email(raw, db=db, user_id=user_id, sender=sender or "")
            if db is not None and user_id:
                try:
                    record_email(db, user_id, result, source="upload" if file_path else "paste")
                except Exception:
                    pass  # history is best-effort; never fail the scan over it
            return result

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
        target = (text_input or "")[:80] or "identity submission"
        if subtopic_id == "contact-impersonation":
            # Personal to the user (their own saved contacts) — not a generic
            # trained model. See known_contact_impersonation.py for why.
            result = known_contact_impersonation.analyze_known_contact_message(
                text_input or "", extra_field_values, subtopic_title, db=db, user_id=user_id,
            )
        elif subtopic_id == "financial-impersonation":
            result = financial_impersonation.analyze_financial_impersonation(
                text_input or "", extra_field_values, subtopic_title,
            )
        elif subtopic_id == "brand-impersonation":
            result = brand_impersonation.analyze_brand_impersonation(
                text_input or "", extra_field_values, subtopic_title,
            )
        elif subtopic_id == "teacher-impersonation":
            result = teacher_university_impersonation.analyze_teacher_university_impersonation(
                text_input or "", extra_field_values, subtopic_title,
            )
        elif subtopic_id == "management-impersonation":
            result = senior_management_impersonation.analyze_senior_management_impersonation(
                text_input or "", extra_field_values, subtopic_title,
            )
        elif subtopic_id == "government-impersonation":
            result = government_impersonation.analyze_government_impersonation(
                text_input or "", extra_field_values, subtopic_title,
            )
        else:
            result = impersonation.analyze_identity(text_input or "", extra_field_values, subtopic_title)
        return result | {"_target": target, "_target_type": "identity"}

    if module_id == "credential":
        fields = dict(extra_field_values)
        result = account_takeover.analyze_event(fields, subtopic_title, text=text_input or "")
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