"""
"Is this safe?" from the chat: runs CyberGuard's OWN detectors on a pasted link / SMS / chat message / e-mail,
exactly like the Scan page in auto-detect mode, and saves the scan to Scan History (source "chat"), with the same
IOC memory, MITRE tags, response actions and alerts as a normal scan.

The verdict comes from the detectors, never from the AI: the chat only explains it, and chat_service adds the
verdict line to the reply itself.
"""
from __future__ import annotations

import hashlib
import logging
import threading

logger = logging.getLogger("cyberguard.chat")


def _scan_once(db, user_id: str, module_id: str, raw: str, url: str | None):
    from app.services import subtopic_router
    result, c = subtopic_router.route(module_id=module_id, text_input=None if url else raw, url_input=url,
                                      file_path=None, file_name=None, extra_field_values={}, db=db, user_id=user_id)
    result["routing"] = c.to_dict()
    return result, c


def run(db, user_id: str, raw: str, cache: dict | None = None) -> dict:
    """Scan one pasted item. Returns the saved result summary (real values; the caller masks it for the AI)."""
    from app.services import notifier, response_playbook, scan_store, subtopic_router

    raw = (raw or "").strip()
    if not raw:
        return {"error": "Nothing to check - paste the link, SMS, message or e-mail."}
    key = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()
    if cache is not None and key in cache:              # the same request asked twice (e.g. a retried AI call)
        return cache[key]

    url = subtopic_router.single_url(raw)
    modules = ["phishing"] if url else ["phishing", "impersonation"]
    best = None
    for module_id in modules:
        try:
            result, c = _scan_once(db, user_id, module_id, raw, url)
        except subtopic_router.RoutingError as exc:
            logger.info("chat scan: %s could not route (%s)", module_id, exc.code)
            continue
        except Exception:
            logger.exception("chat scan failed in %s", module_id)
            continue
        if best is None or result["riskScore"] > best[0]["riskScore"]:
            best = (result, c, module_id)
    if best is None:
        return {"error": "CyberGuard could not decide which check fits this content. Use the Scan page and pick "
                         "the module yourself."}

    result, c, module_id = best
    target = result.pop("_target", None) or url or raw[:120]
    target_type = result.pop("_target_type", "url" if url else "text")
    response_playbook.apply(result, module_id, c.subtopic_id, raw)
    row = scan_store.save_result(db, user_id=user_id, module_id=module_id, subtopic_id=c.subtopic_id,
                                 subtopic_title=c.subtopic_title, result=result, target=str(target),
                                 target_type=target_type, metadata={"via": "chat"}, source="chat")
    db.commit()
    db.refresh(row)
    if result["riskScore"] >= notifier.ALERT_FLOOR:                # same alert rules as a normal scan
        threading.Thread(target=notifier.alert_for_scan, args=(row.id,), daemon=True).start()

    reasons = sorted((i for i in result["indicators"] if i.get("triggered") and i.get("weight", 0) > 0),
                     key=lambda i: -i.get("weight", 0))[:5]
    out = {
        "scan_id": row.id, "risk_score": result["riskScore"], "verdict": result["classification"],
        "severity": result["severity"], "threat_type": result["threatType"],
        "checked_as": f"{module_id} / {c.subtopic_title}",
        "main_reasons": [f"{i['label']}: {i['description'][:220]}" for i in reasons],
        "recommended_actions": [r[:220] for r in result.get("recommendations", [])[:4]],
        "detector_explanation": result["explanation"][:700],
    }
    if cache is not None:
        cache[key] = out
    return out


def verdict_line(summary: dict) -> str:
    """The verdict line CyberGuard itself appends to the AI's reply (the AI cannot change it)."""
    label = {"safe": "Safe", "low_risk": "Low risk", "suspicious": "Suspicious - verify first",
             "high_risk": "High risk", "critical": "Critical - do not interact",
             "unverified": "No verdict"}.get(summary.get("verdict"), str(summary.get("verdict")))
    return (f"🛡️ CyberGuard verdict (from the detectors, not the AI): {summary['risk_score']}/100 - {label} · "
            f"{summary.get('threat_type', '')} · saved as scan {summary['scan_id']}")
