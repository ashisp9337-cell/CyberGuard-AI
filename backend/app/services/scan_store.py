"""
Save one detector result the same way a manual scan is saved -- used by manual scans AND by the
automatic watchers (app/automation/), so automatic findings show up in Scan History, the Dashboard,
Live Monitoring and alerts exactly like manual ones.
"""
from datetime import datetime, timezone

from app.db.models import DetectedIndicatorRow, RecommendationRow, Scan, ThreatEvent


def save_result(db, *, user_id: str, module_id: str, subtopic_id: str, subtopic_title: str, result: dict,
                target: str, target_type: str, metadata: dict | None = None, source: str = "scan",
                event_type: str | None = None, event_title: str | None = None,
                event_extra: dict | None = None) -> Scan:
    """Adds Scan + indicators + recommendations (+ a ThreatEvent when not safe). Caller commits.

    Also checks the scan's URLs/domains/IPs/senders/file hashes against IOCs from earlier risky scans
    ("seen before" raises the score) and remembers this scan's ones if it is risky (app/services/ioc.py),
    and tags the result with MITRE ATT&CK techniques and their explanations (app/services/mitre.py)."""
    from app.services import ioc, mitre
    try:
        cands = ioc.candidates(result, target, module_id)
        hits = ioc.lookup(db, user_id, cands)
        ioc.apply_seen_before(result, hits)
    except Exception:                       # IOC memory must never break a scan
        cands, hits = set(), []
    try:
        mitre.annotate(module_id, subtopic_id, result)   # MITRE ATT&CK techniques + plain explanations
    except Exception:
        result.setdefault("mitre", [])
        result.setdefault("mitreDetails", [])
    scan_row = Scan(
        user_id=user_id, module_id=module_id, subtopic_id=subtopic_id, subtopic_title=subtopic_title,
        input_type=target_type, target=str(target)[:500], input_metadata=metadata or {},
        status="completed", risk_score=result["riskScore"], classification=result["classification"],
        severity=result["severity"], confidence=result["confidenceScore"],
        threat_type=result["threatType"], analysis_engine=result["analysisEngine"],
        explanation=result["explanation"], result=result, completed_at=datetime.now(timezone.utc),
    )
    db.add(scan_row)
    db.flush()
    for ind in result["indicators"]:
        db.add(DetectedIndicatorRow(
            scan_id=scan_row.id, label=ind["label"], severity=ind["severity"],
            description=ind["description"], weight=ind["weight"], triggered=ind["triggered"],
        ))
    for i, rec in enumerate(result["recommendations"]):
        db.add(RecommendationRow(scan_id=scan_row.id, recommendation=rec, priority=i))
    try:
        ioc.record(db, user_id, scan_row.id, module_id, result, cands)
    except Exception:
        pass

    # Feed Live Monitoring / notifications: only notable results become threat events.
    if result["classification"] != "safe":
        db.add(ThreatEvent(
            user_id=user_id, event_type=event_type or module_id, source=source, severity=result["severity"],
            title=event_title or f"{result['threatType']} — {result['classification'].replace('_', ' ').title()}",
            description=result["explanation"][:500],
            event_metadata={"target": scan_row.target, "riskScore": result["riskScore"], "category": module_id,
                            "scanId": scan_row.id, "iocHits": len(hits), **(event_extra or {}),
                            "mitre": result.get("mitre", [])},
            status="active", timestamp=datetime.now(timezone.utc),
        ))
    return scan_row


def detail_fields(result: dict) -> dict:
    """Extra result details for the API (live scan response and Scan History detail):
    MITRE ATT&CK techniques with explanations, IOC 'seen before' hits, the URL model's own assessment,
    the per-engine breakdown of an email, the email's sender/authentication summary and parsed log signals."""
    result = result or {}
    out = {
        "mitreAttack": result.get("mitreDetails") or [],
        "iocHits": result.get("iocHits") or [],
        "modelAssessment": result.get("modelAssessment"),
        "engineBreakdown": [
            {"component": c.get("component"), "engine": c.get("engine"), "score": c.get("score"),
             "classification": c.get("classification"), "explanation": c.get("explanation")}
            for c in (result.get("components") or []) if isinstance(c, dict)][:10],
        "category": result.get("category"),
        "parsedSignals": result.get("parsedSignals"),
    }
    em = result.get("email") or {}
    if em:
        auth = em.get("auth") or {}
        out["emailSummary"] = {
            "from": em.get("from_address", ""), "displayName": em.get("from_display_name", ""),
            "subject": (em.get("subject") or "")[:200], "replyTo": em.get("reply_to_address") or "",
            "originatingIp": em.get("originating_ip") or "",
            "spf": auth.get("spf", "unknown"), "dkim": auth.get("dkim", "unknown"), "dmarc": auth.get("dmarc", "unknown"),
            "links": len(em.get("links") or []), "attachments": len(em.get("attachments") or []),
            "escalations": list(result.get("escalations") or [])[:5],
        }
    return out


def indicator_mitre(ind: dict) -> list[str]:
    v = ind.get("mitre")
    if isinstance(v, str):
        v = [v]
    return [t for t in (v or []) if isinstance(t, str) and t]
