"""
Saving pipeline results: EmailRecord rows + per-user SenderHistory.

Kept separate from the detectors so the pipeline itself stays pure (no DB
writes) and can be reused by the upload API, the IMAP/Gmail poller (step 5)
and tests alike.
"""
from datetime import datetime, timezone

from app.db.models import EmailRecord, SenderHistory
from app.email_pipeline import quarantine


def record_email(db, user_id: str, result: dict, *, scan_id: str | None = None, source: str = "upload") -> EmailRecord:
    em = result.get("email", {}) or {}
    auth = em.get("auth", {}) or {}
    rec = EmailRecord(
        user_id=user_id, scan_id=scan_id, source=source,
        message_id=(em.get("message_id") or "")[:500],
        from_address=em.get("from_address", ""), from_domain=em.get("from_domain", ""),
        from_display_name=(em.get("from_display_name") or "")[:300], subject=em.get("subject", ""),
        spf=auth.get("spf", "unknown"), dkim=auth.get("dkim", "unknown"), dmarc=auth.get("dmarc", "unknown"),
        originating_ip=em.get("originating_ip", ""),
        link_count=len(em.get("links", [])),
        attachment_count=len([a for a in em.get("attachments", []) if not a.get("is_inline")]),
        category=result.get("category", ""), risk_score=result.get("riskScore", 0),
        classification=result.get("classification", "safe"), mitre=result.get("mitre", []),
        components=result.get("components", []),
        details={"links": em.get("links", [])[:50], "attachments": em.get("attachments", []),
                 "claimed_entities": em.get("claimed_entities", []), "trust": result.get("trust", {}),
                 "escalations": result.get("escalations", [])},
    )
    quarantine.apply_to_record(rec, result)   # auto-quarantine dangerous mail
    db.add(rec)
    _update_sender_history(db, user_id, em.get("from_address", ""), em.get("from_domain", ""),
                           result.get("classification", "safe"))
    return rec


def _update_sender_history(db, user_id: str, address: str, domain: str, classification: str):
    if not address:
        return
    row = (db.query(SenderHistory)
           .filter(SenderHistory.user_id == user_id, SenderHistory.sender_address == address).first())
    now = datetime.now(timezone.utc)
    if row is None:
        row = SenderHistory(user_id=user_id, sender_address=address, sender_domain=domain,
                            message_count=0, safe_count=0, malicious_count=0, first_seen=now, last_seen=now)
        db.add(row)
    row.message_count = (row.message_count or 0) + 1
    if classification == "safe":
        row.safe_count = (row.safe_count or 0) + 1
    elif classification in ("high_risk", "critical"):
        row.malicious_count = (row.malicious_count or 0) + 1
    row.last_seen = now
