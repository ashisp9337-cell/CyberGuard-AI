"""
Email Intelligence API.

POST /api/email/analyze        upload a .eml file OR paste a raw email/body -> fused verdict
GET  /api/email/records        the user's analysed emails (newest first)
GET  /api/email/records/{id}   one analysed email with full component breakdown

Every analysis is also saved as a normal Scan (so it appears in Scan History,
Dashboard, Reports) and, when not safe, as a ThreatEvent (Live Monitoring).
"""
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import User, Scan, DetectedIndicatorRow, RecommendationRow, ThreatEvent, EmailRecord
from app.email_pipeline import analyze_email
from app.services import response_playbook, notifier, notifier
from app.email_pipeline.store import record_email
from app.email_pipeline import quarantine
from pydantic import BaseModel

router = APIRouter(prefix="/api/email", tags=["email"])
settings = get_settings()
EMAIL_EXTENSIONS = (".eml", ".txt")


@router.post("/analyze")
async def analyze(
    background_tasks: BackgroundTasks,
    file: UploadFile | None = File(None),
    rawEmail: str | None = Form(None),
    sender: str | None = Form(None),
    subject: str | None = Form(None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if file is not None and file.filename:
        if not file.filename.lower().endswith(EMAIL_EXTENSIONS):
            raise HTTPException(status_code=400, detail={"error": {"code": "UNSUPPORTED_FILE_TYPE",
                                                                   "message": "Upload a .eml or .txt email file."}})
        raw = await file.read()
        if len(raw) > settings.MAX_UPLOAD_MB * 1024 * 1024:
            raise HTTPException(status_code=413, detail={"error": {"code": "FILE_TOO_LARGE",
                                                                   "message": f"File exceeds {settings.MAX_UPLOAD_MB}MB limit."}})
        source = "upload"
    elif rawEmail and rawEmail.strip():
        raw = rawEmail
        source = "paste"
    else:
        raise HTTPException(status_code=422, detail={"error": {"code": "NO_INPUT",
                                                               "message": "Provide a .eml file or paste the email."}})

    result = analyze_email(raw, db=db, user_id=user.id, sender=sender or "", subject=subject or "")
    target = result.pop("_target", "email")
    result.pop("_target_type", None)
    quarantine.decide(result)          # auto-quarantine decision (before the playbook, so it can say so)
    response_playbook.apply(result, "phishing", "email-analysis", str(target))

    scan = Scan(
        user_id=user.id, module_id="phishing", subtopic_id="email-analysis", subtopic_title="Email Analysis",
        input_type="email", target=str(target)[:500], input_metadata={"source": source},
        status="completed", risk_score=result["riskScore"], classification=result["classification"],
        severity=result["severity"], confidence=result["confidenceScore"], threat_type=result["threatType"],
        analysis_engine=result["analysisEngine"], explanation=result["explanation"], result=result,
        completed_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.flush()
    for ind in result["indicators"]:
        db.add(DetectedIndicatorRow(scan_id=scan.id, label=ind["label"], severity=ind["severity"],
                                    description=ind["description"], weight=ind["weight"], triggered=ind["triggered"]))
    for i, rec in enumerate(result["recommendations"]):
        db.add(RecommendationRow(scan_id=scan.id, recommendation=rec, priority=i))

    rec = record_email(db, user.id, result, scan_id=scan.id, source=source)

    if result["classification"] != "safe":
        is_ato = result.get("category", "").startswith("Possible account takeover")
        db.add(ThreatEvent(
            user_id=user.id, event_type="credential" if is_ato else "phishing", source="email-pipeline",
            severity=result["severity"], title=f"{result['category']} — {result['classification'].replace('_', ' ').title()}",
            description=result["explanation"][:500],
            event_metadata={"target": scan.target, "riskScore": result["riskScore"], "scanId": scan.id,
                            "mitre": result.get("mitre", []), "from": result["email"].get("from_address", "")},
            status="active", timestamp=datetime.now(timezone.utc),
        ))
    db.commit()
    db.refresh(scan)
    if result["riskScore"] >= notifier.get_settings().ALERT_MIN_SCORE:
        background_tasks.add_task(notifier.alert_for_scan, scan.id)
    return {"scanId": scan.id, "emailRecordId": rec.id, **result}


@router.get("/records")
def list_records(limit: int = 50, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = (db.query(EmailRecord).filter(EmailRecord.user_id == user.id)
            .order_by(EmailRecord.created_at.desc()).limit(min(limit, 200)).all())
    return [{"id": r.id, "scanId": r.scan_id, "from": r.from_address, "displayName": r.from_display_name,
             "subject": r.subject, "category": r.category, "riskScore": r.risk_score,
             "classification": r.classification, "spf": r.spf, "dkim": r.dkim, "dmarc": r.dmarc,
             "links": r.link_count, "attachments": r.attachment_count, "mitre": r.mitre,
             "action": r.action_taken, "createdAt": r.created_at.isoformat()} for r in rows]


@router.get("/records/{record_id}")
def get_record(record_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    r = db.query(EmailRecord).filter(EmailRecord.id == record_id, EmailRecord.user_id == user.id).first()
    if not r:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Email record not found."}})
    return {"id": r.id, "scanId": r.scan_id, "messageId": r.message_id, "source": r.source,
            "from": r.from_address, "displayName": r.from_display_name, "subject": r.subject,
            "auth": {"spf": r.spf, "dkim": r.dkim, "dmarc": r.dmarc}, "originatingIp": r.originating_ip,
            "category": r.category, "riskScore": r.risk_score, "classification": r.classification,
            "mitre": r.mitre, "components": r.components, "details": r.details, "action": r.action_taken,
            "createdAt": r.created_at.isoformat()}


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------
class QuarantineAction(BaseModel):
    action: str          # release | quarantine | delete
    note: str = ""


@router.get("/quarantine")
def list_quarantine(status: str = "quarantined", limit: int = 20,
                    user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """status: quarantined | released | deleted | all"""
    q = db.query(EmailRecord).filter(EmailRecord.user_id == user.id)
    if status != "all":
        q = q.filter(EmailRecord.action_taken == status)
    rows = q.order_by(EmailRecord.created_at.desc()).limit(max(1, min(limit, 100))).all()
    counts = {k: db.query(EmailRecord).filter(EmailRecord.user_id == user.id, EmailRecord.action_taken == k).count()
              for k in ("quarantined", "released", "deleted")}
    return {"counts": counts, "items": [quarantine.to_dict(r) for r in rows]}


@router.post("/records/{record_id}/action")
def quarantine_action(record_id: str, body: QuarantineAction,
                      user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    r = db.query(EmailRecord).filter(EmailRecord.id == record_id, EmailRecord.user_id == user.id).first()
    if not r:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Email record not found."}})
    try:
        quarantine.change(r, body.action, by=user.email, note=body.note)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": {"code": "INVALID_ACTION", "message": str(exc)}})
    db.commit()
    db.refresh(r)
    return quarantine.to_dict(r)
