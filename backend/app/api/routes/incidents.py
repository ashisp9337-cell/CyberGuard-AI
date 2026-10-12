"""Incident workflow: list incidents, see counts, change status (open -> investigating -> resolved)."""
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import User, Scan, ThreatEvent
from app.services import audit, incidents as inc, notifier

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


class StatusChange(BaseModel):
    status: str
    note: str = ""


class BulkStatusChange(BaseModel):
    status: str
    note: str = ""
    ids: list[str] = []          # the incidents ticked in the UI
    scope: str | None = None     # or "active" = every open + investigating incident


def _incident_events(db: Session, user: User, limit: int = 500) -> list[ThreatEvent]:
    return (db.query(ThreatEvent)
            .filter(ThreatEvent.user_id == user.id, ThreatEvent.severity.in_(inc.INCIDENT_SEVERITIES))
            .order_by(ThreatEvent.timestamp.desc()).limit(limit).all())


@router.get("")
def list_incidents(status: str = "active", limit: int = 20,
                   user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """status: active (open + investigating) | open | investigating | resolved | false_positive | all"""
    rows = [inc.to_dict(e) for e in _incident_events(db, user)]
    if status == "active":
        rows = [r for r in rows if r["status"] in ("open", "investigating")]
    elif status != "all":
        rows = [r for r in rows if r["status"] == status]
    return rows[:max(1, min(limit, 100))]


@router.get("/summary")
def incident_summary(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return inc.summary(_incident_events(db, user))


@router.patch("/{event_id}")
def update_incident(event_id: str, body: StatusChange, request: Request,
                    user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    event = db.get(ThreatEvent, event_id)
    # 404 (not 403) for someone else's incident, so ids can't be probed.
    if event is None or event.user_id != user.id or event.severity not in inc.INCIDENT_SEVERITIES:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Incident not found."}})
    try:
        inc.change_status(event, body.status, by=user.email, note=body.note)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": {"code": "INVALID_STATUS", "message": str(exc)}})
    audit.log(db, action="incident.status", user=user, request=request, target=event.title,
              detail={"incidentId": event.id, "to": body.status, "note": body.note[:200]})
    db.commit()
    db.refresh(event)
    return inc.to_dict(event)


@router.post("/bulk")
def bulk_update(body: BulkStatusChange, request: Request, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    """Set many incidents to one status at once (Select all -> Resolve, etc.)."""
    if body.status not in inc.STATUSES:
        raise HTTPException(status_code=422, detail={"error": {"code": "INVALID_STATUS",
                            "message": f"status must be one of {', '.join(inc.STATUSES)}"}})
    events = _incident_events(db, user, limit=1000)          # only this user's incidents, ever
    if body.scope == "active":
        targets = [e for e in events if inc.state(e)["status"] in ("open", "investigating")]
    else:
        wanted = set(body.ids[:1000])
        targets = [e for e in events if e.id in wanted]
    changed = 0
    for e in targets:
        if inc.state(e)["status"] != body.status:
            inc.change_status(e, body.status, by=user.email, note=body.note)
            changed += 1
    audit.log(db, action="incident.bulk", user=user, request=request, target=f"{changed} incident(s)",
              detail={"to": body.status, "matched": len(targets), "changed": changed})
    db.commit()
    return {"matched": len(targets), "changed": changed, "status": body.status,
            "summary": inc.summary(_incident_events(db, user))}


class EscalateRequest(BaseModel):
    scanId: str
    note: str = ""


def _send_escalation(event_id: str, scan_id: str, by: str, note: str) -> None:
    """Alert the security team now. A person decided this matters, so the score limit and the
    repeat-alert rule are skipped. The outcome is saved on the incident."""
    from app.db.database import SessionLocal
    db = SessionLocal()
    try:
        scan, event = db.get(Scan, scan_id), db.get(ThreatEvent, event_id)
        if scan is None or event is None:
            return
        result = scan.result or {}
        message = notifier.build_alert({
            "id": scan.id, "moduleId": scan.module_id, "threatType": f"ESCALATED by {by}: {scan.threat_type}",
            "classification": scan.classification, "severity": event.severity, "riskScore": scan.risk_score,
            "target": scan.target,
            "explanation": (f"Analyst note: {note}. " if note else "") + (scan.explanation or ""),
            "indicators": result.get("indicators", []), "responseActions": result.get("responseActions", []),
            "mitre": result.get("mitre", []),
        })
        outcome = notifier.send_all(message)
        meta = dict(event.event_metadata or {})
        meta["alerts"] = list(meta.get("alerts", [])) + [dict(o, trigger="escalation") for o in outcome]
        event.event_metadata = meta
        db.commit()
    finally:
        db.close()


@router.post("/escalate")
def escalate(body: EscalateRequest, background_tasks: BackgroundTasks, request: Request,
             user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """'Escalate to Team' on a scan result: make it an incident and alert the security team."""
    scan = db.get(Scan, body.scanId)
    if scan is None or scan.user_id != user.id:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Scan not found."}})

    event = next((e for e in db.query(ThreatEvent).filter(ThreatEvent.user_id == user.id)
                  .order_by(ThreatEvent.timestamp.desc()).limit(500)
                  if (e.event_metadata or {}).get("scanId") == scan.id), None)
    if event is None:                         # safe scans have no event yet
        event = ThreatEvent(
            user_id=user.id, event_type=scan.module_id, source="escalation", severity="high",
            title=f"{scan.threat_type} — Escalated by user", description=(scan.explanation or "")[:500],
            event_metadata={"target": scan.target, "riskScore": scan.risk_score, "category": scan.module_id,
                            "scanId": scan.id, "originalSeverity": scan.severity},
            status="active", timestamp=datetime.now(timezone.utc))
        db.add(event)
        db.flush()
    elif event.severity not in inc.INCIDENT_SEVERITIES:  # make it show up as an incident
        meta = dict(event.event_metadata or {})
        meta["originalSeverity"] = event.severity
        event.event_metadata = meta
        event.severity = "high"

    current = inc.state(event)["status"]
    new_status = "open" if current in inc.CLOSED else current          # re-open if it had been closed
    inc.change_status(event, new_status, by=user.email, note=("Escalated to team. " + body.note).strip())
    meta = dict(event.event_metadata or {})
    meta["escalated"] = {"by": user.email, "at": datetime.now(timezone.utc).isoformat(), "note": body.note[:500]}
    event.event_metadata = meta
    audit.log(db, action="incident.escalate", user=user, request=request, target=scan.target,
              detail={"scanId": scan.id, "incidentId": event.id, "note": body.note[:200]})
    db.commit()
    db.refresh(event)

    channels = notifier.channel_status()
    background_tasks.add_task(_send_escalation, event.id, scan.id, user.email, body.note)
    return {"incident": inc.to_dict(event),
            "alertChannels": [c for c in ("telegram", "email", "whatsapp") if channels.get(c)]}

