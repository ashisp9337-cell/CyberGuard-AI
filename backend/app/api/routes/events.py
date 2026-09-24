from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import User, ThreatEvent

router = APIRouter(prefix="/api/events", tags=["events"])


class CreateEventRequest(BaseModel):
    eventType: str
    source: str = "system"
    severity: str = "low"
    title: str
    description: str = ""
    metadata: dict = {}


@router.post("", status_code=201)
def create_event(body: CreateEventRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    event = ThreatEvent(
        user_id=user.id, event_type=body.eventType, source=body.source, severity=body.severity,
        title=body.title, description=body.description, event_metadata=body.metadata,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return {"id": event.id, "eventType": event.event_type, "severity": event.severity, "title": event.title,
            "timestamp": event.timestamp.isoformat()}


@router.get("")
def list_events(limit: int = 50, severity: str | None = None,
                 user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(ThreatEvent).filter(ThreatEvent.user_id == user.id)
    if severity:
        q = q.filter(ThreatEvent.severity == severity)
    events = q.order_by(ThreatEvent.timestamp.desc()).limit(limit).all()
    return [{"id": e.id, "eventType": e.event_type, "source": e.source, "severity": e.severity,
             "title": e.title, "description": e.description, "status": e.status,
             "timestamp": e.timestamp.isoformat()} for e in events]

@router.get("/unread-count")
def unread_count(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    count = db.query(ThreatEvent).filter(ThreatEvent.user_id == user.id, ThreatEvent.status == "active").count()
    return {"count": count}


@router.post("/mark-all-read")
def mark_all_read(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    updated = (
        db.query(ThreatEvent)
        .filter(ThreatEvent.user_id == user.id, ThreatEvent.status == "active")
        .update({ThreatEvent.status: "acknowledged"}, synchronize_session=False)
    )
    db.commit()
    return {"markedRead": updated}
