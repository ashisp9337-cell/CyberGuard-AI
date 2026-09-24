"""
Live monitoring via Server-Sent Events. Streams real ThreatEvent rows as
they're inserted (by scans or the /api/events endpoint) — polled from the
database, not randomly generated.
"""
import asyncio
import json

from fastapi import APIRouter, Depends, Request
from sse_starlette.sse import EventSourceResponse
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.database import SessionLocal
from app.db.models import User, ThreatEvent

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])


@router.get("/stream")
async def stream(request: Request, user: User = Depends(get_current_user)):
    user_id = user.id

    async def event_generator():
        last_seen = None
        db: Session = SessionLocal()
        try:
            latest = db.query(ThreatEvent).filter(ThreatEvent.user_id == user_id).order_by(ThreatEvent.timestamp.desc()).first()
            last_seen = latest.timestamp if latest else None
            while True:
                if await request.is_disconnected():
                    break
                db.expire_all()
                q = db.query(ThreatEvent).filter(ThreatEvent.user_id == user_id)
                if last_seen:
                    q = q.filter(ThreatEvent.timestamp > last_seen)
                new_events = q.order_by(ThreatEvent.timestamp.asc()).all()
                for e in new_events:
                    last_seen = e.timestamp
                    yield {"event": "threat_event", "data": json.dumps({
                        "id": e.id, "severity": e.severity, "title": e.title,
                        "description": e.description, "status": e.status,
                        "timestamp": e.timestamp.isoformat(), "category": e.event_type,
                    })}
                yield {"event": "heartbeat", "data": "ping"}
                await asyncio.sleep(3)
        finally:
            db.close()

    return EventSourceResponse(event_generator())
