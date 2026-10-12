"""Activity (audit) log: your own account's security-relevant actions."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import AuditLog, User
from app.services import audit

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def list_audit(limit: int = 50, action: str = "", user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    q = db.query(AuditLog).filter((AuditLog.user_id == user.id) | (AuditLog.actor == user.email))
    if action:
        q = q.filter(AuditLog.action.like(f"{action[:40]}%"))
    rows = q.order_by(AuditLog.timestamp.desc()).limit(max(1, min(limit, 200))).all()
    return [audit.to_dict(r) for r in rows]
