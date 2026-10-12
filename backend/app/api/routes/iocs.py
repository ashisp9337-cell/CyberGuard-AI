"""Indicators of Compromise: list, summary, allowlist (false positive) and blocklist export."""
import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import IOC, User
from app.services import audit, ioc as ioc_service

router = APIRouter(prefix="/api/iocs", tags=["iocs"])
TYPES = ("url", "domain", "ip", "email", "sha256")


class IOCUpdate(BaseModel):
    status: str                 # active | allowlisted
    note: str = ""


@router.get("")
def list_iocs(type: str = "", q: str = "", status: str = "active", limit: int = 100,
              user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(IOC).filter(IOC.user_id == user.id)
    if type in TYPES:
        query = query.filter(IOC.ioc_type == type)
    if status in ("active", "allowlisted"):
        query = query.filter(IOC.status == status)
    if q.strip():
        query = query.filter(IOC.value.ilike(f"%{q.strip().lower()[:100]}%"))
    rows = query.order_by(IOC.last_seen.desc()).limit(max(1, min(limit, 500))).all()
    return [ioc_service.to_dict(r) for r in rows]


@router.get("/summary")
def summary(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(IOC).filter(IOC.user_id == user.id).all()
    active = [r for r in rows if r.status == "active"]
    return {"total": len(active), "allowlisted": len(rows) - len(active),
            "byType": {t: sum(1 for r in active if r.ioc_type == t) for t in TYPES},
            "repeat": sum(1 for r in active if r.times_seen > 1),
            "top": [ioc_service.to_dict(r) for r in sorted(active, key=lambda r: (-r.times_seen, -r.max_risk))[:5]]}


@router.patch("/{ioc_id}")
def update_ioc(ioc_id: str, body: IOCUpdate, request: Request,
               user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.get(IOC, ioc_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Indicator not found."}})
    if body.status not in ("active", "allowlisted"):
        raise HTTPException(status_code=422, detail={"error": {"code": "INVALID_STATUS",
                                                               "message": "status must be active or allowlisted"}})
    old = row.status
    row.status, row.note = body.status, body.note[:500]
    audit.log(db, action="ioc.update", user=user, request=request, target=f"{row.ioc_type} {row.value[:200]}",
              detail={"from": old, "to": body.status})
    db.commit()
    db.refresh(row)
    return ioc_service.to_dict(row)


@router.get("/export.csv")
def export_csv(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Blocklist of active indicators (for a firewall, mail filter or SIEM)."""
    rows = db.query(IOC).filter(IOC.user_id == user.id, IOC.status == "active").order_by(IOC.last_seen.desc()).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "times_seen", "max_risk", "modules", "first_seen", "last_seen"])
    for r in rows:
        d = ioc_service.to_dict(r)
        # a leading = + - @ would turn into a formula when the file is opened in Excel: neutralise it
        value = ("'" + d["value"]) if d["value"][:1] in "=+-@" else d["value"]
        w.writerow([d["type"], value, d["timesSeen"], d["maxRisk"], "|".join(d["modules"]), d["firstSeen"], d["lastSeen"]])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="cyberguard_iocs.csv"'})
