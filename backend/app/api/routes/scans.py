from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import User, Scan
from app.services import mitre, scan_store

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _to_history_entry(s: Scan) -> dict:
    status_map = {"critical": "escalated", "high_risk": "flagged", "suspicious": "flagged",
                  "low_risk": "cleared", "safe": "cleared"}
    return {
        "scanId": s.id, "target": s.target, "targetType": s.input_type,
        "threatType": s.threat_type, "moduleId": s.module_id, "riskScore": s.risk_score,
        "severity": s.severity, "date": s.created_at.isoformat() if s.created_at else "",
        "status": status_map.get(s.classification, "completed"),
        "mitre": list(((s.result or {}).get("mitre") or []))[:4],
    }


@router.get("")
def list_scans(
    page: int = 1, pageSize: int = 20, module: str | None = None,
    severity: str | None = None, search: str | None = None,
    user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    q = db.query(Scan).filter(Scan.user_id == user.id)
    if module:
        q = q.filter(Scan.module_id == module)
    if severity:
        q = q.filter(Scan.severity == severity)
    if search:
        q = q.filter(Scan.target.ilike(f"%{search}%"))
    total = q.count()
    items = q.order_by(desc(Scan.created_at)).offset((page - 1) * pageSize).limit(pageSize).all()
    return {"items": [_to_history_entry(s) for s in items], "total": total, "page": page, "pageSize": pageSize}


@router.get("/{scan_id}")
def get_scan(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    s = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not s:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Scan not found."}})
    res = dict(s.result or {})
    if "mitreDetails" not in res and res.get("indicators"):
        # scans saved before MITRE mapping existed: map them now (read-only, nothing is written back)
        try:
            mitre.annotate(s.module_id, s.subtopic_id, res)
        except Exception:
            pass
    ind_mitre = {i.get("label"): scan_store.indicator_mitre(i) for i in res.get("indicators", []) if isinstance(i, dict)}
    return {
        "scanId": s.id, "moduleId": s.module_id, "subtopicId": s.subtopic_id,
        "subtopicTitle": s.subtopic_title, "target": s.target, "targetType": s.input_type,
        "riskScore": s.risk_score, "classification": s.classification,
        "confidenceScore": s.confidence, "detectionTime": s.completed_at.isoformat() if s.completed_at else s.created_at.isoformat(),
        "analysisEngine": s.analysis_engine, "threatType": s.threat_type, "severity": s.severity,
        "indicators": [{"id": i.id, "label": i.label, "description": i.description, "severity": i.severity,
                         "weight": i.weight, "triggered": i.triggered, "mitre": ind_mitre.get(i.label, [])}
                       for i in s.indicators],
        "explanation": s.explanation, "recommendations": [r.recommendation for r in sorted(s.recommendations, key=lambda r: r.priority)],
        "responseActions": res.get("responseActions", []), "quarantine": res.get("quarantine"),
        "status": s.status,
        **scan_store.detail_fields(res),
    }


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    s = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not s:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Scan not found."}})
    db.delete(s)
    db.commit()
    return {"success": True}
