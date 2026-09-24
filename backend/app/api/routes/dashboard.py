from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import User, Scan, ThreatEvent

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

MODULE_LABELS = {
    "phishing": "Phishing", "deepfake": "Deepfake", "impersonation": "Impersonation",
    "credential": "Account Takeover", "url-security": "Malicious URLs", "cyber-threat": "Cyber Threats",
}
MODULE_COLORS = {
    "phishing": "#f97316", "deepfake": "#a855f7", "impersonation": "#ef4444",
    "credential": "#eab308", "url-security": "#3b82f6", "cyber-threat": "#22c55e",
}


@router.get("/overview")
def overview(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    base = db.query(Scan).filter(Scan.user_id == user.id)
    total_scans = base.count()
    active_threats = base.filter(Scan.classification.in_(["high_risk", "critical"])).count()
    critical_threats = base.filter(Scan.classification == "critical").count()

    avg_risk = db.query(func.avg(Scan.risk_score)).filter(Scan.user_id == user.id).scalar() or 0
    security_score = max(0, min(100, round(100 - avg_risk)))
    status = "PROTECTED" if security_score >= 75 else ("AT RISK" if security_score >= 40 else "CRITICAL")

    counts = {
        "critical": base.filter(Scan.severity == "critical").count(),
        "high": base.filter(Scan.severity == "high").count(),
        "medium": base.filter(Scan.severity == "medium").count(),
        "low": base.filter(Scan.severity == "low").count(),
    }

    return {
        "securityScore": security_score, "status": status, "activeThreats": active_threats,
        "totalScans": total_scans, "criticalThreats": critical_threats, **counts,
    }


@router.get("/activity")
def activity(days: int = 14, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    scans = db.query(Scan).filter(Scan.user_id == user.id, Scan.created_at >= since).all()
    buckets: dict[str, dict] = {}
    for i in range(days):
        d = (since + timedelta(days=i)).strftime("%b %d")
        buckets[d] = {"label": d, "phishing": 0, "deepfake": 0, "accountTakeover": 0, "suspiciousUrls": 0, "networkThreats": 0, "malware": 0}
    for s in scans:
        label = s.created_at.strftime("%b %d")
        if label not in buckets:
            continue
        key_map = {"phishing": "phishing", "deepfake": "deepfake", "credential": "accountTakeover",
                   "url-security": "suspiciousUrls", "cyber-threat": "networkThreats", "impersonation": "malware"}
        key = key_map.get(s.module_id)
        if key:
            buckets[label][key] += 1
    return list(buckets.values())


@router.get("/threat-distribution")
def threat_distribution(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = (
        db.query(Scan.module_id, func.count(Scan.id))
        .filter(Scan.user_id == user.id, Scan.classification.in_(["suspicious", "high_risk", "critical"]))
        .group_by(Scan.module_id).all()
    )
    return [
        {"name": MODULE_LABELS.get(mod, mod), "value": count, "color": MODULE_COLORS.get(mod, "#64748b")}
        for mod, count in rows
    ]


@router.get("/live-feed")
def live_feed(limit: int = 20, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    events = db.query(ThreatEvent).filter(ThreatEvent.user_id == user.id).order_by(ThreatEvent.timestamp.desc()).limit(limit).all()
    return [
        {"id": e.id, "severity": e.severity, "title": e.title, "description": e.description,
         "target": e.event_metadata.get("target", ""), "riskScore": e.event_metadata.get("riskScore", 0),
         "status": e.status, "timestamp": e.timestamp.isoformat(), "category": e.event_metadata.get("category", e.event_type)}
        for e in events
    ]
