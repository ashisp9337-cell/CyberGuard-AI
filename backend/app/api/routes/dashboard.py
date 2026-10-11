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
    """Threat detections per day, split by category.

    Only scans that came back suspicious or worse are counted (a "safe" scan
    is not a detection). The window ends TODAY, so today's scans are shown.
    """
    days = max(1, min(days, 90))
    today = datetime.now(timezone.utc).date()
    first_day = today - timedelta(days=days - 1)
    since = datetime.combine(first_day, datetime.min.time(), tzinfo=timezone.utc)

    scans = (db.query(Scan)
             .filter(Scan.user_id == user.id, Scan.created_at >= since,
                     Scan.classification.in_(["suspicious", "high_risk", "critical"]))
             .all())

    empty = {"phishing": 0, "impersonation": 0, "deepfake": 0, "accountTakeover": 0,
             "suspiciousUrls": 0, "networkThreats": 0, "malware": 0}
    buckets: dict[str, dict] = {}
    for i in range(days):
        d = (first_day + timedelta(days=i)).strftime("%b %d")
        buckets[d] = {"label": d, **empty}

    key_map = {"phishing": "phishing", "impersonation": "impersonation", "deepfake": "deepfake",
               "credential": "accountTakeover", "url-security": "suspiciousUrls", "cyber-threat": "networkThreats"}
    for s in scans:
        label = s.created_at.strftime("%b %d")
        if label not in buckets:
            continue
        key = key_map.get(s.module_id)
        # Malware is a cyber-threat subtopic, so give it its own series.
        if s.module_id == "cyber-threat" and s.subtopic_id == "malware-detection":
            key = "malware"
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



@router.get("/top-targets")
def top_targets(days: int = 30, limit: int = 6,
                user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Most targeted services (organisations impersonated/attacked) and accounts.

    Counts each threat scan (suspicious or worse) once per service/account
    it involves, over the last `days` days.
    """
    from app.services.targets import services_for, accounts_for

    days = max(1, min(days, 365))
    limit = max(1, min(limit, 20))
    since = datetime.now(timezone.utc) - timedelta(days=days)
    scans = (db.query(Scan)
             .filter(Scan.user_id == user.id, Scan.created_at >= since,
                     Scan.classification.in_(["suspicious", "high_risk", "critical"]))
             .order_by(Scan.created_at.desc())
             .limit(2000)
             .all())

    services: dict[str, dict] = {}
    accounts: dict[str, dict] = {}
    for s in scans:
        for svc in services_for(s):
            row = services.setdefault(svc["name"], {"name": svc["name"], "category": svc["category"],
                                                    "count": 0, "maxRisk": 0, "lastSeen": s.created_at.isoformat(),
                                                    "modules": set()})
            row["count"] += 1
            row["maxRisk"] = max(row["maxRisk"], s.risk_score or 0)
            row["modules"].add(MODULE_LABELS.get(s.module_id, s.module_id))
        for acc in accounts_for(s):
            row = accounts.setdefault(acc, {"name": acc, "count": 0, "maxRisk": 0,
                                            "lastSeen": s.created_at.isoformat()})
            row["count"] += 1
            row["maxRisk"] = max(row["maxRisk"], s.risk_score or 0)

    def top(rows: dict) -> list[dict]:
        ranked = sorted(rows.values(), key=lambda r: (-r["count"], -r["maxRisk"], r["name"]))[:limit]
        for r in ranked:
            if "modules" in r:
                r["modules"] = sorted(r["modules"])
        return ranked

    return {"days": days, "threatScans": len(scans), "services": top(services), "accounts": top(accounts)}

