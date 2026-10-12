"""MITRE ATT&CK view: which attacker techniques CyberGuard has seen in your scans, explained in plain language."""
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import Scan, User
from app.services import mitre

router = APIRouter(prefix="/api/mitre", tags=["mitre"])


@router.get("/techniques")
def techniques(user: User = Depends(get_current_user)):
    """Every technique CyberGuard can map to, with its tactic and explanation."""
    return mitre.brief(list(mitre.CATALOGUE.keys()))


@router.get("/summary")
def summary(days: int = Query(30, ge=1, le=365), user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Techniques seen in your own scans over the last `days` days, most frequent first."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (db.query(Scan).filter(Scan.user_id == user.id, Scan.created_at >= since, Scan.classification != "safe")
            .order_by(desc(Scan.created_at)).limit(2000).all())
    counts: Counter = Counter()
    last_seen: dict[str, str] = {}
    modules: dict[str, set] = {}
    examples: dict[str, dict] = {}
    mapped = 0
    for s in rows:
        res = s.result or {}
        ids = res.get("mitre")
        if ids is None or ("mitreDetails" not in res and res.get("indicators")):
            try:
                ids = mitre.map_result(s.module_id, s.subtopic_id, dict(res))   # older scans: map on the fly
            except Exception:
                ids = []
        if ids:
            mapped += 1
        for tid in ids or []:
            counts[tid] += 1
            ts = (s.created_at if s.created_at.tzinfo else s.created_at.replace(tzinfo=timezone.utc)).isoformat()
            last_seen.setdefault(tid, ts)
            modules.setdefault(tid, set()).add(s.module_id)
            examples.setdefault(tid, {"scanId": s.id, "target": (s.target or "")[:120], "riskScore": s.risk_score})
    techs = []
    for tid, n in counts.most_common():
        d = mitre.brief([tid])[0]
        techs.append(d | {"count": n, "lastSeen": last_seen.get(tid), "modules": sorted(modules.get(tid, [])),
                          "example": examples.get(tid)})
    tactics: Counter = Counter()
    for t in techs:
        tactics[(t["tactic"] or "Other").split(",")[0].strip()] += t["count"]
    return {"days": days, "mappedScans": mapped,
            "techniques": techs, "tactics": [{"tactic": k, "count": v} for k, v in tactics.most_common()]}
