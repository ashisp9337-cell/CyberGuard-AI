"""
Incidents: the SOC workflow on top of threat events.

Every HIGH or CRITICAL threat event is an incident. Its workflow state is kept in
event_metadata["incident"] (no new table, no migration):

    {"status": "open" | "investigating" | "resolved" | "false_positive",
     "history": [{"status", "by", "at", "note"}, ...],
     "resolvedAt": iso-time or None}

An event with no "incident" entry yet counts as "open".

(ThreatEvent.status is a different thing: it is the read/unread flag behind the
notification bell, so it is left alone.)
"""
from datetime import datetime, timezone

INCIDENT_SEVERITIES = ("high", "critical")
STATUSES = ("open", "investigating", "resolved", "false_positive")
CLOSED = ("resolved", "false_positive")
STATUS_LABELS = {"open": "Open", "investigating": "Investigating", "resolved": "Resolved",
                 "false_positive": "False positive"}


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def state(event) -> dict:
    inc = (event.event_metadata or {}).get("incident") or {}
    return {"status": inc.get("status", "open"), "history": inc.get("history", []),
            "resolvedAt": inc.get("resolvedAt")}


def change_status(event, new_status: str, by: str, note: str = "") -> dict:
    """Move an incident to a new status and record who did it, when, and why."""
    if new_status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    now = datetime.now(timezone.utc).isoformat()
    meta = dict(event.event_metadata or {})
    inc = dict(meta.get("incident") or {"status": "open", "history": []})
    old = inc.get("status", "open")
    inc["history"] = list(inc.get("history", [])) + [
        {"from": old, "status": new_status, "by": by, "at": now, "note": (note or "")[:500]}]
    inc["status"] = new_status
    inc["resolvedAt"] = now if new_status in CLOSED else None
    meta["incident"] = inc
    event.event_metadata = meta          # reassign so SQLAlchemy saves the JSON change
    return state(event)


def to_dict(event) -> dict:
    meta = event.event_metadata or {}
    st = state(event)
    alerts = meta.get("alerts", [])
    return {
        "id": event.id,
        "title": event.title,
        "severity": event.severity,
        "category": meta.get("category", event.event_type),
        "riskScore": meta.get("riskScore", 0),
        "target": meta.get("target", ""),
        "scanId": meta.get("scanId"),
        "createdAt": _aware(event.timestamp).isoformat(),
        "status": st["status"],
        "statusLabel": STATUS_LABELS[st["status"]],
        "resolvedAt": st["resolvedAt"],
        "history": st["history"],
        "alertedVia": sorted({a["channel"] for a in alerts if a.get("status") == "sent"}),
        # True when this threat reuses a URL/domain/IP/sender/file already seen in an earlier threat
        "seenBefore": int(meta.get("iocHits", 0) or 0) > 0,
        # MITRE ATT&CK techniques behind this threat, each with a plain-language explanation
        "mitre": _mitre_brief(meta.get("mitre") or []),
    }


def _mitre_brief(ids) -> list:
    from app.services import mitre
    try:
        return mitre.brief([i for i in ids if isinstance(i, str)][:6])
    except Exception:
        return []


def summary(events: list) -> dict:
    counts = {s: 0 for s in STATUSES}
    resolve_minutes = []
    for e in events:
        st = state(e)
        counts[st["status"]] += 1
        if st["status"] == "resolved" and st["resolvedAt"]:
            done = datetime.fromisoformat(st["resolvedAt"])
            resolve_minutes.append((_aware(done) - _aware(e.timestamp)).total_seconds() / 60)
    return {
        "total": len(events),
        "counts": counts,
        "active": counts["open"] + counts["investigating"],
        "openCritical": sum(1 for e in events if e.severity == "critical" and state(e)["status"] == "open"),
        # Mean time to resolve: a standard SOC metric.
        "mttrMinutes": round(sum(resolve_minutes) / len(resolve_minutes), 1) if resolve_minutes else None,
    }