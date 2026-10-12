"""
Audit log: who did what, when and from where. Written by the API routes, read in Settings -> Activity log.

    audit.log(db, action="incident.status", user=user, request=request, target=event.id,
              detail={"to": "resolved"})

Never stores passwords, codes or tokens. A failure to write the audit row never breaks the action itself.
"""
from datetime import datetime, timezone

from app.db.models import AuditLog

ACTIONS = {
    "auth.signup": "Account created",
    "auth.login": "Signed in",
    "auth.login_failed": "Failed sign-in",
    "auth.otp_failed": "Wrong sign-in code",
    "auth.google_login": "Signed in with Google",
    "auth.password_reset": "Password reset",
    "settings.update": "Settings changed",
    "incident.status": "Incident status changed",
    "incident.bulk": "Incidents updated in bulk",
    "incident.escalate": "Escalated to team",
    "quarantine.action": "Quarantine action",
    "automation.toggle": "Automatic protection switched",
    "automation.run": "Automatic check run",
    "contact.create": "Trusted contact added",
    "contact.update": "Trusted contact changed",
    "contact.delete": "Trusted contact removed",
    "ioc.update": "Indicator changed",
}


def log(db, *, action: str, user=None, actor: str | None = None, request=None, target: str = "",
        detail: dict | None = None, success: bool = True, commit: bool = False) -> None:
    try:
        ip = (request.client.host if request is not None and request.client else "") or ""
        ua = (request.headers.get("user-agent", "") if request is not None else "")[:300]
        db.add(AuditLog(user_id=getattr(user, "id", None), actor=(actor or getattr(user, "email", "") or "system")[:200],
                        action=action, target=str(target)[:500], detail=detail or {}, ip=ip, user_agent=ua,
                        success=success, timestamp=datetime.now(timezone.utc)))
        if commit:
            db.commit()
    except Exception:
        if commit:
            db.rollback()


def to_dict(row: AuditLog) -> dict:
    ts = row.timestamp if row.timestamp.tzinfo else row.timestamp.replace(tzinfo=timezone.utc)
    return {"id": row.id, "action": row.action, "label": ACTIONS.get(row.action, row.action), "actor": row.actor,
            "target": row.target, "detail": row.detail or {}, "ip": row.ip, "userAgent": row.user_agent,
            "success": row.success, "at": ts.isoformat()}
