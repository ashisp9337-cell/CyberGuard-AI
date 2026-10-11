"""
Auto-quarantine for dangerous emails.

When an analysed email scores QUARANTINE_MIN_SCORE or more (default 71 = high risk
/ critical) and AUTO_QUARANTINE is on, it is held in quarantine automatically:
    EmailRecord.action_taken = "quarantined"
    EmailRecord.details["quarantine"] = {"auto", "reason", "at", "history": [...]}

An analyst can then RELEASE it (it was safe), DELETE it (confirmed malicious),
or QUARANTINE it by hand. Every change is recorded with who / when / note, and
nothing is ever really erased, so there is a full audit trail.

Note: emails reach CYBERGUARD by upload or paste, so "quarantine" holds the
email inside CYBERGUARD. Moving it inside a real mailbox (Gmail / Outlook)
needs a mailbox connection (IMAP / Graph API), which can plug in here later.
"""
from datetime import datetime, timezone

from app.core.config import get_settings

ACTIONS = {"release": "released", "quarantine": "quarantined", "delete": "deleted"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def decide(result: dict) -> dict:
    """Set result["quarantine"] once: {"status": "quarantined"|"delivered", "auto", "reason", "at"}."""
    if result.get("quarantine"):
        return result["quarantine"]
    s = get_settings()
    score = result.get("riskScore", 0)
    if s.AUTO_QUARANTINE and score >= s.QUARANTINE_MIN_SCORE:
        q = {"status": "quarantined", "auto": True, "at": _now(),
             "reason": f"Risk {score}/100 ({result.get('classification', '').replace('_', ' ')}): "
                       f"{result.get('category') or result.get('threatType', 'dangerous email')}"}
    else:
        q = {"status": "delivered", "auto": True, "at": _now(), "reason": ""}
    result["quarantine"] = q
    return q


def apply_to_record(rec, result: dict) -> None:
    """Copy the decision onto a new EmailRecord row."""
    q = decide(result)
    rec.action_taken = "quarantined" if q["status"] == "quarantined" else "none"
    details = dict(rec.details or {})
    details["quarantine"] = {**q, "history": [{"action": q["status"], "by": "CYBERGUARD (automatic)",
                                               "at": q["at"], "note": q["reason"]}]}
    rec.details = details


def change(rec, action: str, by: str, note: str = "") -> dict:
    """Analyst action on a record: release | quarantine | delete."""
    if action not in ACTIONS:
        raise ValueError(f"action must be one of {', '.join(ACTIONS)}")
    details = dict(rec.details or {})
    q = dict(details.get("quarantine") or {"history": []})
    q["history"] = list(q.get("history", [])) + [{"action": ACTIONS[action], "by": by, "at": _now(),
                                                  "note": (note or "")[:500]}]
    q["status"] = ACTIONS[action]
    details["quarantine"] = q
    rec.details = details          # reassign so SQLAlchemy saves the JSON change
    rec.action_taken = ACTIONS[action]
    return q


def to_dict(rec) -> dict:
    q = (rec.details or {}).get("quarantine") or {}
    return {"id": rec.id, "scanId": rec.scan_id, "from": rec.from_address, "displayName": rec.from_display_name,
            "subject": rec.subject, "category": rec.category, "riskScore": rec.risk_score,
            "classification": rec.classification, "status": rec.action_taken,
            "reason": q.get("reason", ""), "history": q.get("history", []),
            "createdAt": rec.created_at.isoformat() if rec.created_at else None}
