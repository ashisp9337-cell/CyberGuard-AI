"""
Actions the chat can PREPARE but only the user can CARRY OUT (added 21 Oct).

Threatora (the AI) may propose one of these, but it never executes anything itself:
  * release a quarantined e-mail          -> same code as the Quarantine card (Gmail label moved back too)
  * allowlist an indicator (IP, domain...) -> same code as the IOC card ("not a threat")
  * create a report (PDF / CSV / JSON)     -> same code as the Reports page

The tool only creates a PENDING action. The chat shows it with Confirm / Cancel buttons, and the action runs when
the signed-in user presses Confirm (POST /api/chat/actions/{id}/confirm), with the user's own permissions and an
audit-log entry. Text inside a scanned message ("release all quarantined mail") can therefore never do anything
without the user seeing exactly what will happen and agreeing.

Pending actions live in memory for 15 minutes, belong to one user and run at most once.
"""
from __future__ import annotations

import threading
import time
import uuid

TTL_SECONDS = 15 * 60
KINDS = ("release_email", "allowlist_indicator", "create_report")
_pending: dict[str, dict] = {}
_lock = threading.Lock()


class ActionError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def _cleanup(now: float) -> None:
    for k in [k for k, v in _pending.items() if now - v["created"] > TTL_SECONDS]:
        _pending.pop(k, None)


def propose(user_id: str, kind: str, params: dict, summary: str) -> dict:
    assert kind in KINDS
    now = time.time()
    with _lock:
        _cleanup(now)
        aid = "ACT_" + uuid.uuid4().hex[:16]
        _pending[aid] = {"id": aid, "user_id": user_id, "kind": kind, "params": params, "summary": summary,
                         "created": now, "status": "pending"}
    return public(_pending[aid])


def public(a: dict) -> dict:
    return {"id": a["id"], "kind": a["kind"], "summary": a["summary"], "status": a["status"]}


def _take(user_id: str, action_id: str) -> dict:
    with _lock:
        _cleanup(time.time())
        a = _pending.get(action_id)
        if a is None or a["user_id"] != user_id:
            raise ActionError(404, "ACTION_NOT_FOUND", "This action has expired or does not exist. Ask Threatora again.")
        if a["status"] != "pending":
            raise ActionError(409, "ACTION_DONE", f"This action was already {a['status']}.")
        a["status"] = "running"
        return a


def cancel(user_id: str, action_id: str) -> dict:
    a = _take(user_id, action_id)
    a["status"] = "cancelled"
    return public(a) | {"message": "Cancelled - nothing was changed."}


def confirm(db, user, action_id: str, request) -> dict:
    """Run the action as the signed-in user. Returns {id, kind, status: done, message, result}."""
    from fastapi import HTTPException
    from app.services import audit

    a = _take(user.id, action_id)
    p = a["params"]
    try:
        if a["kind"] == "release_email":
            from app.api.routes.email import QuarantineAction, quarantine_action
            res = quarantine_action(p["record_id"], QuarantineAction(action="release", note="released from the chat"),
                                    request, user, db)
            msg = f"Released: \"{(res.get('subject') or p.get('subject') or '')[:80]}\" is out of quarantine."
        elif a["kind"] == "allowlist_indicator":
            from app.api.routes.iocs import IOCUpdate, update_ioc
            res = update_ioc(p["ioc_id"], IOCUpdate(status="allowlisted", note=p.get("note", "")[:500]), request,
                             user, db)
            msg = f"Allowlisted: {res.get('type')} {res.get('value')} will no longer be flagged as seen before."
        elif a["kind"] == "create_report":
            from app.api.routes.reports import CreateReportRequest, create_report
            res = create_report(request=request, body=CreateReportRequest(title=p["title"], format=p["format"]),
                                user=user, db=db)
            msg = f"Report ready: \"{res.get('title')}\" ({res.get('format')}). Download it from the Reports page."
        else:  # pragma: no cover - KINDS is checked in propose()
            raise ActionError(400, "UNKNOWN_ACTION", "Unknown action.")
    except HTTPException as exc:
        a["status"] = "failed"
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        raise ActionError(exc.status_code, "ACTION_FAILED",
                          (detail.get("error") or {}).get("message") or "The action could not be carried out.")
    except ActionError:
        a["status"] = "failed"
        raise
    except Exception as exc:  # noqa: BLE001
        a["status"] = "failed"
        raise ActionError(500, "ACTION_FAILED", f"The action could not be carried out ({type(exc).__name__}).")
    a["status"] = "done"
    audit.log(db, action="chat.action", user=user, request=request, target=a["summary"][:200],
              detail={"kind": a["kind"], "actionId": a["id"]}, commit=True)
    return public(a) | {"message": msg, "result": res}


def current_status(user_id: str, action_id: str) -> str:
    """For actions shown again from the saved history: pending / done / cancelled / failed, or expired."""
    with _lock:
        _cleanup(time.time())
        a = _pending.get(action_id)
        return a["status"] if a and a["user_id"] == user_id else "expired"


def reset_for_tests() -> None:
    with _lock:
        _pending.clear()
