"""(9 Nov) Company mode: the Employees page (administrators only) and invites.

Every employee and every administrator still uses ALL detection modules for their own protection; these routes only
add the company view: who works with CyberGuard, when they were last active, their scans and threats, and the
administrator's controls (invite, make admin, disable, sign out everywhere). Every change is written to the audit log.
"""
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.dependencies import is_admin, require_admin
from app.core.rate_limit import limiter
from app.db.database import get_db
from app.db.models import AuditLog, Invite, LoginEvent, Scan, User
from app.services import audit, company

router = APIRouter(prefix="/api/company", tags=["company"])

THREAT_SCORE = 71             # high risk and critical = a threat on the Employees page


def _err(code: str, message: str, status_code: int = 400):
    return HTTPException(status_code=status_code, detail={"error": {"code": code, "message": message}})


def _iso(t):
    return t.isoformat() if t else None


def _owner_ids(db) -> set[str]:
    """Accounts the web page can never demote or disable: ADMIN_EMAILS (or, without it, the first account)."""
    s = get_settings()
    if s.admin_email_list:
        return {u.id for u in db.query(User.id).filter(func.lower(User.email).in_(s.admin_email_list))}
    from app.automation.engine import owner_user_id
    oid = owner_user_id(db)
    return {oid} if oid else set()


@router.get("/public")
def public_info():
    """For the sign-up page (no login): the company name and whether sign-up is limited to its domains."""
    s = get_settings()
    return {"name": s.COMPANY_NAME.strip(), "domains": s.company_domain_list,
            "restricted": bool(s.company_domain_list)}


def _row(u: User, admin: bool, owner: bool, st: dict) -> dict:
    return {"id": u.id, "name": u.name, "email": u.email, "role": "admin" if admin else "employee", "owner": owner,
            "signIn": "Google" if (u.provider == "google" or u.google_id) else "Password",
            "active": u.is_active is not False, "online": company.is_online(u) and u.is_active is not False,
            "createdAt": _iso(u.created_at), "lastLogin": _iso(u.last_login), "lastSeen": _iso(u.last_seen_at),
            "lastIp": u.last_ip or "", "lastBrowser": company.browser_of(u.last_user_agent),
            "scans": st.get("scans", 0), "threats": st.get("threats", 0), "lastScan": _iso(st.get("lastScan")),
            "failedSignIns7d": st.get("failed", 0), "devices": st.get("devices", 0)}


def _stats(db) -> dict[str, dict]:
    st: dict[str, dict] = {}
    for uid, n, threats, last in db.query(Scan.user_id, func.count(Scan.id),
                                          func.count(Scan.id).filter(Scan.risk_score >= THREAT_SCORE),
                                          func.max(Scan.created_at)).group_by(Scan.user_id):
        st[uid] = {"scans": int(n), "threats": int(threats), "lastScan": last}
    since = datetime.now(timezone.utc) - timedelta(days=7)
    emails = dict(db.query(func.lower(User.email), User.id).all())
    for email, n in (db.query(func.lower(LoginEvent.email), func.count(LoginEvent.id))
                     .filter(LoginEvent.success.is_(False), LoginEvent.timestamp >= since)
                     .group_by(func.lower(LoginEvent.email))):
        if email in emails:
            st.setdefault(emails[email], {})["failed"] = int(n)
    try:                                           # Part 2 (agent devices) - absent until its table exists
        from app.db.models import Device
        for uid, n in db.query(Device.user_id, func.count(Device.id)).filter(Device.revoked.is_(False)).group_by(Device.user_id):
            st.setdefault(uid, {})["devices"] = int(n)
    except Exception:  # noqa: BLE001
        db.rollback()
    return st


@router.get("/employees")
def employees(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    owners = _owner_ids(db)
    st = _stats(db)
    users = db.query(User).order_by(User.created_at.asc()).all()
    rows = [_row(u, is_admin(u, db), u.id in owners, st.get(u.id, {})) for u in users]
    invites = db.query(Invite).filter(Invite.used_at.is_(None), Invite.revoked.is_(False)).all()
    return {"company": {"name": get_settings().COMPANY_NAME.strip(), "domains": get_settings().company_domain_list},
            "you": user.id, "employees": rows,
            "summary": {"total": len(rows), "online": sum(r["online"] for r in rows),
                        "admins": sum(r["role"] == "admin" for r in rows), "disabled": sum(not r["active"] for r in rows),
                        "openInvites": sum(company.invite_status(i) == "open" for i in invites),
                        "threats": sum(r["threats"] for r in rows)}}


def _target(uid: str, db) -> User:
    u = db.get(User, uid)
    if u is None:
        raise _err("NOT_FOUND", "No such employee.", 404)
    return u


@router.get("/employees/{uid}")
def employee_detail(uid: str, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """One employee: the newest scans and sign-in history (what the administrator may review for security)."""
    u = _target(uid, db)
    scans = (db.query(Scan).filter(Scan.user_id == u.id).order_by(Scan.created_at.desc()).limit(25).all())
    signins = (db.query(AuditLog).filter(AuditLog.user_id == u.id, AuditLog.action.like("auth.%"))
               .order_by(AuditLog.timestamp.desc()).limit(25).all())
    return {"id": u.id, "name": u.name, "email": u.email,
            "scans": [{"id": s.id, "module": s.module_id, "subtopic": s.subtopic_title, "target": (s.target or "")[:120],
                       "risk": s.risk_score, "classification": s.classification, "threatType": s.threat_type,
                       "at": _iso(s.created_at), "source": (s.input_metadata or {}).get("source", "")} for s in scans],
            "signIns": [{"action": a.action, "success": a.success, "ip": a.ip,
                         "browser": company.browser_of(a.user_agent), "at": _iso(a.timestamp)} for a in signins]}


class RoleIn(BaseModel):
    role: str


class ActiveIn(BaseModel):
    active: bool


def _guard(target: User, me: User, db, what: str) -> None:
    if target.id == me.id:
        raise _err("NOT_YOURSELF", f"You cannot {what} your own account here.", 409)
    if target.id in _owner_ids(db):
        raise _err("OWNER", f"This account is a company owner (ADMIN_EMAILS); its access is set on the server, not here.", 409)


@router.post("/employees/{uid}/role")
@limiter.limit("30/minute")
def set_role(uid: str, body: RoleIn, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if body.role not in ("admin", "employee"):
        raise _err("BAD_ROLE", "Role must be admin or employee.", 422)
    u = _target(uid, db)
    _guard(u, user, db, "change the role of")
    old = "admin" if (u.role or "").lower() == "admin" else "employee"
    u.role = "admin" if body.role == "admin" else "user"
    audit.log(db, action="company.role", user=user, request=request, target=u.email, detail={"from": old, "to": body.role})
    db.commit()
    return {"id": u.id, "role": body.role}


@router.post("/employees/{uid}/active")
@limiter.limit("30/minute")
def set_active(uid: str, body: ActiveIn, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    u = _target(uid, db)
    _guard(u, user, db, "disable or enable")
    u.is_active = bool(body.active)
    if not body.active:                          # every session of a disabled account ends at once
        u.session_version = int(u.session_version or 0) + 1
    audit.log(db, action="company.enable" if body.active else "company.disable", user=user, request=request, target=u.email)
    db.commit()
    return {"id": u.id, "active": u.is_active}


@router.post("/employees/{uid}/sign-out")
@limiter.limit("30/minute")
def sign_out_everywhere(uid: str, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    u = _target(uid, db)
    if u.id == user.id:
        raise _err("NOT_YOURSELF", "Use Logout to sign yourself out.", 409)
    u.session_version = int(u.session_version or 0) + 1
    audit.log(db, action="company.sign_out", user=user, request=request, target=u.email)
    db.commit()
    return {"id": u.id, "signedOut": True}


# ---- invites -----------------------------------------------------------------------------------------------
class InviteIn(BaseModel):
    email: EmailStr
    role: str = "employee"


def _invite_out(i: Invite) -> dict:
    return {"id": i.id, "email": i.email, "role": "admin" if i.role == "admin" else "employee",
            "status": company.invite_status(i), "createdAt": _iso(i.created_at), "expiresAt": _iso(i.expires_at),
            "usedAt": _iso(i.used_at)}


@router.get("/invites")
def list_invites(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(Invite).order_by(Invite.created_at.desc()).limit(100).all()
    return {"invites": [_invite_out(i) for i in rows]}


@router.post("/invites", status_code=201)
@limiter.limit("30/minute")
def create_invite(body: InviteIn, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    email = str(body.email).strip().lower()
    if db.query(User).filter(func.lower(User.email) == email).first():
        raise _err("EMAIL_EXISTS", "This person already has an account.", 409)
    inv = company.new_invite(db, email=email, role="admin" if body.role == "admin" else "user", invited_by=user.id)
    audit.log(db, action="company.invite", user=user, request=request, target=email, detail={"role": body.role})
    db.commit()
    s = get_settings()
    link = f"{s.APP_BASE_URL.rstrip('/')}/signup?email={quote(email, safe='@')}"
    who = s.COMPANY_NAME.strip() or "your company"
    sent = "not_sent"
    try:
        from app.services import notifier
        r = notifier.send_mail([email], f"You are invited to CyberGuard ({who})",
                               f"{user.name} invited you to {who}'s CyberGuard - the security workspace that checks "
                               f"messages, links, files and your PC for threats.\n\nCreate your account: {link}\n"
                               f"(sign up with this e-mail address, or use Google sign-in). The invite is valid for "
                               f"{max(1, int(s.INVITE_DAYS))} days.\n\nIf you did not expect this, ignore this e-mail.")
        sent = r.get("status", "not_sent")
    except Exception:  # noqa: BLE001 -- the invite works without the e-mail; the admin can share the link
        pass
    return {**_invite_out(inv), "link": link, "emailStatus": sent}


@router.delete("/invites/{iid}")
def revoke_invite(iid: str, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    inv = db.get(Invite, iid)
    if inv is None:
        raise _err("NOT_FOUND", "No such invite.", 404)
    inv.revoked = True
    audit.log(db, action="company.invite_revoked", user=user, request=request, target=inv.email)
    db.commit()
    return _invite_out(inv)
