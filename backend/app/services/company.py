"""(9 Nov) Company mode: who may join this CyberGuard, invites, and the facts the Employees page shows.

Rules (checked for password sign-up AND Google sign-in):
  * an address in ADMIN_EMAILS may always join (the owner);
  * COMPANY_EMAIL_DOMAINS empty -> anyone may join (the single-PC setup, exactly as before);
  * an address of one of the company's domains may join by itself;
  * anyone else needs a valid invite from an administrator (unused, not revoked, not expired).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from app.core.config import get_settings
from app.db.models import Invite

ONLINE_MINUTES = 5            # "online now" = used CyberGuard in the last 5 minutes
SEEN_EVERY_SECONDS = 60       # last-seen is written at most once a minute per account


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(t: datetime | None) -> datetime | None:
    if t is None:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def domain_of(email: str) -> str:
    return (email or "").rsplit("@", 1)[-1].strip().lower()


def open_invite(db, email: str) -> Invite | None:
    """The newest usable invite for this address, or None."""
    email = (email or "").strip().lower()
    rows = (db.query(Invite).filter(Invite.email == email, Invite.used_at.is_(None), Invite.revoked.is_(False))
            .order_by(Invite.created_at.desc()).all())
    return next((r for r in rows if _aware(r.expires_at) > _now()), None)


def may_join(db, email: str) -> tuple[bool, Invite | None]:
    """(allowed, invite that allows it or None)."""
    s = get_settings()
    email = (email or "").strip().lower()
    if email in s.admin_email_list or not s.company_domain_list:
        return True, None
    if domain_of(email) in s.company_domain_list:
        return True, None
    inv = open_invite(db, email)
    return (inv is not None), inv


def not_invited_message() -> str:
    s = get_settings()
    who = s.COMPANY_NAME.strip() or "this company"
    doms = ", ".join("@" + d for d in s.company_domain_list)
    return (f"This CyberGuard belongs to {who}. Sign up with your company e-mail ({doms}), or ask your administrator "
            "for an invite.")


def use_invite(db, invite: Invite | None, user) -> None:
    """Mark the invite used and give the account the invited role."""
    if invite is None:
        return
    invite.used_at = _now()
    if (invite.role or "user") == "admin":
        user.role = "admin"


def new_invite(db, *, email: str, role: str, invited_by: str | None) -> Invite:
    email = email.strip().lower()
    for old in db.query(Invite).filter(Invite.email == email, Invite.used_at.is_(None), Invite.revoked.is_(False)):
        old.revoked = True                          # one open invite per address: the newest one counts
    inv = Invite(email=email, role=role if role in ("user", "admin") else "user", invited_by=invited_by,
                 expires_at=_now() + timedelta(days=max(1, int(get_settings().INVITE_DAYS))))
    db.add(inv)
    db.flush()
    return inv


def invite_status(inv: Invite) -> str:
    if inv.used_at is not None:
        return "used"
    if inv.revoked:
        return "revoked"
    return "expired" if _aware(inv.expires_at) <= _now() else "open"


def touch_last_seen(db, user, request) -> None:
    """Record when / from where this account was last active (at most once a minute; never breaks a request)."""
    try:
        last = _aware(user.last_seen_at)
        if last is not None and (_now() - last).total_seconds() < SEEN_EVERY_SECONDS:
            return
        user.last_seen_at = _now()
        user.last_ip = ((request.client.host if request is not None and request.client else "") or "")[:64]
        user.last_user_agent = (request.headers.get("user-agent", "") if request is not None else "")[:300]
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()


def is_online(user) -> bool:
    last = _aware(user.last_seen_at)
    return last is not None and (_now() - last).total_seconds() <= ONLINE_MINUTES * 60


_BROWSERS = [("Edge", r"Edg/"), ("Opera", r"OPR/"), ("Brave", r"Brave"), ("Chrome", r"Chrome/"),
             ("Firefox", r"Firefox/"), ("Safari", r"Safari/")]
_SYSTEMS = [("Windows", r"Windows"), ("Android", r"Android"), ("iPhone", r"iPhone|iPad"), ("macOS", r"Mac OS X"),
            ("Linux", r"Linux")]


def browser_of(ua: str | None) -> str:
    """'Chrome on Windows' from a user-agent string ('' when unknown)."""
    ua = ua or ""
    if not ua:
        return ""
    b = next((n for n, rx in _BROWSERS if re.search(rx, ua)), "")
    o = next((n for n, rx in _SYSTEMS if re.search(rx, ua)), "")
    return " on ".join(x for x in (b, o) if x) or ua[:40]
