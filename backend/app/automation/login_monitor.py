"""
Watcher 4 -- sign-ins to CyberGuard itself (Module 4: credential theft & account takeover, live).

Technology: every sign-in attempt is stored (login_events table) by the auth routes; this watcher wakes
up immediately and runs the same Credential Theft engine as a manual scan:
  * per IP address, last hour  -> many failed passwords (brute force), many accounts tried (spraying)
  * per account                -> failed OTP codes (someone HAS the password), success after failures,
                                  and the RBA risk model: sign-in from an IP / browser this account has
                                  never used (compared with its own earlier sign-ins)
A finding is saved like a manual scan + alert; the same finding is not repeated every round.
"""
from datetime import datetime, timedelta, timezone

from app.automation.engine import Watcher, get_state, save_and_alert, update_state

_monitor = None


def record_attempt(db, *, email: str, user_id: str | None, request, success: bool, stage: str) -> None:
    """Called by the auth routes. Never breaks a login, whatever happens."""
    try:
        from app.db.models import LoginEvent
        ip = (request.client.host if request is not None and request.client else "") or ""
        ua = (request.headers.get("user-agent", "") if request is not None else "")[:300]
        db.add(LoginEvent(email=(email or "").strip().lower()[:200], user_id=user_id, ip=ip, user_agent=ua,
                          success=success, stage=stage, timestamp=datetime.now(timezone.utc)))
        db.commit()
        if _monitor is not None:
            _monitor._wake.set()               # check right away instead of waiting for the next round
    except Exception:
        db.rollback()


def _line(e) -> str:
    ts = (e.timestamp if e.timestamp.tzinfo else e.timestamp.replace(tzinfo=timezone.utc)).strftime("%Y-%m-%d %H:%M:%S")
    ua = f' ua="{e.user_agent}"' if e.user_agent else ""
    if e.success:
        return f"{ts} sign-in success user={e.email} ip={e.ip}{ua}"
    if e.stage == "otp":
        return f"{ts} sign-in failed (wrong OTP, MFA failed) user={e.email} ip={e.ip}{ua}"
    if e.user_id is None:
        return f"{ts} sign-in failed for invalid user {e.email} ip={e.ip}{ua}"
    return f"{ts} sign-in failed (wrong password) user={e.email} ip={e.ip}{ua}"


class LoginMonitor(Watcher):
    name = "logins"
    title = "CyberGuard sign-ins"
    what = "Every sign-in to CyberGuard is checked live for brute force, password spraying, failed OTPs and unusual IP/browser."
    modules = ["Credential theft & account takeover"]
    technology = "Sign-in events stored by the backend + CyberGuard Credential engine (rules + RBA risk model)"
    interval_seconds = 60

    def __init__(self):
        super().__init__()
        global _monitor
        _monitor = self

    def check(self) -> dict:
        from app.db.database import SessionLocal
        from app.db.models import LoginEvent
        from app.detectors import account_takeover

        st = get_state(self.name)
        since = st.get("lastSeen")
        db = SessionLocal()
        try:
            q = db.query(LoginEvent)
            if since:
                q = q.filter(LoginEvent.timestamp > datetime.fromisoformat(since))
            new = q.order_by(LoginEvent.timestamp.asc()).limit(500).all()
            if not new:
                return {"checked": 0, "threats": 0, "note": "No new sign-ins"}
            hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
            month_ago = datetime.now(timezone.utc) - timedelta(days=30)
            groups = {}
            for e in new:
                groups[("ip", e.ip)] = None
                groups[("account", e.email)] = None
            signatures = st.get("signatures", {})
            threats, finding = 0, None
            for kind, key in groups:
                if kind == "ip":
                    rows = (db.query(LoginEvent).filter(LoginEvent.ip == key, LoginEvent.timestamp >= hour_ago)
                            .order_by(LoginEvent.timestamp.asc()).limit(300).all())
                else:
                    rows = (db.query(LoginEvent).filter(LoginEvent.email == key, LoginEvent.timestamp >= month_ago)
                            .order_by(LoginEvent.timestamp.desc()).limit(60).all())[::-1]
                result = account_takeover.analyze_event({}, "CyberGuard sign-in monitoring",
                                                        text="\n".join(_line(r) for r in rows))
                level = (result.get("modelAssessment") or {}).get("level", "low")
                sig = sorted(i["label"] for i in result["indicators"] if i["triggered"])
                skey = f"{kind}:{key}"
                self.record(f"{'IP' if kind == 'ip' else 'account'} {key} ({len(rows)} sign-in attempts)",
                            result["riskScore"], result["classification"])
                if (result["riskScore"] >= 51 or level != "low") and sig != signatures.get(skey):
                    target = f"Sign-ins from IP {key}" if kind == "ip" else f"Sign-ins to account {key}"
                    scan_id = save_and_alert(module_id="credential", subtopic_id="failed-logins" if kind == "ip"
                                             else "unusual-location", subtopic_title="CyberGuard sign-in monitoring",
                                             result=result, target=target, target_type="identity", source="logins",
                                             metadata={"events": len(rows)}, min_score=26)
                    if scan_id:
                        threats += 1
                        finding = f"{target}: {sig[0] if sig else 'risky pattern'} (score {result['riskScore']})"
                    signatures[skey] = sig
            if len(signatures) > 500:
                signatures = dict(list(signatures.items())[-500:])
            last = new[-1].timestamp
            last = last if last.tzinfo else last.replace(tzinfo=timezone.utc)
            update_state(self.name, lastSeen=last.isoformat(), signatures=signatures)
            return {"checked": len(new), "threats": threats, "finding": finding,
                    "note": f"{len(new)} new sign-in attempt(s) checked"}
        finally:
            db.close()
