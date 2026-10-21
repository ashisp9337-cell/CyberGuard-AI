"""
Real database-backed tools Threatora can call to answer questions about
the user's own CyberGuard data — scans, alerts, reports, settings,
account info, and overall security posture. Uses Gemini's automatic
function calling: the model decides when a question needs live data and
calls these functions itself; we never manually parse the user's
question for keywords.

SECURITY: every function here is built bound to one specific,
already-authenticated user_id (via build_tools()) — there is no
parameter the model could pass to read another user's data. Sensitive
fields (password_hash, google_id, reset tokens, raw report file paths)
are never included in any tool's return value.
"""
import functools

from sqlalchemy import func
from sqlalchemy.orm import Session

import re

from app.db.models import IOC, Scan, DetectedIndicatorRow, RecommendationRow, ThreatEvent, Report, UserSettings, User

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-f:]+:[0-9a-f:]*$", re.I)
_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.I)


UNTRUSTED_KEYS = ("target", "explanation", "detector_explanation", "description", "title", "main_reasons", "value")


def build_tools(db: Session, user_id: str, ctx=None) -> list:
    """Returns the list of callables to hand to Gemini as tools for this
    one request, each closed over this specific user's id and db session.

    ctx (chat_service.ChatContext, optional): when given, every result is made safe for the AI before Gemini sees
    it - private details are masked and text that came from scanned messages is marked as untrusted data - and the
    check_message_or_link tool is added (it needs ctx to put masked details back before scanning)."""

    def get_recent_scans(limit: int = 5) -> list[dict]:
        """Get the user's most recent security scans, newest first.

        Use this when the user asks about their recent scans, their last
        scan, or scan history in general (e.g. "what was my last scan",
        "show my recent activity").

        Args:
            limit: Maximum number of scans to return (default 5, max 20).

        Returns:
            A list of scans, each with: scan_id, module, subtopic, target,
            risk_score (0-100), classification, severity, date. Empty list
            if the user hasn't run any scans yet.
        """
        limit = max(1, min(limit, 20))
        scans = (
            db.query(Scan)
            .filter(Scan.user_id == user_id)
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "scan_id": s.id, "module": s.module_id, "subtopic": s.subtopic_title,
                "target": s.target[:200], "risk_score": s.risk_score,
                "classification": s.classification, "severity": s.severity,
                "date": s.created_at.isoformat() if s.created_at else None,
            }
            for s in scans
        ]

    def get_scan_details(scan_id: str) -> dict:
        """Get the full details of one specific scan by its ID, including
        why it was flagged and what indicators were detected.

        Use this after get_recent_scans (or if the user gives/confirms a
        scan ID) when they ask to explain, elaborate on, or dig into a
        specific scan's result.

        Args:
            scan_id: The scan's ID, e.g. "SCN_abc123def456".

        Returns:
            Full scan detail: module, subtopic, target, risk_score,
            classification, severity, confidence, analysis_engine,
            explanation, indicators (list of {label, description,
            severity, triggered}), recommendations (list of strings),
            and date. Returns {"error": "..."} if no scan with that ID
            exists for this user.
        """
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user_id).first()
        if not scan:
            return {"error": f"No scan found with id {scan_id} for this account."}
        indicators = db.query(DetectedIndicatorRow).filter(DetectedIndicatorRow.scan_id == scan.id).all()
        recommendations = (
            db.query(RecommendationRow).filter(RecommendationRow.scan_id == scan.id)
            .order_by(RecommendationRow.priority).all()
        )
        return {
            "scan_id": scan.id, "module": scan.module_id, "subtopic": scan.subtopic_title,
            "target": scan.target, "risk_score": scan.risk_score, "classification": scan.classification,
            "severity": scan.severity, "confidence": scan.confidence, "analysis_engine": scan.analysis_engine,
            "explanation": scan.explanation,
            "indicators": [
                {"label": i.label, "description": i.description, "severity": i.severity, "triggered": i.triggered}
                for i in indicators
            ],
            "recommendations": [r.recommendation for r in recommendations],
            "date": scan.created_at.isoformat() if scan.created_at else None,
        }

    def get_security_overview() -> dict:
        """Get the user's overall security summary: total scans, threats
        by severity, and a rough security score.

        Use this for broad questions like "how am I doing", "how many
        threats have I had", or "what's my security score".

        Returns:
            total_scans, active_threats, critical_threats,
            security_score (0-100, higher is better), and a breakdown of
            scan counts by severity (critical/high/medium/low).
        """
        base = db.query(Scan).filter(Scan.user_id == user_id)
        total_scans = base.count()
        active_threats = base.filter(Scan.classification.in_(["suspicious", "high_risk", "critical"])).count()
        avg_risk = db.query(func.avg(Scan.risk_score)).filter(Scan.user_id == user_id).scalar() or 0
        security_score = max(0, min(100, round(100 - avg_risk)))
        return {
            "total_scans": total_scans,
            "active_threats": active_threats,
            "critical_threats": base.filter(Scan.severity == "critical").count(),
            "security_score": security_score,
            "severity_breakdown": {
                "critical": base.filter(Scan.severity == "critical").count(),
                "high": base.filter(Scan.severity == "high").count(),
                "medium": base.filter(Scan.severity == "medium").count(),
                "low": base.filter(Scan.severity == "low").count(),
            },
        }

    def get_threat_distribution() -> list[dict]:
        """Get a breakdown of how many flagged (suspicious or worse)
        scans fall under each detection module — which kind of threat
        the user encounters most.

        Use this for questions like "what type of threats do I get the
        most", "am I targeted more by phishing or malicious URLs", etc.

        Returns:
            A list of {module, count}, sorted by count descending.
        """
        rows = (
            db.query(Scan.module_id, func.count(Scan.id))
            .filter(Scan.user_id == user_id, Scan.classification.in_(["suspicious", "high_risk", "critical"]))
            .group_by(Scan.module_id)
            .order_by(func.count(Scan.id).desc())
            .all()
        )
        return [{"module": mod, "count": count} for mod, count in rows]

    def get_alerts(limit: int = 10) -> list[dict]:
        """Get the user's recent security alerts/notifications (the same
        events shown in Live Monitoring and the notification bell).

        Use this when the user asks about alerts, notifications, or
        "what's going on" / "anything I should know about".

        Args:
            limit: Maximum number of alerts to return (default 10, max 30).

        Returns:
            A list of alerts, each with: title, description, severity,
            status ("active" means unread), timestamp. Empty list if
            there are no alerts.
        """
        limit = max(1, min(limit, 30))
        events = (
            db.query(ThreatEvent).filter(ThreatEvent.user_id == user_id)
            .order_by(ThreatEvent.timestamp.desc()).limit(limit).all()
        )
        return [
            {
                "title": e.title, "description": e.description, "severity": e.severity,
                "status": e.status, "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            }
            for e in events
        ]

    def get_reports(limit: int = 10) -> list[dict]:
        """Get the user's generated security reports.

        Use this when the user asks about their reports, exported
        summaries, or what documents they've generated.

        Args:
            limit: Maximum number of reports to return (default 10).

        Returns:
            A list of reports, each with: title, format (PDF/CSV/JSON),
            size_kb, created date. Empty list if none have been generated.
        """
        limit = max(1, min(limit, 30))
        reports = (
            db.query(Report).filter(Report.user_id == user_id)
            .order_by(Report.created_at.desc()).limit(limit).all()
        )
        return [
            {"title": r.title, "format": r.format, "size_kb": round(r.size_kb, 1),
             "date": r.created_at.isoformat() if r.created_at else None}
            for r in reports
        ]

    def get_settings() -> dict:
        """Get the user's current platform settings — detection
        sensitivity and notification preferences.

        Use this when the user asks what their current settings are,
        e.g. "what's my sensitivity set to", "do I have email
        notifications on".

        Returns:
            sensitivity (conservative = alerts for critical only, balanced = high risk and critical,
            aggressive = suspicious and above), notifications_enabled,
            email_notifications. Never includes secret keys.
        """
        s = db.query(UserSettings).filter(UserSettings.user_id == user_id).first()
        if not s:
            return {"sensitivity": "balanced", "notifications_enabled": True, "email_notifications": True}
        return {
            "sensitivity": s.sensitivity,
            "notifications_enabled": s.notifications_enabled,
            "email_notifications": s.email_notifications,
        }

    def get_account_info() -> dict:
        """Get the user's own basic account info: name, email, how they
        signed up, and when their account was created.

        Use this for questions like "when did I create my account" or
        "how did I sign up". Never returns a password or any credential.

        Returns:
            name, email, provider ("password" or "google"), created_at,
            last_login.
        """
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"error": "Account not found."}
        return {
            "name": user.name, "email": user.email, "provider": user.provider,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
        }

    def lookup_threat_indicator(value: str) -> dict:
        """Check whether an IP address, domain, link, sender e-mail address or file hash has been seen before in
        one of the user's risky scans (CyberGuard's own indicator-of-compromise memory).

        Use this for questions like "have we seen this IP before?", "is this domain in my threat list?",
        "was this sender flagged earlier?".

        Args:
            value: The IP address, domain, URL, e-mail address or SHA-256 file hash to look up.

        Returns:
            found (true/false), checked (what was looked up), and matches: a list of {type, value, status
            ("active" = known bad, "allowlisted" = marked safe by the user), times_seen, highest_risk,
            first_seen, last_seen, last_scan_id}.
        """
        from app.services import ioc as ioc_service
        v = (value or "").strip().strip("<>\"'")
        if not v:
            return {"error": "Give an IP, domain, link, e-mail address or file hash."}
        low = v.lower()
        keys: set[tuple[str, str]] = set()
        if _HASH_RE.match(low):
            keys.add(("sha256", low))
        elif _IP_RE.match(low):
            keys.add(("ip", low))
        elif "@" in low and "/" not in low:
            keys.add(("email", low))
            keys.add(("domain", ioc_service._site(low.split("@", 1)[1])))
        else:
            url = low if "://" in low else None
            host = (low.split("://", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0])
            if url:
                keys.add(("url", low))
            keys.add(("domain", host))
            keys.add(("domain", ioc_service._site(host)))
        rows = []
        for t, val in keys:
            rows += db.query(IOC).filter(IOC.user_id == user_id, IOC.ioc_type == t, IOC.value == val).all()
        seen, matches = set(), []
        for r in sorted(rows, key=lambda r: -(r.max_risk or 0)):
            if r.id in seen:
                continue
            seen.add(r.id)
            matches.append({"type": r.ioc_type, "value": r.value, "status": r.status, "times_seen": r.times_seen,
                            "highest_risk": r.max_risk,
                            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                            "last_scan_id": r.last_scan_id})
        return {"found": any(m["status"] == "active" for m in matches), "checked": sorted(v for _, v in keys),
                "matches": matches[:10]}

    def domain_registration_info(domain: str) -> dict:
        """Look up when a website's domain was registered (public domain registry, RDAP) and by which registrar.
        Brand-new domains (days or weeks old) are a strong phishing sign; real banks and shops use old domains.

        Use this for questions like "how old is this website?", "when was example.com registered?".

        Args:
            domain: A domain or link, e.g. "sbi-kyc-update.top" or "https://example.com/login".

        Returns:
            domain (the registrable part that was checked), registered (date), age (in words), age_days,
            registrar, expires, trusted_official_site (true if CyberGuard knows it as an official site),
            hosting_platform (shared hosting such as vercel.app: its age says nothing about one page), or error.
        """
        from app.detectors import domain_facts, domain_model, trusted_domains
        host = (domain or "").strip().lower().split("://", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0]
        if not host or "." not in host:
            return {"error": "Give a domain such as example.com."}
        parts = domain_model.site_parts(host)
        if parts["ip"]:
            return {"error": "That is an IP address, not a domain - IP addresses have no registration date."}
        site = parts["site"]
        facts = domain_facts.lookup(site)
        age = domain_facts.age_days(facts) if facts.get("ok") else None
        out = {"domain": site, "trusted_official_site": trusted_domains.is_trusted(f"https://{site}/"),
               "hosting_platform": parts["platform"] or (site if site in trusted_domains.USER_CONTENT_DOMAINS else None)}
        if not facts.get("ok"):
            return {**out, "error": facts.get("error") or "The registry has no record (the domain may not exist "
                                                           "or may already be taken down)."}
        return {**out, "registered": facts.get("created"), "age": domain_facts.describe_age(age),
                "age_days": int(age) if age is not None else None, "registrar": facts.get("registrar"),
                "expires": facts.get("expires")}

    def explain_mitre_technique(technique_id: str) -> dict:
        """Explain a MITRE ATT&CK technique ID (e.g. T1566.002) in plain language, as CyberGuard maps its
        detections to MITRE ATT&CK.

        Args:
            technique_id: The technique ID, e.g. "T1566.002" or "T1660".

        Returns:
            id, name, tactic, explanation and the official MITRE page url, or error if CyberGuard does not use it.
        """
        from app.services import mitre
        tid = (technique_id or "").strip().upper()
        if tid not in mitre.CATALOGUE:
            return {"error": f"{tid or 'That ID'} is not one of the techniques CyberGuard maps detections to.",
                    "url": mitre.url_for(tid) if re.match(r"^T\d{4}(\.\d{3})?$", tid) else None}
        return mitre.describe([tid])[0]

    def check_message_or_link(content: str) -> dict:
        """Scan a link, SMS, chat message or e-mail with CyberGuard's own detectors and save it to the user's
        Scan History.

        Use this whenever the user pastes a link / message / e-mail, or asks whether something is safe, a scam,
        phishing, fake or real. Pass the COMPLETE pasted content exactly as written (keep placeholders such as
        [PHONE_1] unchanged). Do not use it for general questions.

        Args:
            content: The full link or message text to check.

        Returns:
            scan_id, risk_score (0-100), verdict (safe / low_risk / suspicious / high_risk / critical), severity,
            threat_type, checked_as (which check was used), main_reasons, recommended_actions and
            detector_explanation. The verdict comes from the detectors: report it as it is.
        """
        from app.services import chat_scan
        raw = ctx.masker.unmask(content or "")
        summary = chat_scan.run(db, user_id, raw, ctx.scan_cache)
        if "scan_id" in summary and summary not in ctx.scans:
            ctx.scans.append(summary)
        return summary

    tools = [get_recent_scans, get_scan_details, get_security_overview,
             get_threat_distribution, get_alerts, get_reports, get_settings, get_account_info,
             lookup_threat_indicator, domain_registration_info, explain_mitre_technique]
    if ctx is None:
        return tools
    return [_safe_for_ai(f, ctx) for f in tools + [check_message_or_link]]


def _safe_for_ai(fn, ctx):
    """Wraps a tool so its result is masked and scanned text is marked untrusted (same name/arguments/docs)."""
    from app.services.chat_safety import untrusted

    def mark(obj):
        if isinstance(obj, dict):
            return {k: (untrusted(v) if k in UNTRUSTED_KEYS and isinstance(v, str) and v else
                        [untrusted(x) if isinstance(x, str) else mark(x) for x in v]
                        if k in UNTRUSTED_KEYS and isinstance(v, list) else mark(v)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [mark(x) for x in obj]
        return obj

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        # The AI only knows the placeholders ([EMAIL_1]@gmail.com ...): put the real values back before looking up.
        args = [ctx.masker.unmask(a) if isinstance(a, str) else a for a in args]
        kwargs = {k: ctx.masker.unmask(v) if isinstance(v, str) else v for k, v in kwargs.items()}
        return ctx.masker.mask_obj(mark(fn(*args, **kwargs)))
    return wrapper