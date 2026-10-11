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
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models import Scan, DetectedIndicatorRow, RecommendationRow, ThreatEvent, Report, UserSettings, User


def build_tools(db: Session, user_id: str) -> list:
    """Returns the list of callables to hand to Gemini as tools for this
    one request, each closed over this specific user's id and db session."""

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
            sensitivity (low/balanced/high), notifications_enabled,
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

    return [
        get_recent_scans, get_scan_details, get_security_overview,
        get_threat_distribution, get_alerts, get_reports, get_settings, get_account_info,
    ]