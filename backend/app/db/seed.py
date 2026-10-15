"""
Optional development/demo seed data. NEVER run against a production
database unless you explicitly want demo content in it.

    python -m app.db.seed
"""
from datetime import datetime, timedelta, timezone

from app.core.security import hash_password
from app.db.database import Base, engine, SessionLocal
from app.db.models import User, UserSettings, Scan, DetectedIndicatorRow, RecommendationRow, ThreatEvent
from app.services.risk_scoring import classify_risk, severity_from_classification


def run():
    from app.core.config import get_settings
    if get_settings().is_production:
        raise SystemExit("Refusing to seed: ENVIRONMENT=production. The demo account has a published password.")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == "demo@cyberguard.local").first()
        if existing:
            print("Demo user already exists — skipping seed.")
            return

        user = User(
            name="Demo Analyst", email="demo@cyberguard.local",
            password_hash=hash_password("DemoPass123"), provider="password",
            is_verified=True, last_login=datetime.now(timezone.utc),
        )
        db.add(user)
        db.flush()
        db.add(UserSettings(user_id=user.id))

        demo_scans = [
            ("phishing", "email-analysis", "Email Analysis", 82, "Suspicious PayPal-style email requesting password reset"),
            ("url-security", "lookalike-domain", "Lookalike Domain", 91, "http://paypa1-secure-login.tk/verify"),
            ("credential", "failed-logins", "Failed Logins", 65, "12 failed login attempts from new device"),
            ("cyber-threat", "network-traffic", "Network Traffic", 20, "Routine outbound traffic, within baseline"),
            ("impersonation", "management-impersonation", "Management Impersonation", 74, "Urgent wire transfer request from 'CEO'"),
        ]
        for module_id, subtopic_id, subtopic_title, score, target in demo_scans:
            classification = classify_risk(score)
            severity = severity_from_classification(classification)
            scan = Scan(
                user_id=user.id, module_id=module_id, subtopic_id=subtopic_id, subtopic_title=subtopic_title,
                input_type="text", target=target, status="completed", risk_score=score,
                classification=classification, severity=severity, confidence=80.0,
                threat_type=subtopic_title, analysis_engine="CYBERGUARD Demo Seed",
                explanation="[DEMO/SEED DATA] This scan result was inserted by the development seed script, not a live analysis.",
                result={}, completed_at=datetime.now(timezone.utc) - timedelta(hours=len(demo_scans)),
            )
            db.add(scan)
            db.flush()
            db.add(DetectedIndicatorRow(scan_id=scan.id, label="Seeded indicator", severity=severity,
                                         description="Demo indicator for seed data.", weight=score, triggered=True))
            db.add(RecommendationRow(scan_id=scan.id, recommendation="This is demo data — review real scans for actionable guidance.", priority=0))

        db.add(ThreatEvent(
            user_id=user.id, event_type="phishing", source="seed", severity="high",
            title="[DEMO] Suspicious login attempt blocked", description="Seed data for local development.",
            event_metadata={"category": "auth"}, timestamp=datetime.now(timezone.utc),
        ))

        db.commit()
        print("Seeded demo user: demo@cyberguard.local / DemoPass123 (development/demo data only)")
    finally:
        db.close()


if __name__ == "__main__":
    run()
