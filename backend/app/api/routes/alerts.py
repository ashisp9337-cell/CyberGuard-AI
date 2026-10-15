"""Alert channels: see what is configured and send a test alert. ADMIN ONLY (they message the owner's phone/email)."""
from fastapi import APIRouter, Depends, Request

from app.core.dependencies import require_admin
from app.core.rate_limit import limiter
from app.db.models import User
from app.services import notifier

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("/status")
def status(user: User = Depends(require_admin)):
    """Which channels are set up in .env, and the score that triggers an alert."""
    return notifier.channel_status()


@router.post("/test")
@limiter.limit("3/minute")
def send_test(request: Request, user: User = Depends(require_admin)):
    """Send a sample alert to every configured channel, so you can check the setup."""
    message = notifier.build_alert({
        "id": "TEST-ALERT", "threatType": "Test alert (no real threat)", "classification": "high_risk",
        "severity": "high", "riskScore": 80, "target": f"Sent by {user.email}",
        "explanation": "This is a test message from CYBERGUARD. If you can read it, alerts are working.",
        "indicators": [{"label": "Example indicator", "triggered": True, "weight": 10}],
        "responseActions": [{"title": "No action needed - this is a test", "priority": "immediate"}],
        "mitre": [],
    })
    return {"channels": notifier.channel_status(), "results": notifier.send_all(message)}