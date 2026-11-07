from fastapi import HTTPException, APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import User, UserSettings

router = APIRouter(prefix="/api/settings", tags=["settings"])


class UpdateSettingsRequest(BaseModel):
    sensitivity: str | None = None
    notificationsEnabled: bool | None = None
    emailNotifications: bool | None = None
    integrationSettings: dict | None = None
    automaticAlerts: str | None = None      # (4 Nov) "critical" (default) | "same": alerts for the watchers' findings


def _to_out(s: UserSettings) -> dict:
    return {
        "sensitivity": s.sensitivity, "notificationsEnabled": s.notifications_enabled,
        "emailNotifications": s.email_notifications, "integrationSettings": s.integration_settings,
        "automaticAlerts": "same" if (s.integration_settings or {}).get("automaticAlerts") == "same" else "critical",
        "updatedAt": s.updated_at.isoformat() if s.updated_at else "",
    }


@router.get("")
def get_settings_(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    s = db.query(UserSettings).filter(UserSettings.user_id == user.id).first()
    if not s:
        s = UserSettings(user_id=user.id)
        db.add(s)
        db.commit()
        db.refresh(s)
    return _to_out(s)


@router.put("")
def update_settings(body: UpdateSettingsRequest, request: Request, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    s = db.query(UserSettings).filter(UserSettings.user_id == user.id).first()
    if not s:
        s = UserSettings(user_id=user.id)
        db.add(s)
    if body.sensitivity is not None:
        level = {"low": "conservative", "high": "aggressive"}.get(body.sensitivity, body.sensitivity)  # old names
        if level not in ("conservative", "balanced", "aggressive"):
            raise HTTPException(status_code=422, detail={"error": {"code": "INVALID_SENSITIVITY",
                                "message": "sensitivity must be conservative, balanced or aggressive"}})
        s.sensitivity = level
    if body.notificationsEnabled is not None:
        s.notifications_enabled = body.notificationsEnabled
    if body.emailNotifications is not None:
        s.email_notifications = body.emailNotifications
    if body.integrationSettings is not None:
        # Never persist secret API keys coming from the client — settings
        # only store non-secret integration toggles/labels.
        safe = {k: v for k, v in body.integrationSettings.items() if "key" not in k.lower() and "secret" not in k.lower()}
        s.integration_settings = safe
    if body.automaticAlerts is not None:
        if body.automaticAlerts not in ("critical", "same"):
            raise HTTPException(status_code=422, detail={"error": {"code": "INVALID_AUTOMATIC_ALERTS",
                                "message": "automaticAlerts must be critical or same"}})
        s.integration_settings = {**(s.integration_settings or {}), "automaticAlerts": body.automaticAlerts}
    from app.services import audit
    audit.log(db, action="settings.update", user=user, request=request,
              detail={k: v for k, v in body.model_dump(exclude_none=True).items() if k != "integrationSettings"})
    db.commit()
    db.refresh(s)
    return _to_out(s)
