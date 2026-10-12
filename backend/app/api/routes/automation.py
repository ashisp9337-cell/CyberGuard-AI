"""Automatic protection: see which watchers run, switch them on/off, or trigger a check now."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.automation import manager
from app.core.config import get_settings
from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import User
from app.services import audit

router = APIRouter(prefix="/api/automation", tags=["automation"])


class ToggleIn(BaseModel):
    enabled: bool


def _get(name: str):
    w = manager.WATCHERS.get(name)
    if w is None:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Unknown watcher."}})
    return w


@router.get("/status")
def status(user: User = Depends(get_current_user)):
    return {"enabled": get_settings().AUTOMATION_ENABLED, "watchers": manager.status()}


@router.post("/{name}/toggle")
def toggle(name: str, body: ToggleIn, request: Request, user: User = Depends(get_current_user),
           db: Session = Depends(get_db)):
    w = _get(name)
    w.set_enabled(body.enabled)
    audit.log(db, action="automation.toggle", user=user, request=request, target=w.title,
              detail={"enabled": body.enabled}, commit=True)
    return w.describe()


@router.post("/{name}/run")
def run_now(name: str, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    w = _get(name)
    w.run_once()
    audit.log(db, action="automation.run", user=user, request=request, target=w.title,
              detail={"error": w.status.get("lastError")}, success=not w.status.get("lastError"), commit=True)
    return w.describe()
