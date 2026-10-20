"""Quarantined downloads: list them and restore one (moves the file back to where it was).
ADMIN ONLY: these are files on the owner's own PC. Nothing here can delete a file."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.automation import file_quarantine
from app.core.config import get_settings
from app.core.dependencies import require_admin
from app.db.database import get_db
from app.db.models import User
from app.services import audit

router = APIRouter(prefix="/api/quarantine", tags=["quarantine"])


@router.get("/files")
def list_files(status: str = "quarantined", user: User = Depends(require_admin)):
    """status: quarantined | restored | all"""
    if status not in ("quarantined", "restored", "all"):
        raise HTTPException(status_code=422, detail={"error": {"code": "INVALID_STATUS",
                                                               "message": "status must be quarantined, restored or all"}})
    s = get_settings()
    items = file_quarantine.list_files(status)
    return {"enabled": s.FILE_QUARANTINE, "minScore": s.FILE_QUARANTINE_MIN_SCORE,
            "counts": {k: len(file_quarantine.list_files(k)) for k in ("quarantined", "restored")},
            "items": items[:100]}


@router.post("/files/{qid}/restore")
def restore_file(qid: str, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        item = file_quarantine.restore(qid, by=user.email)
    except file_quarantine.QuarantineError as exc:
        raise HTTPException(status_code=404 if "unknown" in str(exc) else 409,
                            detail={"error": {"code": "RESTORE_FAILED", "message": str(exc)}})
    except OSError as exc:
        raise HTTPException(status_code=500, detail={"error": {"code": "RESTORE_FAILED",
                                                               "message": f"Could not move the file back: {exc}"}})
    audit.log(db, action="quarantine.file_restore", user=user, request=request, target=item["name"],
              detail={"quarantineId": qid, "restoredTo": item["restoredTo"], "sha256": item["sha256"]}, commit=True)
    return item
