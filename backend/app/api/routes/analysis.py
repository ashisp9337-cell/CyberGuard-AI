import json
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import User, Scan, DetectedIndicatorRow, RecommendationRow, ThreatEvent
from app.schemas.analysis import RunScanRequest
from app.services.analysis_service import run_scan

router = APIRouter(prefix="/api/analysis", tags=["analysis"])
settings = get_settings()

ALLOWED_EXTENSIONS = {".eml", ".msg", ".txt", ".png", ".jpg", ".jpeg", ".mp4", ".mov", ".avi", ".mkv", ".webm", ".mp3", ".wav", ".pdf"}


def _save_upload(file: UploadFile) -> tuple[str, str]:
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail={"error": {"code": "UNSUPPORTED_FILE_TYPE", "message": f"File type {ext} is not supported."}})
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    safe_name = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(settings.UPLOAD_DIR, safe_name)
    content = file.file.read()
    max_bytes = settings.MAX_UPLOAD_MB * 1024 * 1024
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail={"error": {"code": "FILE_TOO_LARGE", "message": f"File exceeds {settings.MAX_UPLOAD_MB}MB limit."}})
    with open(path, "wb") as f:
        f.write(content)
    os.chmod(path, 0o600)
    return path, file.filename or safe_name


@router.post("/scan")
async def scan(
    moduleId: str = Form(...),
    subtopicId: str = Form(...),
    subtopicTitle: str = Form("Analysis"),
    textInput: str | None = Form(None),
    urlInput: str | None = Form(None),
    extraFieldValues: str | None = Form(None),
    file: UploadFile | None = File(None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    extra_fields = {}
    if extraFieldValues:
        try:
            extra_fields = json.loads(extraFieldValues)
        except json.JSONDecodeError:
            extra_fields = {}

    file_path, file_name = (None, None)
    if file is not None and file.filename:
        file_path, file_name = _save_upload(file)

    result = run_scan(
        module_id=moduleId, subtopic_id=subtopicId, subtopic_title=subtopicTitle,
        text_input=textInput, url_input=urlInput, file_path=file_path, file_name=file_name,
        extra_field_values=extra_fields,
    )

    target = result.pop("_target", file_name or urlInput or textInput or "submission")
    target_type = result.pop("_target_type", "text")

    scan_row = Scan(
        user_id=user.id, module_id=moduleId, subtopic_id=subtopicId, subtopic_title=subtopicTitle,
        input_type=target_type, target=str(target)[:500], input_metadata=extra_fields,
        status="completed", risk_score=result["riskScore"], classification=result["classification"],
        severity=result["severity"], confidence=result["confidenceScore"],
        threat_type=result["threatType"], analysis_engine=result["analysisEngine"],
        explanation=result["explanation"], result=result, completed_at=datetime.now(timezone.utc),
    )
    db.add(scan_row)
    db.flush()

    for ind in result["indicators"]:
        db.add(DetectedIndicatorRow(
            scan_id=scan_row.id, label=ind["label"], severity=ind["severity"],
            description=ind["description"], weight=ind["weight"], triggered=ind["triggered"],
        ))
    for i, rec in enumerate(result["recommendations"]):
        db.add(RecommendationRow(scan_id=scan_row.id, recommendation=rec, priority=i))

    # Feed Live Monitoring / notifications: only notable scans become
    # threat events (a "safe" result shouldn't page anyone).
    if result["classification"] != "safe":
        db.add(ThreatEvent(
            user_id=user.id, event_type=moduleId, source="scan", severity=result["severity"],
            title=f"{result['threatType']} — {result['classification'].replace('_', ' ').title()}",
            description=result["explanation"][:500],
            event_metadata={"target": scan_row.target, "riskScore": result["riskScore"], "category": moduleId, "scanId": scan_row.id},
            status="active", timestamp=datetime.now(timezone.utc),
        ))

    db.commit()
    db.refresh(scan_row)

    return {
        "scanId": scan_row.id, "moduleId": moduleId, "subtopicId": subtopicId,
        "subtopicTitle": subtopicTitle, "target": scan_row.target, "targetType": target_type,
        "riskScore": result["riskScore"], "classification": result["classification"],
        "confidenceScore": result["confidenceScore"], "detectionTime": scan_row.completed_at.isoformat(),
        "analysisEngine": result["analysisEngine"], "threatType": result["threatType"],
        "severity": result["severity"], "indicators": [
            {"id": i["id"], "label": i["label"], "description": i["description"], "severity": i["severity"],
             "weight": i["weight"], "triggered": i["triggered"]} for i in result["indicators"]
        ], "explanation": result["explanation"], "recommendations": result["recommendations"], "status": "completed",
    }
