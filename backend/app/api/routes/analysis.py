import json
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, UploadFile, File, Form
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.dependencies import get_current_user
from app.core.rate_limit import limiter
from app.db.database import get_db
from app.db.models import User, Scan, DetectedIndicatorRow, RecommendationRow, ThreatEvent
from app.schemas.analysis import RunScanRequest
from app.services.analysis_service import run_scan
from app.services import response_playbook, notifier, subtopic_router, scan_store

router = APIRouter(prefix="/api/analysis", tags=["analysis"])
settings = get_settings()

ALLOWED_EXTENSIONS = {".eml", ".msg", ".txt", ".png", ".jpg", ".jpeg", ".mp4", ".mov", ".avi", ".mkv", ".webm", ".mp3", ".wav", ".pdf"}


def _save_upload(file: UploadFile) -> tuple[str, str]:
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail={"error": {"code": "UNSUPPORTED_FILE_TYPE", "message": f"File type {ext} is not supported."}})
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    safe_name = f"{uuid.uuid4().hex}{ext}"       # never the user's file name: no path tricks possible
    path = os.path.join(settings.UPLOAD_DIR, safe_name)
    max_bytes = settings.MAX_UPLOAD_MB * 1024 * 1024
    content = file.file.read(max_bytes + 1)      # read at most one byte past the limit, never the whole upload
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail={"error": {"code": "FILE_TOO_LARGE", "message": f"File exceeds {settings.MAX_UPLOAD_MB}MB limit."}})
    with open(path, "wb") as f:
        f.write(content)
    os.chmod(path, 0o600)
    return path, file.filename or safe_name



_FIELD_LIMITS = {"moduleId": 64, "subtopicId": 64, "subtopicTitle": 200, "urlInput": 4096, "extraFieldValues": 20_000}


def _check_lengths(**fields) -> None:
    """Reject oversized form fields with a clear 413 instead of spending CPU on them."""
    limits = dict(_FIELD_LIMITS, textInput=settings.MAX_TEXT_CHARS)
    for name, value in fields.items():
        if value is not None and len(value) > limits[name]:
            raise HTTPException(status_code=413, detail={"error": {"code": "INPUT_TOO_LARGE",
                                "message": f"{name} is longer than {limits[name]:,} characters."}})


def _playbook_text(url_input, text_input, target) -> str:
    """Text the response playbook reads domains/IPs from.

    The scan's "target" is often the first 80 characters of the message, so it can
    end in the middle of a link ("http://indiapost-f"). Use it only when it adds
    something the user's own input doesn't already contain, and then drop a
    cut-off last word so it can't turn into a fake domain to block.
    """
    base = " ".join(filter(None, [url_input, text_input]))
    t = str(target or "").strip()
    if not t or t in base:
        return base
    if len(t) >= 80 and " " in t:
        t = t.rsplit(" ", 1)[0]
    return f"{base} {t}".strip()

@router.post("/scan")
@limiter.limit("30/minute")
async def scan(
    request: Request,
    background_tasks: BackgroundTasks,
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
    _check_lengths(moduleId=moduleId, subtopicId=subtopicId, subtopicTitle=subtopicTitle, textInput=textInput,
                   urlInput=urlInput, extraFieldValues=extraFieldValues)
    extra_fields = {}
    if extraFieldValues:
        try:
            extra_fields = json.loads(extraFieldValues)
        except json.JSONDecodeError:
            extra_fields = {}
        if not isinstance(extra_fields, dict):     # only {"field": "value"} is meaningful
            extra_fields = {}
        extra_fields = {str(k)[:100]: (v if isinstance(v, (str, int, float, bool)) or v is None else str(v))
                        for k, v in list(extra_fields.items())[:50]}

    file_path, file_name = (None, None)
    if file is not None and file.filename:
        file_path, file_name = _save_upload(file)

    routing = None
    if subtopicId == "auto":
        # Auto-detect: classify the input's subtopic, then run the existing detector for it.
        try:
            result, c = subtopic_router.route(
                module_id=moduleId, text_input=textInput, url_input=urlInput, file_path=file_path,
                file_name=file_name, extra_field_values=extra_fields, db=db, user_id=user.id,
            )
        except subtopic_router.RoutingError as exc:
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
            raise HTTPException(status_code=422, detail={"error": {
                "code": f"SUBTOPIC_{exc.code.upper()}", "message": exc.message, "details": exc.details}})
        subtopicId, subtopicTitle, routing = c.subtopic_id, c.subtopic_title, c.to_dict()
    else:
        result = run_scan(
            module_id=moduleId, subtopic_id=subtopicId, subtopic_title=subtopicTitle,
            text_input=textInput, url_input=urlInput, file_path=file_path, file_name=file_name,
            extra_field_values=extra_fields, db=db, user_id=user.id,
        )

    target = result.pop("_target", file_name or urlInput or textInput or "submission")
    target_type = result.pop("_target_type", "text")
    # Threat-specific response actions (quarantine, block IP, revoke session, report ...).
    response_playbook.apply(result, moduleId, subtopicId, _playbook_text(urlInput, textInput, target))

    scan_row = scan_store.save_result(
        db, user_id=user.id, module_id=moduleId, subtopic_id=subtopicId, subtopic_title=subtopicTitle,
        result=result, target=str(target), target_type=target_type, metadata=extra_fields, source="scan",
    )

    db.commit()
    db.refresh(scan_row)

    # Alert the admin / SOC (Telegram, email) after the response is sent.
    if result["riskScore"] >= notifier.get_settings().ALERT_MIN_SCORE:
        background_tasks.add_task(notifier.alert_for_scan, scan_row.id)

    return {
        "scanId": scan_row.id, "moduleId": moduleId, "subtopicId": subtopicId,
        "subtopicTitle": subtopicTitle, "target": scan_row.target, "targetType": target_type,
        "riskScore": result["riskScore"], "classification": result["classification"],
        "confidenceScore": result["confidenceScore"], "detectionTime": scan_row.completed_at.isoformat(),
        "analysisEngine": result["analysisEngine"], "threatType": result["threatType"],
        "severity": result["severity"], "indicators": [
            {"id": i["id"], "label": i["label"], "description": i["description"], "severity": i["severity"],
             "weight": i["weight"], "triggered": i["triggered"], "mitre": scan_store.indicator_mitre(i)}
            for i in result["indicators"]
        ], "explanation": result["explanation"], "recommendations": result["recommendations"],
        "responseActions": result.get("responseActions", []),
        "quarantine": result.get("quarantine"), "routing": routing, "status": "completed",
        **scan_store.detail_fields(result),
    }
