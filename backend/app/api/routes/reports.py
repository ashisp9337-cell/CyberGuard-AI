import os

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.core.rate_limit import limiter
from app.db.database import get_db
from app.db.models import User, Scan, Report
from app.services.report_service import generate_json_report, generate_csv_report, generate_pdf_report, save_report_file

router = APIRouter(prefix="/api/reports", tags=["reports"])


class CreateReportRequest(BaseModel):
    title: str = Field("CyberGuard Security Report", max_length=200)
    format: str = Field("JSON", max_length=8)  # PDF | CSV | JSON
    scanIds: list[str] | None = Field(None, max_length=1000)


def _to_out(r: Report) -> dict:
    return {
        "id": r.id, "title": r.title, "type": r.report_type, "createdAt": r.created_at.isoformat(),
        "format": r.format, "sizeKb": round(r.size_kb, 1),
    }


@router.post("", status_code=201)
@limiter.limit("10/minute")
def create_report(request: Request, body: CreateReportRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(Scan).filter(Scan.user_id == user.id)
    if body.scanIds:
        q = q.filter(Scan.id.in_(body.scanIds))
    scans = q.order_by(Scan.created_at.desc()).all()

    fmt = body.format.upper()
    if fmt == "CSV":
        content = generate_csv_report(scans, body.title)
        ext = "csv"
    elif fmt == "PDF":
        content = generate_pdf_report(scans, body.title)
        ext = "pdf"
    else:
        content = generate_json_report(scans, body.title)
        fmt, ext = "JSON", "json"

    report = Report(user_id=user.id, title=body.title, report_type="scan_summary",
                     scan_ids=[s.id for s in scans], format=fmt)
    db.add(report)
    db.flush()

    filename = f"{report.id}.{ext}"
    path = save_report_file(content, filename)
    report.file_path = path
    report.size_kb = len(content) / 1024
    db.commit()
    db.refresh(report)

    return _to_out(report)


@router.get("")
def list_reports(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    reports = db.query(Report).filter(Report.user_id == user.id).order_by(Report.created_at.desc()).all()
    return [_to_out(r) for r in reports]


@router.get("/{report_id}")
def get_report(report_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    r = db.query(Report).filter(Report.id == report_id, Report.user_id == user.id).first()
    if not r:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Report not found."}})
    return _to_out(r)


@router.get("/{report_id}/download")
def download_report(report_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    r = db.query(Report).filter(Report.id == report_id, Report.user_id == user.id).first()
    if not r or not os.path.exists(r.file_path):
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Report file not found."}})
    media_types = {"PDF": "application/pdf", "CSV": "text/csv", "JSON": "application/json"}
    return FileResponse(r.file_path, media_type=media_types.get(r.format, "application/octet-stream"),
                         filename=os.path.basename(r.file_path))
