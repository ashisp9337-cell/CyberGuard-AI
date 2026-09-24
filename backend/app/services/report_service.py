"""
Real report generation (CSV, JSON, PDF) from actual scan records stored
in the database. No placeholder content.
"""
import csv
import io
import json
import os
from datetime import datetime, timezone

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

from app.core.config import get_settings

settings = get_settings()


def _scan_rows(scans: list) -> list[dict]:
    rows = []
    for s in scans:
        rows.append({
            "scan_id": s.id, "module": s.module_id, "subtopic": s.subtopic_title,
            "target": s.target, "risk_score": s.risk_score, "classification": s.classification,
            "severity": s.severity, "confidence": s.confidence,
            "created_at": s.created_at.isoformat() if s.created_at else "",
        })
    return rows


def generate_json_report(scans: list, title: str) -> bytes:
    payload = {
        "title": title,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "scanCount": len(scans),
        "scans": _scan_rows(scans),
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def generate_csv_report(scans: list, title: str) -> bytes:
    rows = _scan_rows(scans)
    buf = io.StringIO()
    if rows:
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    else:
        buf.write("scan_id,module,subtopic,target,risk_score,classification,severity,confidence,created_at\n")
    return buf.getvalue().encode("utf-8")


def generate_pdf_report(scans: list, title: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = [Paragraph(title, styles["Title"]), Spacer(1, 12),
                Paragraph(f"Generated: {datetime.now(timezone.utc).isoformat()} — {len(scans)} scan(s)", styles["Normal"]),
                Spacer(1, 12)]

    data = [["Scan ID", "Module", "Risk", "Classification", "Severity", "Date"]]
    for s in scans[:200]:
        data.append([s.id, s.module_id, str(s.risk_score), s.classification, s.severity,
                     s.created_at.strftime("%Y-%m-%d %H:%M") if s.created_at else ""])
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
    ]))
    elements.append(table)
    doc.build(elements)
    return buf.getvalue()


def save_report_file(content: bytes, filename: str) -> str:
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    path = os.path.join(settings.REPORTS_DIR, filename)
    with open(path, "wb") as f:
        f.write(content)
    return path
