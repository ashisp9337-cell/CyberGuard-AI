"""
Real report generation (CSV, JSON, PDF) from actual scan records stored
in the database. No placeholder content.
"""
import csv
import io
import json
import os
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

from app.core.config import get_settings

settings = get_settings()


def _mitre_ids(s) -> list[str]:
    res = s.result or {}
    ids = res.get("mitre")
    if ids is None and res.get("indicators"):
        try:
            from app.services import mitre
            ids = mitre.map_result(s.module_id, s.subtopic_id, dict(res))
        except Exception:
            ids = []
    return [i for i in (ids or []) if isinstance(i, str)]


def _scan_rows(scans: list) -> list[dict]:
    rows = []
    for s in scans:
        rows.append({
            "scan_id": s.id, "module": s.module_id, "subtopic": s.subtopic_title,
            "target": s.target, "risk_score": s.risk_score, "classification": s.classification,
            "severity": s.severity, "confidence": s.confidence,
            "created_at": s.created_at.isoformat() if s.created_at else "",
            "mitre_attack": "; ".join(_mitre_ids(s)),
        })
    return rows


def _mitre_reference(scans: list) -> list[dict]:
    from app.services import mitre
    seen: list[str] = []
    for s in scans[:200]:
        for t in _mitre_ids(s):
            if t not in seen:
                seen.append(t)
    return mitre.brief(seen)


def generate_json_report(scans: list, title: str) -> bytes:
    payload = {
        "title": title,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "scanCount": len(scans),
        "scans": _scan_rows(scans),
        "mitreAttack": _mitre_reference(scans),
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def generate_csv_report(scans: list, title: str) -> bytes:
    rows = _scan_rows(scans)
    buf = io.StringIO()
    if rows:
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for r in rows:   # guard against spreadsheet formula injection in targets
            writer.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@\t\r" else v) for k, v in r.items()})
    else:
        buf.write("scan_id,module,subtopic,target,risk_score,classification,severity,confidence,created_at,mitre_attack\n")
    return buf.getvalue().encode("utf-8")


def generate_pdf_report(scans: list, title: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = [Paragraph(title, styles["Title"]), Spacer(1, 12),
                Paragraph(f"Generated: {datetime.now(timezone.utc).isoformat()} — {len(scans)} scan(s)", styles["Normal"]),
                Spacer(1, 12)]

    data = [["Scan ID", "Module", "Risk", "Classification", "Severity", "ATT&CK", "Date"]]
    for s in scans[:200]:
        data.append([s.id, s.module_id, str(s.risk_score), s.classification, s.severity,
                     ", ".join(_mitre_ids(s)[:3]),
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

    # Detail for small reports: what was found and the MITRE ATT&CK techniques, explained.
    if len(scans) <= 5:
        for s in scans:
            elements += [Spacer(1, 14), Paragraph(escape(f"{s.threat_type} — risk {s.risk_score} ({s.classification})"), styles["Heading3"]),
                         Paragraph(escape(f"Target: {s.target}"), styles["Normal"]), Spacer(1, 4),
                         Paragraph(escape(s.explanation or ""), styles["Normal"])]
            for ind in [i for i in ((s.result or {}).get("indicators") or []) if i.get("triggered")][:8]:
                elements.append(Paragraph(escape(f"• {ind.get('label', '')}: {ind.get('description', '')}"), styles["Normal"]))
    ref = _mitre_reference(scans)
    if ref:
        elements += [Spacer(1, 16), Paragraph("MITRE ATT&amp;CK techniques in this report", styles["Heading2"])]
        for t in ref:
            elements.append(Paragraph(f"<b>{escape(t['id'])} — {escape(t['name'])}</b> ({escape(t['tactic'])})", styles["Normal"]))
            elements.append(Paragraph(escape(t["explanation"]), styles["Normal"]))
            elements.append(Spacer(1, 6))
    doc.build(elements)
    return buf.getvalue()


def save_report_file(content: bytes, filename: str) -> str:
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    path = os.path.join(settings.REPORTS_DIR, filename)
    with open(path, "wb") as f:
        f.write(content)
    return path
