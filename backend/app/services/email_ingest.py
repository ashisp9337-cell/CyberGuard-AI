"""
One email in -> full Email Intelligence Pipeline -> saved, quarantined if dangerous, ready to alert.

Shared by the manual upload (/api/email/analyze) and the automatic Gmail watcher
(app/automation/email_watcher.py), so both treat an email exactly the same way.
"""
from app.email_pipeline import analyze_email, quarantine
from app.email_pipeline.store import record_email
from app.services import response_playbook, scan_store


def process_email(db, user_id: str, raw, *, source: str, sender: str = "", subject: str = "",
                  network: bool = True):
    """Returns (scan_row, email_record, result). Caller commits, then alerts if riskScore is high."""
    result = analyze_email(raw, db=db, user_id=user_id, sender=sender, subject=subject, network=network)
    target = result.pop("_target", "email")
    result.pop("_target_type", None)
    quarantine.decide(result)          # auto-quarantine decision (before the playbook, so it can say so)
    response_playbook.apply(result, "phishing", "email-analysis", str(target))
    is_ato = result.get("category", "").startswith("Possible account takeover")
    scan = scan_store.save_result(
        db, user_id=user_id, module_id="phishing", subtopic_id="email-analysis", subtopic_title="Email Analysis",
        result=result, target=str(target), target_type="email", metadata={"source": source},
        source="email-pipeline" if source in ("upload", "paste") else f"automation:{source}",
        event_type="credential" if is_ato else "phishing",
        event_title=f"{result.get('category', 'Email')} — {result['classification'].replace('_', ' ').title()}",
        event_extra={"mitre": result.get("mitre", []), "from": result.get("email", {}).get("from_address", "")},
    )
    rec = record_email(db, user_id, result, scan_id=scan.id, source=source)
    return scan, rec, result
