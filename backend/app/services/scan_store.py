"""
Save one detector result the same way a manual scan is saved -- used by manual scans AND by the
automatic watchers (app/automation/), so automatic findings show up in Scan History, the Dashboard,
Live Monitoring and alerts exactly like manual ones.
"""
import re
from datetime import datetime, timezone

from app.db.models import DetectedIndicatorRow, RecommendationRow, Scan, ThreatEvent


def save_result(db, *, user_id: str, module_id: str, subtopic_id: str, subtopic_title: str, result: dict,
                target: str, target_type: str, metadata: dict | None = None, source: str = "scan",
                event_type: str | None = None, event_title: str | None = None,
                event_extra: dict | None = None) -> Scan:
    """Adds Scan + indicators + recommendations (+ a ThreatEvent when not safe). Caller commits.

    Also checks the scan's URLs/domains/IPs/senders/file hashes against IOCs from earlier risky scans
    ("seen before" raises the score) and remembers this scan's ones if it is risky (app/services/ioc.py),
    and tags the result with MITRE ATT&CK techniques and their explanations (app/services/mitre.py)."""
    from app.services import ioc, mitre
    try:
        cands = ioc.candidates(result, target, module_id)
        hits = ioc.lookup(db, user_id, cands)
        ioc.apply_seen_before(result, hits)
    except Exception:                       # IOC memory must never break a scan
        cands, hits = set(), []
    try:
        mitre.annotate(module_id, subtopic_id, result)   # MITRE ATT&CK techniques + plain explanations
    except Exception:
        result.setdefault("mitre", [])
        result.setdefault("mitreDetails", [])
    scan_row = Scan(
        user_id=user_id, module_id=module_id, subtopic_id=subtopic_id, subtopic_title=subtopic_title,
        input_type=target_type, target=str(target)[:500], input_metadata=metadata or {},
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
    try:
        ioc.record(db, user_id, scan_row.id, module_id, result, ioc.recordable(cands, result, module_id))
    except Exception:
        pass

    # Feed Live Monitoring / notifications: only notable results become threat events.
    if result["classification"] != "safe":
        db.add(ThreatEvent(
            user_id=user_id, event_type=event_type or module_id, source=source, severity=result["severity"],
            title=event_title or f"{result['threatType']} — {result['classification'].replace('_', ' ').title()}",
            description=result["explanation"][:500],
            event_metadata={"target": scan_row.target, "riskScore": result["riskScore"], "category": module_id,
                            "scanId": scan_row.id, "iocHits": len(hits), **(event_extra or {}),
                            "mitre": result.get("mitre", [])},
            status="active", timestamp=datetime.now(timezone.utc),
        ))
    return scan_row


def detail_fields(result: dict) -> dict:
    """Extra result details for the API (live scan response and Scan History detail):
    MITRE ATT&CK techniques with explanations, IOC 'seen before' hits, the URL model's own assessment,
    the per-engine breakdown of an email, the email's sender/authentication summary and parsed log signals."""
    result = result or {}
    out = {
        "mitreAttack": result.get("mitreDetails") or [],
        "iocHits": result.get("iocHits") or [],
        "modelAssessment": result.get("modelAssessment"),
        "engineBreakdown": [
            {"component": c.get("component"), "engine": c.get("engine"), "score": c.get("score"),
             "classification": c.get("classification"), "explanation": c.get("explanation")}
            for c in (result.get("components") or []) if isinstance(c, dict)][:10],
        "category": result.get("category"),
        "parsedSignals": result.get("parsedSignals"),
        "autoDetect": _routing(result.get("routing")),
        "modelDetails": _model_details(result),
        "provenance": _provenance(result.get("provenance")),
        "liveCheck": _live_check(result.get("liveCheck")),
        "checkedDetectors": [{"detector": str(d.get("detector", ""))[:80], "riskScore": _int(d.get("riskScore"))}
                             for d in (result.get("checkedDetectors") or []) if isinstance(d, dict)][:10],
    }
    em = result.get("email") or {}
    if em:
        auth = em.get("auth") or {}
        out["emailSummary"] = {
            "from": em.get("from_address", ""), "displayName": em.get("from_display_name", ""),
            "subject": (em.get("subject") or "")[:200], "replyTo": em.get("reply_to_address") or "",
            "originatingIp": em.get("originating_ip") or "",
            "spf": auth.get("spf", "unknown"), "dkim": auth.get("dkim", "unknown"), "dmarc": auth.get("dmarc", "unknown"),
            "links": len(em.get("links") or []), "attachments": len(em.get("attachments") or []),
            "escalations": list(result.get("escalations") or [])[:5],
        }
    return out


def indicator_mitre(ind: dict) -> list[str]:
    v = ind.get("mitre")
    if isinstance(v, str):
        v = [v]
    return [t for t in (v or []) if isinstance(t, str) and t]


# ---- extra details shown on the result page (whitelisted, size-capped: nothing internal or private leaks) ----
def _num(x):
    return round(float(x), 6) if isinstance(x, (int, float)) and not isinstance(x, bool) else None


def _int(x):
    return int(x) if isinstance(x, (int, float)) and not isinstance(x, bool) else 0


def _strs(xs, n=6, length=200):
    return [str(x)[:length] for x in (xs or []) if x is not None][:n] if isinstance(xs, (list, tuple)) else []


def _routing(r):
    """How auto-detect chose the subtopic (only for scans run with 'Auto-detect')."""
    if not isinstance(r, dict):
        return None
    return {"subtopicId": str(r.get("subtopicId", ""))[:60], "subtopicTitle": str(r.get("subtopicTitle", ""))[:120],
            "method": str(r.get("method", ""))[:60], "status": str(r.get("status", "") or "ok")[:20],
            "reasons": _strs(r.get("reasons")), "secondary": _strs(r.get("secondary"), 3, 60),
            "note": _readable_note(r)}


def _readable_note(r):
    """The detector note in plain words (internal function names such as 'deepfake.analyze_media' are not shown)."""
    for text in (r.get("detectorNote"), r.get("detector")):
        text = str(text or "")
        if text and not re.search(r"\b[a-z_]+\.[a-z_]+\b", text):
            return text[:200]
    return ""


def _model(name, level, probability=None, verify=None, alert=None, notes=None, kind="probability"):
    return {"name": str(name)[:120], "level": str(level or "low")[:10], "kind": kind, "probability": _num(probability),
            "verifyThreshold": _num(verify), "alertThreshold": _num(alert), "notes": _strs(notes, 8)}


def _model_details(result):
    """Every trained model that looked at this item, with its own verdict and alert levels."""
    out = []
    sm = result.get("subtopicModel")
    if isinstance(sm, dict) and sm.get("model"):
        notes = []
        if sm.get("brandDomain"):
            notes.append(f"Imitated real site: {sm['brandDomain']}")
        notes += [f"Trick: {t}" for t in _strs(sm.get("tricks"), 4)]
        notes += _strs(sm.get("reasons"), 4)
        if sm.get("eventsScored") is not None:
            notes.append(f"{_int(sm.get('eventsFlagged'))} of {_int(sm.get('eventsScored'))} events flagged")
        out.append(_model(sm["model"], sm.get("level"), sm.get("probability"), sm.get("verifyThreshold"),
                          sm.get("alertThreshold"), notes))
    for m in (result.get("urlModels") or [])[:6]:
        if isinstance(m, dict) and m.get("model") and not (isinstance(sm, dict) and m.get("model") == sm.get("model")):
            out.append(_model(m["model"], m.get("level"), m.get("probability")))
    ma = result.get("modelAssessment")
    if isinstance(ma, dict) and "percentile" in ma:                       # login risk model (credential module)
        notes = _strs(ma.get("reasons"), 5)
        notes.append(f"{_int(ma.get('loginsFlagged'))} of {_int(ma.get('loginsScored'))} logins flagged")
        out.append(_model("Login risk model (RBA dataset)", ma.get("level"), (_num(ma.get("percentile")) or 0) / 100,
                          (_num(ma.get("verifyPercentile")) or 0) / 100 or None,
                          (_num(ma.get("alertPercentile")) or 0) / 100 or None, notes, kind="percentile"))
    ai = result.get("aiImageModel")
    if isinstance(ai, dict):
        views = ai.get("views") or []
        notes = [f"{len(views)} parts of the picture checked; the most AI-looking one decides"] if len(views) > 1 else []
        out.append(_model("AI-generated image model (CLIP ViT-L/14)", ai.get("level"), ai.get("probability"),
                          ai.get("verifyThreshold"), ai.get("alertThreshold"), notes))
    df = result.get("deepfakeModel")
    if isinstance(df, dict):
        faces = [f for f in (df.get("faces") or []) if isinstance(f, dict)][:5]
        notes = (["No face found - the whole picture was judged"] if df.get("wholeImage") else
                 [f"Face {i + 1}: raw score {round(100 * (_num(f.get('probability')) or 0), 4):g}%"
                  for i, f in enumerate(faces)])
        out.append(_model("Face-swap model (EfficientNet-B0)", df.get("level"), df.get("probability"),
                          df.get("verifyThreshold"), df.get("alertThreshold"), notes))
    dv = result.get("deepfakeVideoModel")
    if isinstance(dv, dict) and dv.get("level"):
        faces = sorted((f for f in (dv.get("faces") or []) if isinstance(f, dict)),
                       key=lambda f: -(_num(f.get("probability")) or 0))[:4]
        notes = [f"Faces checked: {_int(dv.get('framesWithFace'))} of {_int(dv.get('framesChecked'))} frames"]
        notes += [f"At {int(_num(f.get('second')) or 0) // 60}:{int(_num(f.get('second')) or 0) % 60:02d} - "
                  f"{round(100 * (_num(f.get('probability')) or 0))}%" for f in faces]
        out.append(_model("Face-swap video model (EfficientNet-B0, Celeb-DF v2)", dv.get("level"), dv.get("probability"),
                          dv.get("verifyThreshold"), dv.get("alertThreshold"), notes))
    return out


def _provenance(p):
    if not isinstance(p, dict):
        return None
    return {"proof": bool(p.get("proof")), "hasContentCredentials": bool(p.get("hasContentCredentials")),
            "findings": [{"label": str(f.get("label", ""))[:120], "detail": str(f.get("detail", ""))[:300],
                          "proof": bool(f.get("proof"))} for f in (p.get("findings") or []) if isinstance(f, dict)][:6]}


def _live_check(e):
    """Read-only visit of a link: every redirect hop and what the final page asks for."""
    if not isinstance(e, dict):
        return None
    page = e.get("page") if isinstance(e.get("page"), dict) else {}
    return {"status": str(e.get("status", ""))[:20], "reason": str(e.get("reason", ""))[:200],
            "finalUrl": str(e.get("finalUrl", ""))[:300], "redirectChain": _strs(e.get("redirectChain"), 8, 200),
            "page": {"title": str(page.get("title", ""))[:150], "hasPassword": bool(page.get("has_password")),
                     "brandsImitated": _strs(page.get("brands_imitated"), 3, 60),
                     "externalFormTargets": _strs(page.get("external_form_targets"), 3, 120),
                     "sensitiveFields": _strs(page.get("sensitive_fields"), 6, 40)} if page else None}
