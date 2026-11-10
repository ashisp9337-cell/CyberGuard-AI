"""
(10 Nov) Learning from "False positive".

When the user marks an incident as a false positive, CyberGuard remembers it for that user:
  1. the exact message / link / file of that scan  -> scanning it again gives "safe (you marked it as safe)";
     (10 Nov) for photos / videos also their LOOK, so a re-sent, re-compressed copy is recognised too;
  2. its sender address, links, domains, IPs, file hashes -> allowlisted IOCs: never "seen before in an earlier
     threat" again and never remembered as bad again (app/services/ioc.py already skips allowlisted ones);
  3. a later e-mail from the SAME sender address is trusted for its wording - its links, attachments and QR codes
     are still checked, because real accounts get hacked.
Changing the incident back (re-open / resolve) undoes 1-3. Nothing is shared between users, and no model is
retrained: one click must never teach the AI models anything for everybody (anyone could poison them that way).
Everything is stored in the existing IOC table (type "message" = the fingerprint of a message), so no new table.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from app.db.models import IOC, Scan

MESSAGE = "message"                     # ioc_type of a marked-safe message fingerprint
NOTE_PREFIX = "False positive (scan "
CONTENT = ("url", "qr", "attachment")
_WS = re.compile(r"\s+")


def _now():
    return datetime.now(timezone.utc)


def fingerprint(module_id: str, text: str | None) -> str | None:
    """Stable key of what was scanned: the same e-mail copied again (even a day later, when Gmail shows '(1 day
    ago)' instead of '(2 hours ago)') gives the same key."""
    t = (text or "").strip()
    if not t:
        return None
    try:
        from app.email_pipeline.parser import pasted_mail_view
        view = pasted_mail_view(t)
        if view:
            t = "\n".join(view)                       # sender, subject, body - without the date / "to me" lines
    except Exception:
        pass
    norm = _WS.sub(" ", t.lower()).strip()[:200_000]
    return hashlib.sha256(f"{module_id}|{norm}".encode("utf-8", "ignore")).hexdigest()


def _note(scan_id: str, how: str) -> str:
    return f"{NOTE_PREFIX}{scan_id}) - {how}"


def _sender(result: dict) -> str:
    em = result.get("email") or {}
    return (em.get("from_address") or "").strip().lower() if isinstance(em, dict) else ""


def _allowlisted(db, user_id: str, ioc_type: str, value: str) -> IOC | None:
    if not value:
        return None
    return (db.query(IOC).filter(IOC.user_id == user_id, IOC.ioc_type == ioc_type, IOC.value == value,
                                 IOC.status == "allowlisted").first())


def _mark_safe(result: dict, cap: int, label: str, description: str, threat_type: str | None = None) -> None:
    from app.services.risk_scoring import classify_risk, recommendations_for, severity_from_classification
    old = int(result.get("riskScore", 0))
    new = min(old, cap)
    result["riskScore"] = new
    result["classification"] = classify_risk(new)
    result["severity"] = severity_from_classification(result["classification"])
    if threat_type and new <= 25:
        result["threatType"] = threat_type
    result.setdefault("indicators", []).insert(0, {
        "id": "IND_user_marked_safe", "label": label, "description": description, "severity": "low",
        "weight": 0, "triggered": True})
    result["explanation"] = f"{description} (Without your earlier decision the score would be {old}/100.) " + \
        str(result.get("explanation", ""))
    if new < old:
        result["recommendations"] = recommendations_for(result["classification"], str(result.get("threatType", "")))
        result.pop("quarantine", None)
    result["userVerdict"] = {"kind": label, "scoreBefore": old}


# (10 Nov) Photos and videos: the same picture sent again is usually NOT the same file (WhatsApp / Telegram re-compress
# and resize it), so besides the file's SHA-256 a perceptual "look" fingerprint is kept: 256-bit difference hash of
# the picture (videos: one frame 1 second in). Measured on 300 real photos (BSDS500): a re-sent copy (60% size, JPEG
# quality 45) differed in 5 bits on average, at most 35; two different photos in at least 62 (44,850 pairs).
IMG_PREFIX = "img:"
IMG_MAX_BITS = 40


def file_sha256(file_path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def look_hash(file_path: str) -> str | None:
    """Difference hash (16x16 = 256 bits, hex) of a picture or of a video's frame at ~1 s; None for anything else."""
    from PIL import Image
    img = None
    try:
        try:
            import pillow_heif
            pillow_heif.register_heif_opener()
        except Exception:
            pass
        with Image.open(file_path) as im:
            im.seek(0)
            img = im.convert("L").resize((17, 16), Image.BILINEAR)
    except Exception:
        try:
            import av
            with av.open(file_path) as c:
                vs = [s for s in c.streams if s.type == "video"]
                if not vs:
                    return None
                for i, frame in enumerate(c.decode(vs[0])):
                    if (frame.time or 0) >= 1.0 or i >= 60:
                        img = frame.to_image().convert("L").resize((17, 16), Image.BILINEAR)
                        break
        except Exception:
            return None
    if img is None:
        return None
    import numpy as np
    a = np.asarray(img, dtype=np.int16)
    bits = (a[:, 1:] > a[:, :-1]).flatten()
    return "".join(f"{int(''.join('1' if b else '0' for b in bits[i:i + 4]), 2):x}" for i in range(0, 256, 4))


def _bits_apart(a: str, b: str) -> int:
    try:
        return bin(int(a, 16) ^ int(b, 16)).count("1")
    except ValueError:
        return 256


def media_keys(module_id: str, file_path: str | None) -> tuple[str | None, str | None]:
    """(exact key from the file's SHA-256, look fingerprint) of an uploaded file."""
    if not file_path:
        return None, None
    sha = file_sha256(file_path)
    return (fingerprint(module_id, f"sha256:{sha}") if sha else None,
            look_hash(file_path) if module_id == "deepfake" else None)


def apply_user_verdict(db, user_id: str | None, module_id: str, result: dict, key: str | None,
                       look: str | None = None) -> None:
    """Before a scan is saved (and before any response action runs): apply what this user taught CyberGuard."""
    if db is None or not user_id or not isinstance(result, dict) or result.get("userVerdict"):
        return
    if look:
        result["feedbackLook"] = look
    if key:
        result["feedbackKey"] = key
        row = _allowlisted(db, user_id, MESSAGE, key)
        if row is not None:
            what = "file" if look or str(result.get("feedbackKind")) == "file" else "message"
            _mark_safe(result, 20, f"You marked this exact {what} as safe",
                       f"You marked this same {what} as a false positive earlier, so CyberGuard treats it as safe.",
                       "No threat (marked safe by you)")
            return
    if look:                                    # the same picture / video again, even re-compressed or resized
        rows = (db.query(IOC.value).filter(IOC.user_id == user_id, IOC.ioc_type == MESSAGE,
                                           IOC.status == "allowlisted", IOC.value.like(IMG_PREFIX + "%")).limit(2000))
        for (v,) in rows:
            if _bits_apart(look, v[len(IMG_PREFIX):]) <= IMG_MAX_BITS:
                _mark_safe(result, 20, "You marked this picture / video as safe",
                           "You marked the same picture or video as a false positive earlier (this copy may have been "
                           "re-sent or re-compressed), so CyberGuard treats it as safe.",
                           "No threat (marked safe by you)")
                return
    sender = _sender(result)
    if module_id == "phishing" and sender and _allowlisted(db, user_id, "email", sender) is not None:
        comps = result.get("components") or []
        content_risky = any(c.get("component") in CONTENT and int(c.get("score") or 0) >= 51 for c in comps)
        if not content_risky and not result.get("escalations"):
            _mark_safe(result, 25, "Sender you marked as safe",
                       f"You marked an earlier e-mail from {sender} as a false positive, so its wording is trusted; "
                       "its links, attachments and QR codes were still checked and none is risky.",
                       "No threat (sender marked safe by you)")
        else:
            result.setdefault("indicators", []).append({
                "id": "IND_user_sender_but_risky", "label": "Sender you marked as safe - but this e-mail has a risky "
                "link or attachment", "description": f"You trusted {sender} earlier, but this e-mail carries a risky "
                "link / attachment, so it is still flagged: the account may be hacked.", "severity": "high",
                "weight": 0, "triggered": True})


def _upsert_allowlisted(db, user_id: str, ioc_type: str, value: str, scan: Scan) -> bool:
    row = db.query(IOC).filter(IOC.user_id == user_id, IOC.ioc_type == ioc_type, IOC.value == value).first()
    if row is None:
        with db.begin_nested():
            db.add(IOC(user_id=user_id, ioc_type=ioc_type, value=value[:1000], status="allowlisted", times_seen=1,
                       max_risk=int(scan.risk_score or 0), modules=[scan.module_id], first_scan_id=scan.id,
                       last_scan_id=scan.id, note=_note(scan.id, "added"), first_seen=_now(), last_seen=_now()))
        return True
    if row.status == "active":
        row.status, row.note = "allowlisted", _note(scan.id, "was active")
        return True
    return False


def learn_false_positive(db, user_id: str, event) -> int:
    """The incident `event` was marked a false positive: remember its scan as safe for this user. Returns how many
    things were remembered (0 when the incident has no scan, e.g. a watcher alert without one)."""
    from app.services import ioc
    scan_id = (event.event_metadata or {}).get("scanId")
    scan = db.get(Scan, scan_id) if scan_id else None
    if scan is None or scan.user_id != user_id:
        return 0
    result = scan.result or {}
    n = 0
    key = result.get("feedbackKey")
    if key:
        n += _upsert_allowlisted(db, user_id, MESSAGE, key, scan)
    look = result.get("feedbackLook")
    if look:
        n += _upsert_allowlisted(db, user_id, MESSAGE, IMG_PREFIX + look, scan)
    try:
        cands = ioc.candidates(result, scan.target, scan.module_id)
    except Exception:
        cands = set()
    for t, v in sorted(cands):
        n += _upsert_allowlisted(db, user_id, t, v, scan)
    sender = _sender(result)
    if sender and ("email", sender) not in cands and "@" in sender:
        n += _upsert_allowlisted(db, user_id, "email", sender, scan)
    return n


def unlearn_false_positive(db, user_id: str, event) -> int:
    """The incident is no longer a false positive: undo exactly what learn_false_positive did for its scan."""
    scan_id = (event.event_metadata or {}).get("scanId")
    if not scan_id:
        return 0
    rows = db.query(IOC).filter(IOC.user_id == user_id, IOC.status == "allowlisted",
                                IOC.note.like(f"{NOTE_PREFIX}{scan_id}) - %")).all()
    for row in rows:
        if row.note.endswith("- was active"):
            row.status, row.note = "active", ""
        else:
            db.delete(row)
    return len(rows)
