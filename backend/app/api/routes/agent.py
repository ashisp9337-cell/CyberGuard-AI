"""
(10 Nov) Company mode: the CyberGuard Agent on employee PCs, and the Devices page.

Pairing: on the Devices page an employee (for their own PC) or an administrator (for anyone's PC) makes a device key.
It is shown ONCE; only its SHA-256 hash is stored. The agent sends it in the header X-CyberGuard-Agent. Removing the
device stops the key at once. A disabled employee's PCs are refused too.

The agent only READS security facts and sends them; this server judges them with the SAME code the laptop's own
watchers use, so a finding means the same thing everywhere:
  POST /api/agent/hello     who the PC is (name, Windows version, agent version) -> what to collect and how often
  POST /api/agent/network   open ports + live connections (as pc_network.raw_connections lists them)
                            -> pc_network.judge_connections + network_watcher.finding_result
  POST /api/agent/logons    the Windows Security log's sign-in events (wevtutil XML, last hour)
                            -> windows_logons.parse_events / to_log_lines + the Credential (account takeover) engine
  POST /api/agent/dns       NEW website names the PC looked up (the agent remembers what it already sent)
                            -> dns_watcher.worth_checking / judge (URL models, no-network mode)
  POST /api/agent/file      a NEW risky download (program, script, archive, macro document ...), at most 15 MB
                            -> downloads_watcher.scan_file (static checks + EMBER2024); deleted right after
Findings are saved in the PC owner's Scan History (source "automation:agent-<collector>", tagged with the device) and
use the usual automatic-alert limits. Administrators see every PC on the Devices page; employees see their own.
Website names are judged and forgotten: only DANGEROUS names are kept (as findings) - no browsing list is stored.
"""
import copy
import hashlib
import os
import re
import secrets
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.core.config import get_settings
from app.core.dependencies import get_current_user, is_admin
from app.core.rate_limit import limiter
from app.db.database import SessionLocal, get_db
from app.db.models import Device, IOC, Scan, User
from app.services import audit

router = APIRouter(tags=["agent"])

AGENT_VERSION = "1.0"
KEY_PREFIX = "cga_"
MAX_DEVICES_PER_PERSON = 10
ONLINE_SECONDS = 180                  # a PC that reported in the last 3 minutes is "online"
INTERVALS = {"network": 60, "dns": 60, "logons": 300, "downloads": 30, "hello": 300}
MAX_ROWS, MAX_NAMES, MAX_XML = 5000, 1000, 3_000_000
REPEAT_PORT_H, REPEAT_CONN_H, REPEAT_NAME_H = 24 * 7, 24, 24
_lock = threading.Lock()
_name_reported: dict[tuple[str, str], float] = {}      # (device, dangerous name) -> time; in memory only


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _err(code: str, message: str, status: int):
    return HTTPException(status_code=status, detail={"error": {"code": code, "message": message}})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(t):
    return None if t is None else (t if t.tzinfo else t.replace(tzinfo=timezone.utc))


def _iso(t):
    return t.isoformat() if t else None


def _agent_rate_key(request: Request) -> str:
    """Rate limits per PC (many company PCs share one internet address), falling back to the address."""
    key = request.headers.get("x-cyberguard-agent", "")
    return "agent:" + _hash(key)[:16] if key else (request.client.host if request.client else "?")


# ---- the agent's identity ------------------------------------------------------------------------------------------
def agent_device(request: Request, x_cyberguard_agent: str = Header(default=""), db: Session = Depends(get_db)) -> Device:
    key = (x_cyberguard_agent or "").strip()
    if not key.startswith(KEY_PREFIX) or len(key) > 100:
        raise _err("AGENT_NOT_PAIRED", "Pair this agent with a device key from the CyberGuard Devices page.", 401)
    dev = db.query(Device).filter(Device.token_hash == _hash(key)).first()
    if dev is None or dev.revoked:
        raise _err("AGENT_NOT_PAIRED", "This device key was removed or is wrong. Make a new one on the Devices page.", 401)
    owner = db.get(User, dev.user_id)
    if owner is None or owner.is_active is False:
        raise _err("OWNER_DISABLED", "The employee this PC belongs to is disabled in CyberGuard.", 403)
    dev.last_seen_at = _now()
    dev.last_ip = ((request.client.host if request.client else "") or "")[:64]
    db.commit()
    return dev


def _state(dev: Device) -> dict:
    return copy.deepcopy(dev.state or {})           # a real copy: the saved value must differ for the UPDATE


def _save_state(db, dev: Device, st: dict) -> None:
    dev.state = st
    flag_modified(dev, "state")                     # always written, even when SQLAlchemy cannot see the change
    db.commit()


def _save_finding(dev: Device, *, collector: str, module_id: str, subtopic_id: str, subtopic_title: str, result: dict,
                  target: str, target_type: str, extra: dict | None = None) -> str | None:
    """A finding from an agent: saved for the PC's owner, tagged with the PC, alerted with the automatic limits."""
    from app.services import notifier, scan_store
    db = SessionLocal()
    try:
        scan = scan_store.save_result(
            db, user_id=dev.user_id, module_id=module_id, subtopic_id=subtopic_id, subtopic_title=subtopic_title,
            result=result, target=target, target_type=target_type, source=f"automation:agent-{collector}",
            metadata={"automatic": True, "source": f"agent-{collector}", "deviceId": dev.id, "deviceName": dev.name,
                      "hostname": dev.hostname or "", "collector": collector, **(extra or {})})
        db.commit()
        scan_id = scan.id
    finally:
        db.close()
    if result["riskScore"] >= notifier.ALERT_FLOOR:
        notifier.alert_for_scan(scan_id)
    return scan_id


def _on(dev: Device, text: str) -> str:
    return f"On {dev.name}{f' ({dev.hostname})' if dev.hostname and dev.hostname != dev.name else ''}: {text}"


def _record(st: dict, collector: str, **summary) -> None:
    st.setdefault("collectors", {})[collector] = {"at": _now().isoformat(), **summary}


# ---- agent calls ---------------------------------------------------------------------------------------------------
class HelloIn(BaseModel):
    hostname: str = Field(default="", max_length=100)
    os: str = Field(default="", max_length=150)
    agentVersion: str = Field(default="", max_length=20)
    collectors: list[str] = Field(default_factory=list, max_length=10)


@router.post("/api/agent/hello")
@limiter.limit("20/minute", key_func=_agent_rate_key)
def hello(body: HelloIn, request: Request, dev: Device = Depends(agent_device), db: Session = Depends(get_db)):
    dev.hostname, dev.os, dev.agent_version = body.hostname.strip()[:100], body.os.strip()[:150], body.agentVersion[:20]
    st = _state(dev)
    st["collectorsAvailable"] = [c for c in body.collectors if c in ("network", "logons", "dns", "downloads")][:4]
    _record(st, "hello")
    _save_state(db, dev, st)
    owner = db.get(User, dev.user_id)
    s = get_settings()
    who = s.COMPANY_NAME.strip() or "your company"
    return {"deviceId": dev.id, "name": dev.name, "owner": owner.name if owner else "", "company": who,
            "intervals": INTERVALS, "maxFileMb": s.MAX_UPLOAD_MB, "serverVersion": AGENT_VERSION,
            "notice": (f"This PC is protected by {who}'s CyberGuard. The agent reads security facts only - open ports "
                       "and connections, failed Windows sign-ins, website NAMES this PC looks up, and new risky "
                       "downloads - and sends them to the company's CyberGuard server to be checked. It never reads "
                       "your files' contents (except risky downloads), screen, keystrokes or messages, and it never "
                       "blocks or deletes anything.")}


class ConnIn(BaseModel):
    protocol: str = Field(default="TCP", max_length=5)
    localAddress: str = Field(default="", max_length=64)
    localPort: int = Field(default=0, ge=0, le=65535)
    remoteAddress: str = Field(default="", max_length=64)
    remotePort: int = Field(default=0, ge=0, le=65535)
    status: str = Field(default="", max_length=20)
    program: str = Field(default="unknown", max_length=260)
    pid: int | None = Field(default=None, ge=0)
    path: str = Field(default="", max_length=520)


class NetworkIn(BaseModel):
    rows: list[ConnIn] = Field(default_factory=list, max_length=MAX_ROWS)


def _flagged_ips(db, user_id: str) -> set[str]:
    return {v for (v,) in db.query(IOC.value).filter(IOC.user_id == user_id, IOC.ioc_type == "ip").limit(5000)}


@router.post("/api/agent/network")
@limiter.limit("20/minute", key_func=_agent_rate_key)
def report_network(body: NetworkIn, request: Request, dev: Device = Depends(agent_device), db: Session = Depends(get_db)):
    from app.automation.network_watcher import finding_result
    from app.services import pc_network
    rows = [{**r.model_dump(), "protocol": "UDP" if r.protocol.upper() == "UDP" else "TCP",
             "program": r.program or "unknown"} for r in body.rows]
    snap = pc_network.judge_connections(rows, _flagged_ips(db, dev.user_id))
    st = _state(dev)
    reported = dict((st.get("network") or {}).get("reported") or {})
    now = _now()
    saved = 0
    for f in snap["findings"]:
        if f["severity"] != "high":
            continue
        sig = "|".join(str(f.get(k, "")) for k in (("title", "port", "remote") if f.get("remote") else ("title", "program", "port")))
        last = reported.get(sig)
        hours = REPEAT_CONN_H if f.get("remote") else REPEAT_PORT_H
        if last and now - datetime.fromisoformat(last) < timedelta(hours=hours):
            continue
        result = finding_result(f)
        result["explanation"] = _on(dev, result["explanation"])
        result["threatType"] = result["threatType"].replace("on this PC", f"on {dev.name}")
        if _save_finding(dev, collector="network", module_id="cyber-threat", subtopic_id="network-traffic",
                         subtopic_title="CyberGuard Agent - network", result=result, target=f"{dev.name}: {f['title']}",
                         target_type="network", extra={"program": f.get("program"), "port": f.get("port"),
                                                       "remote": f.get("remote")}):
            saved += 1
        reported[sig] = now.isoformat()
    if len(reported) > 1000:
        reported = dict(sorted(reported.items(), key=lambda kv: kv[1])[-1000:])
    s = snap["summary"]
    st["network"] = {"reported": reported, "last": {
        "takenAt": now.isoformat(), "summary": s, "findings": snap["findings"][:30],
        "listening": [r for r in snap["listening"] if r["scope"] != "this computer only"][:50],
        "topRemote": snap["topRemote"], "topPrograms": snap["topPrograms"]}}
    _record(st, "network", checked=s["connections"] + s["openPorts"], findings=saved,
            note=f"{s['openPorts']} open port(s), {s['connections']} connection(s), {s['high']} high finding(s)")
    _save_state(db, dev, st)
    return {"ok": True, "findings": saved, "summary": s}


class LogonsIn(BaseModel):
    xml: str = Field(default="", max_length=MAX_XML)


@router.post("/api/agent/logons")
@limiter.limit("10/minute", key_func=_agent_rate_key)
def report_logons(body: LogonsIn, request: Request, dev: Device = Depends(agent_device), db: Session = Depends(get_db)):
    from app.automation import windows_logons as W
    from app.detectors import account_takeover
    try:
        events = W.parse_events(body.xml)
    except Exception:                                   # noqa: BLE001 - malformed or refused XML (DTD / entities)
        raise _err("BAD_EVENTS", "The sign-in events could not be read.", 422)
    st = _state(dev)
    lg = dict(st.get("logons") or {})
    last = int(lg.get("lastRecord", 0))
    new = [e for e in events if e["record"] > last]
    if events:
        lg["lastRecord"] = max(e["record"] for e in events)
    lines, new_lines = W.to_log_lines(events), W.to_log_lines(new)
    saved = 0
    note = f"No new sign-ins ({len(lines)} in the last hour)"
    if new_lines:
        result = account_takeover.analyze_event({}, "Windows sign-in monitoring", text="\n".join(lines))
        signature = sorted(i["label"] for i in result["indicators"] if i["triggered"])
        note = f"{len(new_lines)} new sign-in event(s) checked, risk {result['riskScore']}"
        if result["riskScore"] >= 51 and signature != lg.get("lastSignature"):
            result["explanation"] = _on(dev, result["explanation"])
            if _save_finding(dev, collector="logons", module_id="credential", subtopic_id="failed-logins",
                             subtopic_title="CyberGuard Agent - Windows sign-ins", result=result,
                             target=f"Windows sign-ins on {dev.name}", target_type="text", extra={"events": len(lines)}):
                saved = 1
            lg["lastSignature"] = signature
    st["logons"] = lg
    _record(st, "logons", checked=len(new_lines), findings=saved, note=note)
    _save_state(db, dev, st)
    return {"ok": True, "findings": saved, "checked": len(new_lines)}


class DnsIn(BaseModel):
    names: list[str] = Field(default_factory=list, max_length=MAX_NAMES)


@router.post("/api/agent/dns")
@limiter.limit("10/minute", key_func=_agent_rate_key)
def report_dns(body: DnsIn, request: Request, dev: Device = Depends(agent_device), db: Session = Depends(get_db)):
    from app.automation import dns_watcher as D
    names = list(dict.fromkeys(n.strip().rstrip(".").lower()[:253] for n in body.names if isinstance(n, str)))
    names = [n for n in names if D.worth_checking(n)][:D.MAX_PER_ROUND]
    saved = 0
    for n in names:
        result = D.judge(n)
        if result["riskScore"] < D.REPORT_SCORE:
            continue                                    # judged and forgotten: not stored anywhere
        k = (dev.id, n)
        with _lock:
            if time.time() - _name_reported.get(k, 0) < REPEAT_NAME_H * 3600:
                continue
            _name_reported[k] = time.time()
            if len(_name_reported) > 20000:
                _name_reported.clear()
        result["explanation"] = _on(dev, f"a program looked up the website name {n}. " + result["explanation"])
        if _save_finding(dev, collector="dns", module_id="url-security", subtopic_id="malicious-url",
                         subtopic_title="CyberGuard Agent - websites looked up", result=result, target=n,
                         target_type="url", extra={"name": n}):
            saved += 1
    st = _state(dev)
    _record(st, "dns", checked=len(names), findings=saved, note=f"{len(names)} new website name(s) judged")
    _save_state(db, dev, st)
    return {"ok": True, "findings": saved, "checked": len(names)}


RISKY_EXTENSIONS = {".exe", ".dll", ".scr", ".sys", ".cpl", ".msi", ".msix", ".appx", ".com", ".pif", ".bat", ".cmd",
                    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".sct", ".lnk", ".url",
                    ".reg", ".jar", ".apk", ".zip", ".rar", ".7z", ".gz", ".tgz", ".tar", ".cab", ".iso", ".img", ".vhd",
                    ".vhdx", ".one", ".chm", ".xll", ".xlam", ".docm", ".xlsm", ".pptm", ".dotm", ".ppsm", ".doc", ".xls",
                    ".ppt", ".rtf", ".html", ".htm", ".svg", ".mht", ".iqy", ".slk"}


@router.post("/api/agent/file")
@limiter.limit("30/minute", key_func=_agent_rate_key)
async def report_file(request: Request, file: UploadFile = File(...), dev: Device = Depends(agent_device),
                      db: Session = Depends(get_db)):
    from fastapi.concurrency import run_in_threadpool
    from app.automation.downloads_watcher import scan_file
    s = get_settings()
    # the original name matters to the checks (invoice.pdf.exe), so it is kept - cleaned of path parts / odd signs
    name = os.path.basename((file.filename or "download").replace("\\", "/"))[:200]
    name = re.sub(r'[\x00-\x1f<>:"/\\|?*]', "_", name).strip(" .") or "download"
    max_bytes = s.MAX_UPLOAD_MB * 1024 * 1024
    data = await file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise _err("FILE_TOO_LARGE", f"Files over {s.MAX_UPLOAD_MB} MB are not checked.", 413)
    folder = Path(s.UPLOAD_DIR) / f"agent_{uuid.uuid4().hex}"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name                    # a fresh folder of its own, so the name can stay as it was
    try:
        path.write_bytes(data)
        os.chmod(path, 0o600)
        result = await run_in_threadpool(scan_file, path)
    finally:
        try:
            path.unlink(missing_ok=True)
            folder.rmdir()
        except OSError:
            pass
    saved = 0
    if result["riskScore"] >= 26:
        result["explanation"] = _on(dev, f"the new download {name} was checked. " + result["explanation"])
        result["threatType"] = "Malware Detection (CyberGuard Agent download)"
        if await run_in_threadpool(_save_finding, dev, collector="downloads", module_id="cyber-threat",
                                   subtopic_id="malware-detection", subtopic_title="CyberGuard Agent - downloads",
                                   result=result, target=f"{dev.name}: {name}", target_type="file",
                                   extra={"sha256": result.get("sha256", "")}):
            saved = 1
    st = _state(dev)
    recent = list((st.get("downloads") or {}).get("recent") or [])[-19:]
    recent.append({"name": name, "score": result["riskScore"], "at": _now().isoformat()})
    st["downloads"] = {"recent": recent}
    _record(st, "downloads", checked=1, findings=saved, note=f"{name}: risk {result['riskScore']}")
    _save_state(db, dev, st)
    return {"ok": True, "findings": saved, "riskScore": result["riskScore"], "classification": result["classification"]}


# ---- Devices page (signed-in people) -------------------------------------------------------------------------------
class DeviceIn(BaseModel):
    name: str = Field(default="My PC", max_length=60)
    userId: str | None = Field(default=None, max_length=40)


def _visible(db, user: User):
    q = db.query(Device).filter(Device.revoked.is_(False))
    return q if is_admin(user, db) else q.filter(Device.user_id == user.id)


def _findings_q(db, dev: Device):
    return db.query(Scan).filter(Scan.user_id == dev.user_id, Scan.input_metadata["deviceId"].as_string() == dev.id)


def _device_out(db, dev: Device, owners: dict) -> dict:
    last = _aware(dev.last_seen_at)
    online = last is not None and (_now() - last).total_seconds() <= ONLINE_SECONDS
    since = _now() - timedelta(days=1)
    fq = _findings_q(db, dev)
    newest = fq.order_by(Scan.created_at.desc()).first()
    owner = owners.get(dev.user_id)
    st = dev.state or {}
    net = (st.get("network") or {}).get("last") or {}
    return {"id": dev.id, "name": dev.name, "hostname": dev.hostname or "", "os": dev.os or "",
            "agentVersion": dev.agent_version or "", "createdAt": _iso(dev.created_at), "lastSeen": _iso(dev.last_seen_at),
            "lastIp": dev.last_ip or "", "online": online, "paired": dev.last_seen_at is not None,
            "owner": {"id": dev.user_id, "name": owner.name if owner else "", "email": owner.email if owner else ""},
            "findings24h": fq.filter(Scan.created_at >= since).count(), "findingsTotal": fq.count(),
            "highestRisk24h": int(fq.filter(Scan.created_at >= since).with_entities(func.max(Scan.risk_score)).scalar() or 0),
            "lastFinding": ({"title": newest.target, "risk": newest.risk_score, "at": _iso(newest.created_at)}
                            if newest else None),
            "collectors": st.get("collectors") or {}, "collectorsAvailable": st.get("collectorsAvailable") or [],
            "network": {"summary": net.get("summary"), "takenAt": net.get("takenAt")} if net else None}


@router.get("/api/devices")
def list_devices(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    devs = _visible(db, user).order_by(Device.created_at.asc()).all()
    owners = {u.id: u for u in db.query(User).filter(User.id.in_(sorted({d.user_id for d in devs}) or [""]))}
    rows = [_device_out(db, d, owners) for d in devs]
    return {"admin": is_admin(user, db), "devices": rows,
            "summary": {"total": len(rows), "online": sum(r["online"] for r in rows),
                        "withFindings24h": sum(1 for r in rows if r["findings24h"]),
                        "findings24h": sum(r["findings24h"] for r in rows)}}


def _get_visible(db, user: User, device_id: str) -> Device:
    dev = _visible(db, user).filter(Device.id == device_id).first()
    if dev is None:
        raise _err("NOT_FOUND", "No such device.", 404)
    return dev


@router.get("/api/devices/{device_id}")
def device_detail(device_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    dev = _get_visible(db, user, device_id)
    owners = {dev.user_id: db.get(User, dev.user_id)}
    out = _device_out(db, dev, owners)
    st = dev.state or {}
    out["networkLast"] = (st.get("network") or {}).get("last")
    out["recentDownloads"] = (st.get("downloads") or {}).get("recent") or []
    out["findings"] = [{"id": s.id, "title": s.target, "risk": s.risk_score, "classification": s.classification,
                        "threatType": s.threat_type, "collector": (s.input_metadata or {}).get("collector", ""),
                        "at": _iso(s.created_at), "explanation": (s.explanation or "")[:400]}
                       for s in _findings_q(db, dev).order_by(Scan.created_at.desc()).limit(50)]
    return out


@router.post("/api/devices", status_code=201)
@limiter.limit("10/minute")
def create_device(body: DeviceIn, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    owner_id = user.id
    if body.userId and body.userId != user.id:
        if not is_admin(user, db):
            raise _err("ADMIN_ONLY", "Only an administrator can add a PC for someone else.", 403)
        target = db.get(User, body.userId)
        if target is None or target.is_active is False:
            raise _err("NOT_FOUND", "No such (active) employee.", 404)
        owner_id = target.id
    if db.query(Device).filter(Device.user_id == owner_id, Device.revoked.is_(False)).count() >= MAX_DEVICES_PER_PERSON:
        raise _err("TOO_MANY_DEVICES", f"At most {MAX_DEVICES_PER_PERSON} PCs per person. Remove an old one first.", 409)
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    dev = Device(user_id=owner_id, name=(body.name or "My PC").strip()[:60] or "My PC", token_hash=_hash(key),
                 created_by=user.id, state={})
    db.add(dev)
    db.flush()
    audit.log(db, action="device.created", user=user, request=request, target=dev.name, detail={"owner": owner_id})
    db.commit()
    server = get_settings().APP_BASE_URL.rstrip("/")
    return {"id": dev.id, "name": dev.name, "key": key, "server": server,
            "note": "Copy this key into the CyberGuard Agent on that PC now: it is shown only once."}


@router.delete("/api/devices/{device_id}")
def remove_device(device_id: str, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    dev = _get_visible(db, user, device_id)
    dev.revoked = True
    audit.log(db, action="device.removed", user=user, request=request, target=dev.name, detail={"owner": dev.user_id})
    db.commit()
    return {"id": dev.id, "removed": True}
