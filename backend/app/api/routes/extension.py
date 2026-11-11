"""
(6 Nov) CyberGuard browser extension (Chrome, Edge, Brave, Opera, Firefox): connection keys + live page checks.

Connecting: in Settings the signed-in user makes a connection key (shown ONCE; only its SHA-256 hash is stored) and
pastes it into the extension. Deleting the key disconnects that browser at once.

Checking (header X-CyberGuard-Extension: <key>):
  POST /api/extension/check  {url, redirects?: [...], html?: "<page code>"}
    * the address (and every redirect hop) is judged by the URL engine in its no-network mode: models + rules only,
      CyberGuard does not contact the website;
    * html is sent only for pages that ask for a password / card / OTP: judged by the fake-login-page model;
    * verdict: safe (< 51) / verify (51-70) / danger (71+). A danger verdict is saved as a finding (once per site and
      day) and goes through the usual alert limits.
Private / local addresses and CyberGuard's own pages are never judged.
"""
import hashlib
import ipaddress
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.core.rate_limit import limiter
from app.db.database import SessionLocal, get_db
from app.db.models import ExtensionToken, User
from app.services import audit

router = APIRouter(prefix="/api/extension", tags=["extension"])
MAX_TOKENS = 5
DANGER, VERIFY = 71, 51
_cache: dict[str, tuple[float, dict]] = {}        # url -> (time, verdict), 10 minutes
_reported: dict[tuple[str, str], float] = {}      # (user, host) -> time of the last saved finding
_lock = threading.Lock()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _err(code: str, message: str, status: int):
    return HTTPException(status_code=status, detail={"error": {"code": code, "message": message}})


# ---- connection keys (signed-in user) --------------------------------------------------------------------------
class TokenIn(BaseModel):
    label: str = Field(default="Browser", max_length=60)


@router.post("/tokens", status_code=201)
@limiter.limit("10/minute")
def make_token(body: TokenIn, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if db.query(ExtensionToken).filter(ExtensionToken.user_id == user.id).count() >= MAX_TOKENS:
        raise _err("TOO_MANY_KEYS", f"At most {MAX_TOKENS} browsers can be connected. Delete an old key first.", 409)
    token = "cgx_" + secrets.token_urlsafe(32)
    row = ExtensionToken(user_id=user.id, token_hash=_hash(token), label=(body.label or "Browser").strip()[:60] or "Browser")
    db.add(row)
    audit.log(db, action="extension.key_created", user=user, request=request, target=row.label)
    db.commit()
    return {"id": row.id, "label": row.label, "token": token,
            "note": "Copy this key into the CyberGuard extension now: it is shown only once."}


@router.get("/tokens")
def list_tokens(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(ExtensionToken).filter(ExtensionToken.user_id == user.id).order_by(ExtensionToken.created_at).all()
    return [{"id": r.id, "label": r.label, "createdAt": r.created_at.isoformat() if r.created_at else None,
             "lastUsedAt": r.last_used_at.isoformat() if r.last_used_at else None} for r in rows]


@router.delete("/tokens/{token_id}")
def delete_token(token_id: str, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.query(ExtensionToken).filter(ExtensionToken.id == token_id, ExtensionToken.user_id == user.id).first()
    if not row:
        raise _err("NOT_FOUND", "Key not found.", 404)
    db.delete(row)
    audit.log(db, action="extension.key_deleted", user=user, request=request, target=row.label)
    db.commit()
    return {"deleted": True}


# ---- the extension's own calls ---------------------------------------------------------------------------------
def extension_user(x_cyberguard_extension: str = Header(default=""), db: Session = Depends(get_db)) -> str:
    key = (x_cyberguard_extension or "").strip()
    if not key.startswith("cgx_") or len(key) > 100:
        raise _err("EXTENSION_NOT_CONNECTED", "Connect the extension with a key from CyberGuard Settings.", 401)
    row = db.query(ExtensionToken).filter(ExtensionToken.token_hash == _hash(key)).first()
    if not row:
        raise _err("EXTENSION_NOT_CONNECTED", "This key was deleted or is wrong. Make a new one in Settings.", 401)
    now = datetime.now(timezone.utc)
    last = row.last_used_at if (row.last_used_at is None or row.last_used_at.tzinfo) else row.last_used_at.replace(tzinfo=timezone.utc)
    if last is None or now - last > timedelta(minutes=5):
        row.last_used_at = now
        db.commit()
    return row.user_id


@router.get("/ping")
@limiter.limit("60/minute")
def ping(request: Request, user_id: str = Depends(extension_user)):
    return {"connected": True}


class CheckIn(BaseModel):
    url: str = Field(max_length=4096)
    redirects: list[str] = Field(default_factory=list, max_length=10)
    html: str | None = Field(default=None, max_length=400_000)
    title: str = Field(default="", max_length=300)


def skip_reason(url: str) -> str | None:
    """Why an address is not judged (None = judge it)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "not a web address"
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return "not a web page"
    host = parts.hostname.lower().rstrip(".")
    if host in ("localhost",) or host.endswith((".local", ".localhost", ".internal", ".lan")):
        return "a page on this computer or network"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "a page on this computer or network"
    except ValueError:
        pass
    return None


def judge(url: str, redirects: list[str], html: str | None) -> dict:
    from app.detectors import fake_login, malicious_url, trusted_domains
    key = f"{url}|{'>'.join(redirects)}|{bool(html)}"
    with _lock:
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < 600:
            return hit[1]
    result = malicious_url.analyze_url(url, "Website opened in the browser", subtopic_id="malicious-url", network=False)
    hops = []
    for hop in [r for r in redirects if r and r != url and not skip_reason(r)][:5]:
        h = malicious_url.analyze_url(hop, "Redirect step", subtopic_id="malicious-url", network=False)
        hops.append({"url": hop[:300], "score": h["riskScore"]})
        if h["riskScore"] >= VERIFY:
            result["indicators"].append({"id": f"IND_hop_{len(hops)}", "label": "Redirect through a risky address",
                                         "description": f"On the way here the browser was sent through {hop[:150]}, "
                                                        f"which scores {h['riskScore']}/100.",
                                         "severity": "high", "weight": 15, "triggered": True})
            result["riskScore"] = max(result["riskScore"], h["riskScore"])
    page = None
    if html and not trusted_domains.is_trusted(url):
        page = fake_login.assess(html, url)
        if page and page["level"] in ("high", "medium"):
            why = "; ".join(fake_login.reasons(page["facts"])[:3]) or "it looks like known fake login pages"
            score = 90 if page["level"] == "high" else 60
            result["indicators"].append({"id": "IND_page_login", "label": "Fake login page model: " +
                                         ("looks like a fake login page" if page["level"] == "high" else "check this page"),
                                         "description": f"The page asks for your details and {why}.",
                                         "severity": "critical" if page["level"] == "high" else "medium",
                                         "weight": 30, "triggered": True})
            result["riskScore"] = max(result["riskScore"], score)
    score = int(result["riskScore"])
    level = "danger" if score >= DANGER else "verify" if score >= VERIFY else "safe"
    reasons = [i["label"] for i in sorted((i for i in result["indicators"] if i.get("triggered")),
                                          key=lambda i: -i.get("weight", 0))][:4]
    out = {"level": level, "score": score, "host": (urlsplit(url).hostname or "")[:253], "reasons": reasons,
           "explanation": result["explanation"][:400], "redirects": hops, "pageChecked": page is not None,
           "_result": result}
    with _lock:
        if len(_cache) > 5000:
            _cache.clear()
        _cache[key] = (time.time(), out)
    return out


def _masked(url: str) -> str:
    """The address with secret-looking link values (token=, code=, password= ...) replaced by ***."""
    from app.services.request_log import _mask
    base, sep, query = url.partition("?")
    query, hsep, frag = query.partition("#")
    return base + (sep + _mask(query) if sep else "") + (hsep + "***" if hsep and frag else "")


def _save_finding(user_id: str, url: str, verdict: dict) -> str | None:
    """Danger verdicts become a finding (once per site and day) and use the usual automatic-alert limits."""
    from app.services import notifier, scan_store
    k = (user_id, verdict["host"])
    with _lock:
        if time.time() - _reported.get(k, 0) < 86400:
            return None
        _reported[k] = time.time()
    url = _masked(url)                       # tokens / codes in the link are never saved
    db = SessionLocal()
    try:
        result = dict(verdict["_result"], riskScore=verdict["score"])
        result["explanation"] = f"Opened in your browser: {url[:200]}. " + result["explanation"]
        scan = scan_store.save_result(db, user_id=user_id, module_id="url-security", subtopic_id="malicious-url",
                                      subtopic_title="Browser extension (automatic)", result=result, target=url[:500],
                                      target_type="url", metadata={"automatic": True, "browser": True},
                                      source="automation:browser")
        db.commit()
        scan_id = scan.id
    finally:
        db.close()
    if verdict["score"] >= notifier.ALERT_FLOOR:
        notifier.alert_for_scan(scan_id)
    return scan_id


class ReputationIn(BaseModel):
    url: str = Field(max_length=4096)


def reputation(url: str) -> dict:
    """(11 Nov) What VirusTotal, URLhaus and AbuseIPDB know about the SITE (opt-in in the extension). Only the site
    name goes to VirusTotal / URLhaus; AbuseIPDB gets the server address the name resolves to. The website itself is
    never contacted. Well-known official sites are not looked up (saves the free quotas)."""
    from concurrent.futures import ThreadPoolExecutor
    from app.detectors import trusted_domains
    from app.detectors.url_features_v2 import registered_domain
    from app.services import network_intel, threat_intelligence as TI
    host = (urlsplit(url).hostname or "").lower().rstrip(".")[:253]
    site = registered_domain(host) or host
    out = {"host": host, "site": site, "level": "safe", "notes": []}
    if trusted_domains.is_trusted(url):
        out["notes"].append("Well-known official site - the outside services were not asked (saves your free limits).")
        out["trusted"] = True
        return out
    with ThreadPoolExecutor(max_workers=3) as pool:
        vt_f = pool.submit(TI.check_virustotal_domain_sync, site)
        uh_f = pool.submit(TI.check_urlhaus_host_sync, host)
        dns = network_intel.resolve_domain(host) if not _is_ip(host) else {"ips": [host]}
        ips = (dns.get("ips") or []) if isinstance(dns, dict) else []
        ip = next((a for a in ips if "." in a), ips[0] if ips else None)
        ab = TI.check_abuseipdb_sync(ip) if ip else {"status": "skipped"}
        vt, uh = vt_f.result(), uh_f.result()
    out |= {"virustotal": vt, "urlhaus": uh, "abuseipdb": {k: ab.get(k) for k in
                                                         ("status", "ip", "abuseScore", "totalReports", "isWhitelisted", "isp")}}
    danger = verify = False
    if vt.get("status") == "ok" and vt.get("malicious", 0) + vt.get("suspicious", 0) > 0:
        votes = vt["malicious"] + vt["suspicious"]
        danger |= vt["malicious"] >= 3
        verify |= votes >= 1
        out["notes"].append(f"VirusTotal: {votes} of {vt['total']} security vendors flag {site}.")
    if uh.get("status") == "ok" and uh.get("listed"):
        danger |= uh.get("online", 0) > 0
        verify = True
        out["notes"].append(f"URLhaus: {host} is on the malware list ({uh['urlCount']} link(s), {uh['online']} still "
                            f"online{', ' + ', '.join(uh['threats']) if uh.get('threats') else ''}).")
    if ab.get("status") == "ok" and not ab.get("isWhitelisted") and ab.get("abuseScore", 0) >= 75 and ab.get("totalReports", 0) >= 5:
        verify |= _is_ip(host)                     # a named site may share its server with others: a note only
        out["notes"].append(f"AbuseIPDB: its server {ab['ip']} has an abuse score of {ab['abuseScore']}% "
                            f"({ab['totalReports']} reports in 90 days)" + ("." if _is_ip(host) else
                            " - shared servers can host good and bad sites, so this alone is not a verdict."))
    out["level"] = "danger" if danger else "verify" if verify else "safe"
    return out


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


@router.post("/reputation")
@limiter.limit("60/minute")
async def site_reputation(body: ReputationIn, request: Request, user_id: str = Depends(extension_user)):
    why = skip_reason(body.url)
    if why:
        return {"level": "skip", "reason": why}
    out = await run_in_threadpool(reputation, body.url)
    if out["level"] == "danger":
        from app.detectors.base import build_result
        result = build_result(indicators=[
            {"id": f"IND_rep_{i}", "label": "Listed by a threat-intelligence service", "description": n[:300],
             "severity": "critical", "weight": 35, "triggered": True} for i, n in enumerate(out["notes"])],
            base_score=90, confidence=85, engine_name="CyberGuard browser extension (threat feeds)",
            threat_type="Malicious URL", explanation=" ".join(out["notes"])[:400])
        out["savedAsFinding"] = bool(await run_in_threadpool(
            _save_finding, user_id, body.url, {"host": out["host"], "score": 90, "_result": result}))
    return out


@router.post("/check")
@limiter.limit("300/minute")
async def check(body: CheckIn, request: Request, user_id: str = Depends(extension_user)):
    why = skip_reason(body.url)
    if why:
        return {"level": "skip", "score": 0, "reason": why}
    verdict = await run_in_threadpool(judge, body.url, body.redirects, body.html)
    saved = None
    if verdict["level"] == "danger":
        saved = await run_in_threadpool(_save_finding, user_id, body.url, verdict)
    return {k: v for k, v in verdict.items() if k != "_result"} | {"savedAsFinding": bool(saved)}
