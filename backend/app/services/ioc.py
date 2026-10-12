"""
Indicators of Compromise (IOCs): CyberGuard's memory of bad things it has already seen.

Every scan (manual or automatic) goes through two steps in app/services/scan_store.py:
  1. LOOK UP  -- pull the observables out of the scan (URLs, domains, IPs, sender addresses, file
                 hashes) and check them against IOCs from EARLIER risky scans. A match adds the
                 indicator "Seen before in an earlier threat" and raises the risk score.
  2. REMEMBER -- if this scan is risky (score >= 51), store its observables as IOCs, or update
                 times_seen / last_seen / max_risk if they are already known.

Never stored as IOCs: well-known official sites (trusted list), free-mail providers' domains
(gmail.com, outlook.com ...), private/local IP addresses. Anything the user marks "allowlisted"
is ignored from then on (false-positive control).
"""
import ipaddress
import re
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from app.db.models import IOC

MIN_RISK_TO_RECORD = 51
FREEMAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "yahoo.co.in",
            "rediffmail.com", "icloud.com", "proton.me", "protonmail.com", "aol.com", "zoho.com", "gmx.com",
            "mail.com", "yandex.com"}
# How much a match raises the score: a known bad file or link is stronger proof than a known sender.
BOOST = {"sha256": 30, "url": 25, "ip": 20, "domain": 20, "email": 15}
LABEL = {"sha256": "file", "url": "link", "ip": "IP address", "domain": "domain", "email": "sender"}

_URL_RE = re.compile(r"https?://[^\s\"'<>()\]]+", re.I)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_SHA_RE = re.compile(r"\b[a-f0-9]{64}\b", re.I)


def _now():
    return datetime.now(timezone.utc)


def _public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast or a.is_unspecified)


def _site(host: str) -> str:
    from app.detectors.domain_model import site_parts
    try:
        return site_parts(host)["site"]
    except Exception:
        return host


def _trusted(site: str) -> bool:
    from app.detectors import trusted_domains
    return trusted_domains.is_trusted(f"https://{site}/")


def _add_url(out: set, url: str) -> None:
    from app.detectors.url_features_v2 import split_url
    url = url.strip().rstrip(".,;)")
    host = split_url(url)["host"]
    if not host:
        return
    if _IP_RE.fullmatch(host):
        if _public_ip(host):
            out.add(("ip", host))
            out.add(("url", url[:1000].lower()))
        return
    site = _site(host)
    if _trusted(site) and not _trusted_redirect(url):
        return
    out.add(("url", url[:1000].lower()))
    out.add(("domain", site))


def _trusted_redirect(url: str) -> bool:
    """A trusted site that forwards to an untrusted one is still worth remembering."""
    from app.detectors import trusted_domains
    return not trusted_domains.is_trusted(url)


def candidates(result: dict, target: str, module_id: str) -> set[tuple[str, str]]:
    """Every observable in a scan, normalised: {(type, value)}."""
    out: set[tuple[str, str]] = set()
    text = str(target or "")
    if module_id in ("url-security",) or (module_id == "phishing" and "://" in text and " " not in text.strip()):
        _add_url(out, text if "://" in text else "http://" + text)
    for u in _URL_RE.findall(text):
        _add_url(out, u)
    for ip in _IP_RE.findall(text):
        if _public_ip(ip):
            out.add(("ip", ip))
    for sha in _SHA_RE.findall(text):
        out.add(("sha256", sha.lower()))
    em = result.get("email") or {}
    if em:
        sender = (em.get("from_address") or "").strip().lower()
        if _EMAIL_RE.fullmatch(sender or "-"):
            out.add(("email", sender))
            dom = sender.split("@", 1)[1]
            if dom not in FREEMAIL and not _trusted(_site(dom)):
                out.add(("domain", _site(dom)))
        for link in em.get("links", [])[:50]:
            if isinstance(link, dict) and link.get("url"):
                _add_url(out, link["url"])
        ip = em.get("originating_ip") or ""
        if _public_ip(ip):
            out.add(("ip", ip))
        for a in em.get("attachments", []):
            if isinstance(a, dict) and a.get("sha256") and not a.get("is_inline"):
                out.add(("sha256", a["sha256"].lower()))
    if result.get("sha256"):
        out.add(("sha256", str(result["sha256"]).lower()))
    return out


def lookup(db, user_id: str, cands: set) -> list[IOC]:
    """Active IOCs (from earlier risky scans) that match this scan's observables."""
    if not cands:
        return []
    hits = []
    by_type: dict[str, list[str]] = {}
    for t, v in cands:
        by_type.setdefault(t, []).append(v)
    for t, values in by_type.items():
        hits += (db.query(IOC).filter(IOC.user_id == user_id, IOC.ioc_type == t, IOC.value.in_(values[:200]),
                                      IOC.status == "active").all())
    return hits


def apply_seen_before(result: dict, hits: list[IOC]) -> None:
    """Add the 'seen before' indicator and raise the score (never lowers it)."""
    import uuid

    from app.services.risk_scoring import classify_risk, severity_from_classification
    if not hits:
        return
    hits = sorted(hits, key=lambda h: (-BOOST.get(h.ioc_type, 15), -h.max_risk))
    top = hits[0]
    boost = max(BOOST.get(h.ioc_type, 15) for h in hits)
    names = ", ".join(f"{LABEL.get(h.ioc_type, h.ioc_type)} {h.value[:60]} (seen {h.times_seen}x, max risk {h.max_risk})"
                      for h in hits[:3])
    result["indicators"].append({
        "id": f"IND_{uuid.uuid4().hex[:12]}", "label": "Seen before in an earlier threat",
        "description": f"CyberGuard already recorded {len(hits)} indicator(s) from earlier risky scans: {names}.",
        "severity": "high" if top.max_risk >= 71 else "medium", "weight": boost, "triggered": True,
    })
    old = int(result.get("riskScore", 0))
    new = min(100, old + boost)
    if top.max_risk >= 71:
        new = max(new, 60)                     # a known high-risk indicator is never "low risk"
    if new > old:
        result["riskScore"] = new
        result["classification"] = classify_risk(new)
        result["severity"] = severity_from_classification(result["classification"])
    result["explanation"] = (result.get("explanation", "") +
                             f" It also matches {len(hits)} indicator(s) seen in earlier threats.").strip()
    result["iocHits"] = [{"type": h.ioc_type, "value": h.value[:200], "timesSeen": h.times_seen,
                          "maxRisk": h.max_risk} for h in hits[:10]]


def record(db, user_id: str, scan_id: str, module_id: str, result: dict, cands: set) -> int:
    """Remember the observables of a risky scan. Returns how many IOCs were created or updated."""
    risk = int(result.get("riskScore", 0))
    if risk < MIN_RISK_TO_RECORD or not cands:
        return 0
    n = 0
    for t, v in sorted(cands):
        try:
            with db.begin_nested():            # one bad row (e.g. a race) never breaks the scan
                row = db.query(IOC).filter(IOC.user_id == user_id, IOC.ioc_type == t, IOC.value == v).first()
                if row is None:
                    db.add(IOC(user_id=user_id, ioc_type=t, value=v, max_risk=risk, modules=[module_id],
                               first_scan_id=scan_id, last_scan_id=scan_id, first_seen=_now(), last_seen=_now()))
                elif row.status == "active":
                    row.times_seen += 1
                    row.last_seen = _now()
                    row.max_risk = max(row.max_risk, risk)
                    row.last_scan_id = scan_id
                    if module_id not in (row.modules or []):
                        row.modules = list(row.modules or []) + [module_id]
                else:
                    continue                    # allowlisted by the user
            n += 1
        except IntegrityError:
            continue
    return n


def to_dict(row: IOC) -> dict:
    def iso(d):
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).isoformat() if d else None
    return {"id": row.id, "type": row.ioc_type, "value": row.value, "status": row.status,
            "timesSeen": row.times_seen, "maxRisk": row.max_risk, "modules": row.modules or [],
            "firstSeen": iso(row.first_seen), "lastSeen": iso(row.last_seen), "lastScanId": row.last_scan_id,
            "note": row.note}
