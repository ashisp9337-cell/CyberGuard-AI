"""
Domain registration facts from RDAP (the modern WHOIS): when was this domain registered, until when, by which
registrar, with which name servers.

Why it matters: most phishing domains are hours to weeks old and registered for the minimum one year; real
banks, shops and universities have had their domain for years.

RDAP is the official registry record (ICANN requires it for every gTLD; most ccTLDs have it too). The lookup asks
the REGISTRY about the name - it never contacts the suspicious website itself. rdap.org forwards each query to the
right registry. Results are kept in memory for a day, so a domain is looked up at most once per day.

Used by:
  * app/ml/training/collect_domain_facts.py  (collects the training data on your PC)
  * app/detectors/domain_age.py               (live check + trained model in the scanner)
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

RDAP_URL = "https://rdap.org/domain/{}"
TIMEOUT = 12
USER_AGENT = "CyberGuard-Domain-Facts/1.0 (security research; RDAP lookups only)"
CACHE_SECONDS = 24 * 3600
_cache: dict[str, tuple[float, dict]] = {}


def _parse_date(s: str | None):
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            d = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s, fmt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _vcard_name(entity: dict) -> str:
    for item in (entity.get("vcardArray") or [None, []])[1] or []:
        if isinstance(item, list) and len(item) >= 4 and item[0] in ("fn", "org"):
            return str(item[3])
    return ""


def parse_rdap(doc: dict) -> dict:
    """RDAP JSON -> the facts CyberGuard uses (all optional)."""
    events = {}
    for e in doc.get("events") or []:
        action, date = str(e.get("eventAction", "")).lower(), e.get("eventDate")
        if action and date and action not in events:
            events[action] = date
    registrar, iana = "", ""
    for ent in doc.get("entities") or []:
        if "registrar" in [r.lower() for r in ent.get("roles") or []]:
            registrar = _vcard_name(ent) or registrar
            for pid in ent.get("publicIds") or []:
                if "iana" in str(pid.get("type", "")).lower():
                    iana = str(pid.get("identifier", ""))
    return {
        "created": events.get("registration"),
        "expires": events.get("expiration"),
        "updated": events.get("last changed") or events.get("last update of rdap database"),
        "registrar": registrar,
        "registrar_iana": iana,
        "status": [str(s).lower() for s in doc.get("status") or []],
        "nameservers": sorted({str(n.get("ldhName", "")).lower() for n in doc.get("nameservers") or [] if n.get("ldhName")}),
        "dnssec": bool((doc.get("secureDNS") or {}).get("delegationSigned")),
    }


def lookup(domain: str, use_cache: bool = True) -> dict:
    """-> {"domain", "ok", "error", "checked_at", ...facts}. Never raises."""
    domain = (domain or "").strip().lower().rstrip(".")
    now = time.time()
    if use_cache and domain in _cache and now - _cache[domain][0] < CACHE_SECONDS:
        return _cache[domain][1]
    out = {"domain": domain, "ok": False, "error": "", "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    try:
        req = urllib.request.Request(RDAP_URL.format(domain), headers={"User-Agent": USER_AGENT,
                                                                       "Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            doc = json.loads(r.read(2_000_000).decode("utf-8", errors="replace"))
        out.update(parse_rdap(doc), ok=True)
    except urllib.error.HTTPError as e:
        out["error"] = "not found in the registry" if e.code == 404 else f"registry answered HTTP {e.code}"
        out["http_status"] = e.code
    except Exception as e:                         # network down, timeout, bad JSON ...
        out["error"] = f"lookup failed ({e.__class__.__name__})"
    if out["ok"] or out.get("http_status") == 404:
        _cache[domain] = (now, out)
    return out


def age_days(facts: dict, at: datetime | None = None):
    created = _parse_date(facts.get("created"))
    if not created:
        return None
    at = at or _parse_date(facts.get("checked_at")) or datetime.now(timezone.utc)
    return max((at - created).total_seconds() / 86400, 0.0)


def describe_age(days) -> str:
    if days is None:
        return "unknown"
    if days < 1:
        return "less than a day"
    if days < 60:
        return f"{int(days)} day{'s' if int(days) != 1 else ''}"
    if days < 730:
        return f"{int(days // 30)} months"
    return f"{days / 365.25:.0f} years"
