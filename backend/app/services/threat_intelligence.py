"""
Threat intelligence abstraction over VirusTotal, AbuseIPDB, and URLhaus.
Each provider call is real (httpx to the real API) and gated by an env
var API key. If a key isn't configured, that provider reports
"unavailable" — results are never fabricated.
"""
import httpx
from app.core.config import get_settings

settings = get_settings()


async def check_virustotal_url(url: str) -> dict:
    if not settings.VIRUSTOTAL_API_KEY:
        return {"provider": "virustotal", "status": "unavailable", "reason": "VIRUSTOTAL_API_KEY not configured"}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
            if resp.status_code == 404:
                return {"provider": "virustotal", "status": "not_found"}
            resp.raise_for_status()
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"provider": "virustotal", "status": "ok", "stats": stats}
    except httpx.HTTPError as e:
        return {"provider": "virustotal", "status": "error", "reason": str(e)}


async def check_abuseipdb(ip: str) -> dict:
    if not settings.ABUSEIPDB_API_KEY:
        return {"provider": "abuseipdb", "status": "unavailable", "reason": "ABUSEIPDB_API_KEY not configured"}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {"provider": "abuseipdb", "status": "ok",
                    "abuseScore": data.get("abuseConfidenceScore"), "countryCode": data.get("countryCode")}
    except httpx.HTTPError as e:
        return {"provider": "abuseipdb", "status": "error", "reason": str(e)}


def _urlhaus_headers() -> dict | None:
    """URLhaus (abuse.ch) needs a free Auth-Key since 2025: https://auth.abuse.ch/ . No key -> skip the lookup."""
    key = (settings.URLHAUS_API_KEY or "").strip()
    return {"Auth-Key": key} if key else None


_URLHAUS_OFF = {"provider": "urlhaus", "status": "unavailable", "reason": "URLHAUS_API_KEY not configured"}


async def check_urlhaus(url: str) -> dict:
    headers = _urlhaus_headers()
    if headers is None:
        return dict(_URLHAUS_OFF)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return {"provider": "urlhaus", "status": "ok", "query_status": data.get("query_status"),
                    "threat": data.get("threat")}
    except httpx.HTTPError as e:
        return {"provider": "urlhaus", "status": "error", "reason": str(e)}


async def lookup_url(url: str) -> dict:
    vt = await check_virustotal_url(url)
    uh = await check_urlhaus(url)
    return {"url": url, "virustotal": vt, "urlhaus": uh}

def check_virustotal_url_sync(url: str, timeout: float = 4.0) -> dict:
    if not settings.VIRUSTOTAL_API_KEY:
        return {"provider": "virustotal", "status": "unavailable", "reason": "VIRUSTOTAL_API_KEY not configured"}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
            if resp.status_code == 404:
                return {"provider": "virustotal", "status": "not_found"}
            resp.raise_for_status()
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"provider": "virustotal", "status": "ok", "stats": stats}
    except Exception as e:
        return {"provider": "virustotal", "status": "error", "reason": str(e)}


def check_urlhaus_sync(url: str, timeout: float = 4.0) -> dict:
    headers = _urlhaus_headers()
    if headers is None:
        return dict(_URLHAUS_OFF)
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return {"provider": "urlhaus", "status": "ok", "query_status": data.get("query_status"),
                    "threat": data.get("threat")}
    except Exception as e:
        return {"provider": "urlhaus", "status": "error", "reason": str(e)}


# (11 Nov) AbuseIPDB for the link scan: is the server behind a link reported for abuse? One lookup per address per
# 6 hours (free plan: 1,000 lookups a day); private / reserved addresses are never sent.
_ABUSE_CACHE: dict[str, tuple[float, dict]] = {}
_ABUSE_TTL = 6 * 3600


def check_abuseipdb_sync(ip: str, timeout: float = 4.0) -> dict:
    import ipaddress
    import time
    key = (settings.ABUSEIPDB_API_KEY or "").strip()
    if not key:
        return {"provider": "abuseipdb", "status": "unavailable", "reason": "ABUSEIPDB_API_KEY not configured"}
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"provider": "abuseipdb", "status": "skipped", "reason": "not an IP address"}
    if not addr.is_global:
        return {"provider": "abuseipdb", "status": "skipped", "reason": "private or reserved address"}
    hit = _ABUSE_CACHE.get(str(addr))
    if hit and time.time() - hit[0] < _ABUSE_TTL:
        return hit[1]
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": str(addr), "maxAgeInDays": 90},
                              headers={"Key": key, "Accept": "application/json"})
            resp.raise_for_status()
            d = resp.json().get("data", {}) or {}
    except Exception as e:
        return {"provider": "abuseipdb", "status": "error", "reason": type(e).__name__}
    out = {"provider": "abuseipdb", "status": "ok", "ip": str(addr),
           "abuseScore": int(d.get("abuseConfidenceScore") or 0), "totalReports": int(d.get("totalReports") or 0),
           "isWhitelisted": bool(d.get("isWhitelisted")), "usageType": str(d.get("usageType") or "")[:80],
           "isp": str(d.get("isp") or "")[:80], "countryCode": str(d.get("countryCode") or "")[:4]}
    if len(_ABUSE_CACHE) > 5000:
        _ABUSE_CACHE.clear()
    _ABUSE_CACHE[str(addr)] = (time.time(), out)
    return out


# (11 Nov) Site reputation for the browser extension: only the SITE NAME is sent (never the full address, so no
# page paths, search words or tokens leave this computer). Results are kept 12 hours per site, and VirusTotal is asked
# at most 4 times a minute (its free limit) - over that, the site shows "skipped (free limit)" instead of an error.
_SITE_CACHE: dict[tuple[str, str], tuple[float, dict]] = {}
_SITE_TTL = 12 * 3600
_VT_CALLS: list[float] = []


def _cached(kind: str, name: str):
    import time
    hit = _SITE_CACHE.get((kind, name))
    return hit[1] if hit and time.time() - hit[0] < _SITE_TTL else None


def _remember(kind: str, name: str, out: dict) -> dict:
    import time
    if out.get("status") == "ok":
        if len(_SITE_CACHE) > 20000:
            _SITE_CACHE.clear()
        _SITE_CACHE[(kind, name)] = (time.time(), out)
    return out


_VT_LOCK = __import__("threading").Lock()


def _vt_slot() -> bool:
    import time
    with _VT_LOCK:
        now = time.time()
        _VT_CALLS[:] = [t for t in _VT_CALLS if now - t < 60]
        if len(_VT_CALLS) >= 4:
            return False
        _VT_CALLS.append(now)
        return True


def check_virustotal_domain_sync(domain: str, timeout: float = 5.0) -> dict:
    key = (settings.VIRUSTOTAL_API_KEY or "").strip()
    if not key:
        return {"provider": "virustotal", "status": "unavailable"}
    hit = _cached("vt", domain)
    if hit:
        return hit
    if not _vt_slot():
        return {"provider": "virustotal", "status": "skipped", "reason": "free limit of 4 lookups a minute reached"}
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": key})
            if resp.status_code == 404:
                return _remember("vt", domain, {"provider": "virustotal", "status": "ok", "known": False,
                                                "malicious": 0, "suspicious": 0, "total": 0})
            resp.raise_for_status()
            st = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
    except Exception as e:
        return {"provider": "virustotal", "status": "error", "reason": type(e).__name__}
    return _remember("vt", domain, {"provider": "virustotal", "status": "ok", "known": True,
                                    "malicious": int(st.get("malicious") or 0), "suspicious": int(st.get("suspicious") or 0),
                                    "total": int(sum(v for v in st.values() if isinstance(v, int)))})


def check_urlhaus_host_sync(host: str, timeout: float = 5.0) -> dict:
    headers = _urlhaus_headers()
    if headers is None:
        return dict(_URLHAUS_OFF)
    hit = _cached("uh", host)
    if hit:
        return hit
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": host}, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return {"provider": "urlhaus", "status": "error", "reason": type(e).__name__}
    urls = data.get("urls") or []
    return _remember("uh", host, {"provider": "urlhaus", "status": "ok", "listed": data.get("query_status") == "ok",
                                  "urlCount": int(data.get("url_count") or len(urls) or 0),
                                  "online": sum(1 for u in urls if isinstance(u, dict) and u.get("url_status") == "online"),
                                  "threats": sorted({str(u.get("threat"))[:40] for u in urls
                                                     if isinstance(u, dict) and u.get("threat")})[:3]})
