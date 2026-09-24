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


async def check_urlhaus(url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url})
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
