"""
Real, live network intelligence for a domain — DNS resolution, WHOIS
registration age, and SSL certificate inspection.
"""
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timezone

import whois

DNS_TIMEOUT = 2.5
SSL_TIMEOUT = 3.0
WHOIS_TIMEOUT = 4.0


def _run_with_timeout(fn, timeout: float):
    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(fn)
    try:
        return future.result(timeout=timeout)
    except FutureTimeoutError:
        raise TimeoutError(f"Timed out after {timeout}s")
    finally:
        pool.shutdown(wait=False)


def resolve_domain(domain: str) -> dict:
    try:
        _, _, ip_list = _run_with_timeout(lambda: socket.gethostbyname_ex(domain), DNS_TIMEOUT)
        return {"status": "ok", "ips": ip_list}
    except socket.gaierror as e:
        return {"status": "unresolvable", "reason": str(e)}
    except TimeoutError as e:
        return {"status": "unavailable", "reason": str(e)}
    except Exception as e:
        return {"status": "error", "reason": str(e)}


def get_domain_age(domain: str) -> dict:
    try:
        w = _run_with_timeout(lambda: whois.whois(domain), WHOIS_TIMEOUT)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return {"status": "unavailable", "reason": "No creation date in WHOIS record"}
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - created).days
        return {"status": "ok", "age_days": age_days, "created": created.isoformat(), "registrar": w.registrar}
    except Exception as e:
        return {"status": "unavailable", "reason": str(e)}


def get_ssl_info(domain: str) -> dict:
    def _fetch():
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=SSL_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert()
    try:
        cert = _run_with_timeout(_fetch, SSL_TIMEOUT + 1)
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_until_expiry = (not_after - datetime.now(timezone.utc)).days
        return {"status": "ok", "issuer": issuer.get("organizationName") or issuer.get("commonName") or "Unknown",
                "valid_from": not_before.isoformat(), "valid_until": not_after.isoformat(),
                "days_until_expiry": days_until_expiry, "expired": days_until_expiry < 0,
                "age_days": (datetime.now(timezone.utc) - not_before).days}
    except ssl.SSLCertVerificationError as e:
        return {"status": "invalid_cert", "reason": str(e)}
    except Exception as e:
        return {"status": "unavailable", "reason": str(e)}