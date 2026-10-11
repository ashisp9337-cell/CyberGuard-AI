"""
Safe, read-only fetch of a suspicious URL: follows redirects and returns the page HTML as TEXT.

Used for two URL subtopics that cannot be judged from the address alone:
  * Redirect analysis   -- where does this link REALLY lead? (every hop is recorded)
  * Fake login page     -- does the final page ask for a password / card / OTP?

SAFETY (this code talks to attacker-controlled servers, so it is deliberately paranoid):
  * Nothing is executed: no JavaScript, no browser. The page is only read as text and parsed.
  * Nothing is saved to disk. At most MAX_BYTES of the page is read into memory, then dropped.
  * No cookies, no logins, no form submission. Only GET, with an honest scanner User-Agent.
  * Only http/https on the normal web ports (80, 443, 8080, 8443).
  * Never connects to private / local / reserved addresses (127.x, 10.x, 192.168.x, 169.254.x ...):
    an attacker's link cannot make this scanner poke at your own computer or home network (SSRF).
    Checked on EVERY hop, so a redirect cannot sneak in a local address either.
  * Hard limits: MAX_HOPS redirects, TIMEOUT seconds per request, MAX_BYTES per page.
  * TLS certificates are verified (an invalid certificate is reported, the page is not fetched).
  * Can be switched off with LIVE_PAGE_CHECKS=false in backend/.env.
The site you scan can see your public IP address -- the same as for any online URL scanner.
"""
import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse

MAX_HOPS = 5
TIMEOUT = 5.0
MAX_BYTES = 300_000
ALLOWED_PORTS = {None, 80, 443, 8080, 8443}
USER_AGENT = "Mozilla/5.0 (compatible; CyberGuard-URL-Scanner/1.0; read-only security check)"

_META_REFRESH = re.compile(r"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?\s*\d*\s*;?\s*url\s*=\s*([^"'>\s]+)""", re.I)
_JS_LOCATION = re.compile(r"""(?:window\.|document\.|top\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*["'](https?://[^"']+)["']""", re.I)


def _public_ips(host: str) -> tuple[bool, str]:
    """(True, '') if every address the host resolves to is a public internet address."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False, "does not resolve"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
                or ip.is_unspecified or (ip.version == 6 and ip.ipv4_mapped and not ip.ipv4_mapped.is_global)):
            return False, f"points to a private/local address ({ip})"
    return True, ""


def _check(url: str) -> str:
    """'' if the URL may be fetched, else the reason it is refused."""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return f"scheme '{p.scheme}' is not fetched"
    try:
        port = p.port
    except ValueError:
        return "invalid port"
    if port not in ALLOWED_PORTS:
        return f"port {port} is not fetched"
    if not p.hostname:
        return "no host"
    ok, why = _public_ips(p.hostname)
    return "" if ok else why


def fetch(url: str) -> dict:
    """Follow the link safely. Returns
    {'status': 'ok'|'refused'|'error', 'chain': [{'url','status','how'}], 'final_url', 'html', 'reason'}."""
    import requests

    url = url if "://" in url else "http://" + url
    chain, current, how = [], url, "start"
    for _ in range(MAX_HOPS + 1):
        why = _check(current)
        if why:
            chain.append({"url": current, "status": None, "how": how})
            return {"status": "refused", "chain": chain, "final_url": current, "html": "", "reason": why}
        try:
            with requests.get(current, allow_redirects=False, timeout=(3.0, TIMEOUT), stream=True, verify=True,
                              headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"}) as r:
                ctype = r.headers.get("Content-Type", "")
                body = b""
                if "html" in ctype.lower() or not ctype:
                    body = r.raw.read(MAX_BYTES, decode_content=True) or b""
                status, location = r.status_code, r.headers.get("Location")
                encoding = r.encoding or "utf-8"
        except requests.exceptions.SSLError as e:
            chain.append({"url": current, "status": None, "how": how})
            return {"status": "error", "chain": chain, "final_url": current, "html": "",
                    "reason": f"TLS certificate problem: {str(e)[:160]}"}
        except requests.exceptions.RequestException as e:
            chain.append({"url": current, "status": None, "how": how})
            return {"status": "error", "chain": chain, "final_url": current, "html": "", "reason": str(e)[:200]}
        chain.append({"url": current, "status": status, "how": how})
        if 300 <= status < 400 and location:
            current, how = urljoin(current, location), f"HTTP {status} redirect"
            continue
        html = body.decode(encoding, errors="replace")
        nxt = _META_REFRESH.search(html[:20000]) or _JS_LOCATION.search(html[:20000])
        if nxt and len(html) < 20000:          # a tiny page whose only job is to send you elsewhere
            target = urljoin(current, nxt.group(1).strip("'\""))
            if target != current:
                current, how = target, ("meta-refresh redirect" if nxt.re is _META_REFRESH else "JavaScript redirect")
                continue
        return {"status": "ok", "chain": chain, "final_url": current, "html": html, "reason": ""}
    return {"status": "ok", "chain": chain, "final_url": current, "html": "",
            "reason": f"stopped after {MAX_HOPS} redirects"}
