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
    Checked on EVERY hop, so a redirect cannot sneak in a local address either. The connection is then made
    to exactly the address that was checked (no second DNS lookup), so a domain cannot answer "public" to the
    check and "127.0.0.1" to the download ("DNS rebinding").
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


# Well-known NAT64 prefix (RFC 6052). On IPv6-only networks (many Indian mobile / hotspot connections) the DNS
# answers public IPv4 sites with 64:ff9b::<IPv4>: the address is judged by the IPv4 address embedded in it.
NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _bad_ip(ip) -> bool:
    if ip.version == 6 and ip in NAT64:
        return _bad_ip(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
                or ip.is_unspecified or (ip.version == 6 and ip.ipv4_mapped and not ip.ipv4_mapped.is_global))


def _resolve_public(host: str) -> tuple[str | None, str]:
    """(ip, '') with the address to connect to, if EVERY address the host resolves to is public; else (None, why)."""
    ips, why = _resolve_public_all(host)
    return (ips[0] if ips else None), why


def _resolve_public_all(host: str) -> tuple[list[str], str]:
    """([ips to try, IPv4 first then IPv6], '') if EVERY address the host resolves to is public; else ([], why)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return [], "does not resolve"
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if _bad_ip(ip):
            return [], f"points to a private/local address ({ip})"
        if ip not in ips:
            ips.append(ip)
    if not ips:
        return [], "does not resolve"
    v4 = [str(i) for i in ips if i.version == 4][:1]
    v6 = [str(i) for i in ips if i.version == 6][:1]
    return v4 + v6, ""


def _public_ips(host: str) -> tuple[bool, str]:
    """(True, '') if every address the host resolves to is a public internet address."""
    ip, why = _resolve_public(host)
    return ip is not None, why


def _check(url: str) -> str:
    """'' if the URL may be fetched, else the reason it is refused."""
    return _vet(url)[1]


def _vet(url: str) -> tuple[str | None, str]:
    """(ip_to_connect_to, '') if the URL may be fetched, else (None, reason)."""
    ips, why = _vet_all(url)
    return (ips[0] if ips else None), why


def _vet_all(url: str) -> tuple[list[str], str]:
    """([checked ips to try], '') if the URL may be fetched, else ([], reason)."""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return [], f"scheme '{p.scheme}' is not fetched"
    try:
        port = p.port
    except ValueError:
        return [], "invalid port"
    if port not in ALLOWED_PORTS:
        return [], f"port {port} is not fetched"
    if not p.hostname:
        return [], "no host"
    return _resolve_public_all(p.hostname)


class FetchError(Exception):
    def __init__(self, reason: str, tls: bool = False):
        super().__init__(reason)
        self.reason, self.tls = reason, tls


def _get_pinned(url: str, ip: str) -> tuple[int, str | None, str, bytes]:
    """One GET of `url`, connecting ONLY to the already-checked address `ip`. The real host name is still used for
    the Host header and for TLS (SNI + certificate check), so the site answers normally and an invalid
    certificate is still refused. -> (status, Location, Content-Type, body <= MAX_BYTES)."""
    import certifi
    import urllib3
    p = urlparse(url)
    host = p.hostname
    https = p.scheme == "https"
    port = p.port or (443 if https else 80)
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")
    headers = {"Host": host if p.port is None else f"{host}:{p.port}", "User-Agent": USER_AGENT,
               "Accept": "text/html,*/*;q=0.5", "Accept-Encoding": "gzip, deflate"}
    timeout = urllib3.Timeout(connect=3.0, read=TIMEOUT)
    if https:
        pool = urllib3.HTTPSConnectionPool(ip, port, timeout=timeout, retries=False, cert_reqs="CERT_REQUIRED",
                                           ca_certs=certifi.where(), server_hostname=host, assert_hostname=host)
    else:
        pool = urllib3.HTTPConnectionPool(ip, port, timeout=timeout, retries=False)
    try:
        r = pool.urlopen("GET", path, headers=headers, redirect=False, retries=False, preload_content=False)
        try:
            ctype = r.headers.get("Content-Type", "")
            body = b""
            if "html" in ctype.lower() or not ctype:
                body = r.read(MAX_BYTES, decode_content=True) or b""
            return r.status, r.headers.get("Location"), ctype, body
        finally:
            r.release_conn()
    except urllib3.exceptions.SSLError as e:
        raise FetchError(f"TLS certificate problem: {str(e)[:160]}", tls=True) from e
    except urllib3.exceptions.HTTPError as e:
        raise FetchError(str(e)[:200]) from e
    except OSError as e:
        raise FetchError(str(e)[:200]) from e
    finally:
        pool.close()


def _encoding(ctype: str) -> str:
    m = re.search(r"charset=([\w.:-]+)", ctype or "", re.I)
    return m.group(1) if m else "utf-8"


def fetch(url: str) -> dict:
    """Follow the link safely. Returns
    {'status': 'ok'|'refused'|'error', 'chain': [{'url','status','how'}], 'final_url', 'html', 'reason'}."""
    url = url if "://" in url else "http://" + url
    chain, current, how = [], url, "start"
    for _ in range(MAX_HOPS + 1):
        ips, why = _vet_all(current)
        if why:
            chain.append({"url": current, "status": None, "how": how})
            return {"status": "refused", "chain": chain, "final_url": current, "html": "", "reason": why}
        err = None
        for ip in ips:                       # IPv4 first; IPv6 if this network has no working IPv4 (IPv6-only links)
            try:
                status, location, ctype, body = _get_pinned(current, ip)
                encoding = _encoding(ctype)
                err = None
                break
            except FetchError as e:
                err = e
                if e.tls:                    # a certificate problem is the site's answer: never retried
                    break
        if err is not None:
            chain.append({"url": current, "status": None, "how": how})
            return {"status": "error", "chain": chain, "final_url": current, "html": "", "reason": err.reason}
        chain.append({"url": current, "status": status, "how": how})
        if 300 <= status < 400 and location:
            current, how = urljoin(current, location), f"HTTP {status} redirect"
            continue
        try:
            html = body.decode(encoding, errors="replace")
        except LookupError:                                   # unknown charset name from the server
            html = body.decode("utf-8", errors="replace")
        nxt = _META_REFRESH.search(html[:20000]) or _JS_LOCATION.search(html[:20000])
        if nxt and len(html) < 20000:          # a tiny page whose only job is to send you elsewhere
            target = urljoin(current, nxt.group(1).strip("'\""))
            if target != current:
                current, how = target, ("meta-refresh redirect" if nxt.re is _META_REFRESH else "JavaScript redirect")
                continue
        return {"status": "ok", "chain": chain, "final_url": current, "html": html, "reason": ""}
    return {"status": "ok", "chain": chain, "final_url": current, "html": "",
            "reason": f"stopped after {MAX_HOPS} redirects"}
