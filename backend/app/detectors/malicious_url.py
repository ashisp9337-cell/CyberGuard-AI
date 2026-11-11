"""
Malicious URL & website detector (Module 5), shared by every URL subtopic:

  1. Address rules        -- raw IP, '@' trick, odd port, encoding, punycode, long/odd URLs
  2. Who it claims to be  -- brand in a domain it does not own (spoofing), look-alikes (typos,
                             swapped letters, 0/o 1/l), free hosting platforms, security words in the name
  3. Domain-name model    -- trained on real data (PhiUSIIL phishing domains vs PhiUSIIL + Tranco
                             legitimate domains), see app/detectors/domain_model.py
  4. Live checks          -- DNS, WHOIS age, TLS certificate (validity, age), VirusTotal/URLhaus,
                             and a SAFE read-only fetch that follows redirects and inspects the final
                             page for fake-login signs (app/services/safe_fetch.py, page_inspector.py)
The old whole-URL RandomForest models were retired: their training data had format shortcuts
(every "bad" URL started with https://, every "good" one did not) and flagged ~98% of real
popular domains when used without the trusted-site list.
"""
import uuid

from app.core.config import get_settings
from app.detectors.base import build_result
from app.detectors.url_features import extract_url_features, explain_url_features
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from app.services import network_intel, threat_intelligence
from app.detectors import trusted_domains
from app.detectors.url_features import IP_RE
from app.detectors.url_features_v2 import (split_url, SENSITIVE_WORDS, BRAND_DOMAINS, BRAND_ALIASES, REDIRECT_PARAMS, brand_in_host,
                                           is_shortener, registered_domain)
from app.detectors import domain_age, domain_model, page_inspector
from app.services import safe_fetch
import re

settings = get_settings()

# ---- Added 21 Oct after the QR / 2026-link benchmark (offline; no link was opened) -------------------------------
# Free website hosts where anyone can publish a page in minutes. On these the site NAME is chosen by whoever uploaded
# the page, so brand / login words in it are a strong hint. Measured on real 2026 data: brand or login words in the
# name fire on 0.8% of the 4,404 popular real sites on these hosts (Chrome UX Report top-1M, mostly gambling and
# clickbait blogs) and on 23% of the 1,103 phishing sites on them that urlscan.io saw in 2026.
FREE_WEB_HOSTS = frozenset("""vercel.app netlify.app github.io gitlab.io pages.dev workers.dev r2.dev web.app
firebaseapp.com appspot.com glitch.me repl.co replit.app replit.dev webflow.io framer.app framer.website square.site
wixsite.com weebly.com weeblysite.com blogspot.com wordpress.com yolasite.com typedream.app herokuapp.com onrender.com
azurewebsites.net amplifyapp.com pantheonsite.io plesk.page cprapid.com duckdns.org ddns.net trycloudflare.com
dweb.link cf-ipfs.com w3s.link nftstorage.link lovable.app myshopify.com surge.sh fly.dev deno.dev godaddysites.com
mystrikingly.com carrd.co notion.site jimdosite.com webnode.page edgeone.app""".split())
# Words kept only if they are clearly more common in phishing names than in real ones on 2026 data ("update", "auth",
# "sso", "reward", "unlock", "invoice", "bank", "recover" were dropped: real company apps and blogs use them as often).
_HOSTED_LURE_LONG = ("login", "signin", "logon", "verify", "secure", "account", "wallet", "support", "billing", "claim",
                     "refund", "payment", "confirm", "security", "suspend", "webmail", "airdrop", "authenticat")
_HOSTED_LURE_SHORT = frozenset({"kyc", "otp", "usdt", "mfa", "2fa", "pay", "help", "fees"})
HOSTED_NAME_LABEL = "Brand or login words in the name of a free-hosted site"
WP_PLANTED_LABEL = "Web page planted in a WordPress system folder"
DOMAIN_2026_LABEL = "Domain-name model: name looks like 2026 phishing domains - verify"
VERIFY_FLOOR_LABELS = frozenset({HOSTED_NAME_LABEL, WP_PLANTED_LABEL, DOMAIN_2026_LABEL})
# A web page (.html / .php) inside WordPress's own system folders is where phishing kits are dropped on hacked sites.
# Fires on 19 of 288,195 real links (DEPHIDES / CommonCrawl), 0 of 7,698 real urlscan.io links and 0 of 5,005 real QR
# links; on 2-4% of the phishing links in the DEPHIDES, Phishing.Database and quishing (QR) sets.
_WP_PLANTED_RE = re.compile(r"/wp-(?:includes|content|admin)/(?:[^?#]*/)?[^/?#]+\.s?html?(?:[?#]|$)|"
                            r"/wp-(?:includes|content/uploads)/(?:[^?#]*/)?[^/?#]+\.php(?:[?#]|$)", re.I)


# the hosts' own service names (login.wordpress.com is WordPress's real sign-in), never judged as user sites
_HOST_OWN_NAMES = frozenset({"www", "login", "accounts", "account", "auth", "signin", "my", "app", "api", "help",
                             "support", "status", "docs", "blog", "mail", "pay", "secure", "dashboard", "admin"})


def free_host(host: str) -> tuple[str | None, str]:
    """('vercel.app', 'wetransfer-smoky') for a site on a free website host, else (None, '')."""
    host = (host or "").lower().rstrip(".")
    sp = domain_model.site_parts(host)
    pl = sp["platform"]
    if pl:                                    # on the public-suffix list (vercel.app, github.io, ey.r.appspot.com ...)
        base = pl if pl in FREE_WEB_HOSTS else next((f for f in FREE_WEB_HOSTS if pl.endswith("." + f)), None)
    elif sp["site"] in FREE_WEB_HOSTS:        # not on it (weeblysite.com, wordpress.com ...): the sub-domain is the name
        pl = base = sp["site"]
    else:
        return None, ""
    if not base:
        return None, ""
    name = host[: -len(pl) - 1] if host.endswith("." + pl) else ""
    return base, ("" if name in _HOST_OWN_NAMES else name)


def _popular_sites():
    """The 100,000 most popular sites (Tranco), kept inside the look-alike model. Long-lived popular sites are never
    raised to "verify" by the domain-name model alone (steamcommunity.com, gq.com, my.naver.com scored above its 2026
    level). None when that model is missing -> the domain-name model then never raises a score on its own."""
    try:
        from app.detectors import lookalike_domain
        b = lookalike_domain.load_model()
        return b["index_obj"].allow if b and b.get("index_obj") is not None else None
    except Exception:
        return None


def hosted_name_words(host: str) -> tuple[str | None, str | None, str | None]:
    """(platform, brand, login word) found in the uploader-chosen name of a free-hosted site."""
    platform, name = free_host(host)
    if not platform or not name:
        return platform, None, None
    name = name.lower()
    tokens = [t for t in re.split(r"[^a-z0-9]+", name) if t]
    brands = set(BRAND_DOMAINS) | set(BRAND_ALIASES)
    brand = next((t for t in tokens if t in brands), None) or \
        next((b for b in sorted(brands) if len(b) >= 6 and any(b in t and t != b for t in tokens)), None)
    if platform in ("github.io", "gitlab.io"):
        brand = None             # GitHub / GitLab user names: the real organisations own their brand names there
    word = next((w for w in _HOSTED_LURE_LONG if w in name), None) or next((t for t in tokens if t in _HOSTED_LURE_SHORT), None)
    return platform, brand, word

def _registry(host: str):
    """Registry record (RDAP) of the registrable domain + the domain-registration model, or None
    (IP address, shared hosting platform such as *.web.app - its owner's age says nothing about this page)."""
    parts = domain_model.site_parts(host)
    if parts["ip"] or parts["platform"] or not parts["site"] or "." not in parts["site"]:
        return None
    try:
        return domain_age.assess(parts["site"])
    except Exception:          # registry trouble never breaks a scan
        return None


def _live_indicators(url: str, registry_out: dict | None = None) -> list[dict]:
    try:
        host = urlparse(url if "://" in url else f"http://{url}").netloc.split("@")[-1].split(":")[0]
    except ValueError:         # a broken link (e.g. "http://[::1:bad/") is still scored offline; no live lookups
        return []
    if not host:
        return []
    indicators: list[dict] = []
    def add(triggered, label, desc, severity, weight):
        indicators.append({"label": label, "description": desc, "severity": severity, "weight": weight,
                            "triggered": bool(triggered), "id": f"IND_{uuid.uuid4().hex[:12]}"})
    # All lookups run at the same time. WHOIS is the slowest (often 3-4 s, many servers never answer) and only gives
    # the registration date, which the registry (RDAP) lookup also gives: when the registry answered with a date we do
    # NOT wait for WHOIS (it finishes or times out in the background). WHOIS is only waited for as a fallback.
    pool = ThreadPoolExecutor(max_workers=7)
    try:
        dns_f = pool.submit(network_intel.resolve_domain, host)
        abuse_f = pool.submit(_abuse_lookup, host, dns_f)                 # (11 Nov) waits for DNS, then AbuseIPDB
        whois_f = pool.submit(network_intel.get_domain_age, host)
        ssl_f = pool.submit(network_intel.get_ssl_info, host)
        vt_f = pool.submit(threat_intelligence.check_virustotal_url_sync, url)
        uh_f = pool.submit(threat_intelligence.check_urlhaus_sync, url)
        reg_f = pool.submit(_registry, host)
        reg = reg_f.result()
        dns_r, ssl_r, vt_r, uh_r = dns_f.result(), ssl_f.result(), vt_f.result(), uh_f.result()
        ab_r = abuse_f.result()
        if reg and reg.get("ageDays") is not None:
            whois_r = {"status": "ok", "age_days": int(reg["ageDays"])}     # registry date: no need to wait for WHOIS
        else:
            whois_r = whois_f.result()                                       # no registry date: WHOIS is the fallback
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    if registry_out is not None:
        registry_out["registry"] = reg
    if reg and reg.get("sentences"):
        add(False, "Domain registration (registry record)", ". ".join(reg["sentences"]) + ".", "low", 0)
    if dns_r["status"] == "unresolvable":
        add(True, "Domain does not resolve", f"'{host}' does not resolve to any real server right now.", "critical", 30)
    if whois_r["status"] == "ok":
        age = whois_r["age_days"]
        if registry_out is not None:
            registry_out["ageDays"] = age          # (10 Nov) analyze_url uses it: an old domain is no look-alike
        add(age < 30, "Recently registered domain", f"Domain was registered only {age} day(s) ago.", "high", 22)
        add(30 <= age < 90, "Young domain", f"Domain was registered {age} day(s) ago.", "medium", 10)
    if ssl_r["status"] == "ok":
        add(ssl_r["expired"], "Expired SSL certificate", f"Certificate expired {-ssl_r['days_until_expiry']} day(s) ago.", "critical", 25)
        age = ssl_r.get("age_days")
        add(age is not None and age < 3, "Brand-new SSL certificate",
            f"The certificate was issued {age} day(s) ago by {ssl_r.get('issuer')}. Phishing sites usually get a "
            "free certificate minutes before a campaign; real sites also renew, so this alone is a weak signal.",
            "low", 6)
    elif ssl_r["status"] == "invalid_cert":
        add(True, "Invalid/untrusted SSL certificate", ssl_r["reason"], "critical", 28)
    if vt_r.get("status") == "ok":
        stats = vt_r.get("stats", {})
        votes = stats.get("malicious", 0) + stats.get("suspicious", 0)
        add(votes > 0, "Flagged by VirusTotal", f"{votes} vendor(s) flag this as malicious.", "critical", min(35, 15 + votes * 2))
    if uh_r.get("status") == "ok" and uh_r.get("query_status") == "ok":
        add(True, "Listed on URLhaus malware feed", f"Threat type: {uh_r.get('threat')}.", "critical", 35)
    _abuse_indicator(add, ab_r, host)
    return indicators


def _abuse_lookup(host: str, dns_f) -> dict:
    """(11 Nov) AbuseIPDB for the link's server: the address in the link itself, or the first address its name
    resolves to. Skipped (no outside call) without ABUSEIPDB_API_KEY."""
    if not (settings.ABUSEIPDB_API_KEY or "").strip():
        return {"status": "unavailable"}
    ip = host.strip("[]") if IP_RE.match(host) or ":" in host else None
    if ip is None:
        try:
            dns = dns_f.result(timeout=6)
        except Exception:
            return {"status": "error"}
        ips = (dns.get("ips") or []) if isinstance(dns, dict) else []
        ip = next((a for a in ips if "." in a), ips[0] if ips else None)
    return threat_intelligence.check_abuseipdb_sync(ip) if ip else {"status": "skipped"}


def _abuse_indicator(add, r: dict, host: str) -> None:
    """A link on a raw IP address reported for abuse is a strong sign; a NAMED site on a reported address is weaker -
    shared hosting puts thousands of sites on one address, so one bad neighbour must not condemn a real site."""
    if r.get("status") != "ok":
        return
    score, reports, where = r["abuseScore"], r["totalReports"], f"{r['ip']}" + (f" ({r['isp']})" if r.get("isp") else "")
    raw_ip = bool(IP_RE.match(host)) or ":" in host
    if r.get("isWhitelisted"):
        add(False, "Server address checked on AbuseIPDB",
            f"{where} is on AbuseIPDB's allow-list (a well-known provider); abuse score {score}%.", "low", 0)
    elif score >= 75 and reports >= 5:
        add(True, "Server address reported for abuse (AbuseIPDB)",
            f"{where} has an AbuseIPDB abuse score of {score}% from {reports} report(s) in the last 90 days"
            + ("." if raw_ip else " - the link's site runs on that address; shared hosting can mix good and bad sites, "
               "so this supports the other checks rather than deciding alone."), "high" if raw_ip else "medium",
            25 if raw_ip else 12)
    elif score >= 25 and reports >= 2:
        add(True, "Server address has some abuse reports (AbuseIPDB)",
            f"{where}: abuse score {score}% from {reports} report(s) in the last 90 days.", "medium" if raw_ip else "low",
            10 if raw_ip else 5)
    else:
        add(False, "Server address checked on AbuseIPDB",
            f"{where}: abuse score {score}% ({reports} report(s) in the last 90 days) - nothing notable.", "low", 0)


def _extra_rules(url: str) -> list[dict]:
    """Structural rules the generic URL features miss."""
    parts = split_url(url)
    sensitive = tuple(SENSITIVE_WORDS) + ("kyc", "otp", "bank", "wallet", "refund")
    path_query = (parts["path"] + "?" + parts["query"]).lower()
    ip_login = bool(IP_RE.match(parts["host"])) and any(w in path_query for w in sensitive)
    out = [{"label": "Login-style page on a raw IP address",
            "description": "A page asking for login/KYC/account details is hosted on a bare IP address instead of a "
                           "named website. Real banks and services never do this.",
            "severity": "critical", "weight": 25, "triggered": ip_login}]
    # Added 21 Oct after the QR benchmark (public quishing dataset): two classic tricks the domain checks miss.
    site = registered_domain(parts["host"])
    brand_site = next((d for b, doms in BRAND_DOMAINS.items() for d in doms
                       if d not in (site, parts["host"]) and re.search(r"(?<![a-z0-9-])" + re.escape(d)
                                                                      + r"(?![a-z0-9-])", path_query)), None)
    hidden = bool(brand_site) and bool(_PATH_LOGIN_RE.search(path_query)) and not _redirect_target(parts["query"])
    out.append({"label": "Another brand's address hidden in the path",
                "description": f"The page path mentions {brand_site} next to login words, but the page is on "
                               f"{site or parts['host']}. Phishing kits copy the real site's address into the path "
                               "so the link looks right at a glance.", "severity": "high", "weight": 25,
                "triggered": hidden})
    kit = _KIT_RE.search(path_query)
    out.append({"label": "Phishing-kit file name in the path",
                "description": f"The path contains '{kit.group(0)[:40] if kit else ''}', a file / command name used by "
                               "well-known phishing kits that copy PayPal / bank sign-in pages.", "severity": "high",
                "weight": 25, "triggered": bool(kit) and site not in BRAND_DOMAINS.get("paypal", ())})
    planted = _WP_PLANTED_RE.search(parts["path"] + ("?" + parts["query"] if parts["query"] else ""))
    out.append({"label": WP_PLANTED_LABEL,
                "description": f"The page '{planted.group(0)[-60:] if planted else ''}' sits inside WordPress's own "
                               "system folders (wp-includes / wp-content), where real sites keep code and images, not "
                               "pages. Phishing kits are dropped there on hacked WordPress sites.", "severity": "high",
                "weight": 25, "triggered": bool(planted)})
    return out


_PATH_LOGIN_RE = re.compile(r"log-?in|sign-?in|logon|verif|secure|account|update|confirm|webscr|auth|password|banking")
_KIT_RE = re.compile(r"webscr(?:\.php|\.cmd|_)|cmd=_(?:login|account|s-xclick|update)|websc[r]?_?login|"
                     r"(?:paypal|apple|chase|wellsfargo|bankofamerica|amazon|netflix)[^/?]*/(?:[^/?]*/)*"
                     r"(?:login|signin|verify|update)[^/?]*\.(?:php|html?)", re.I)


def _domain_indicators(url: str) -> tuple[list[dict], dict | None]:
    """Who does this address claim to be, and does the name look like a phishing name?"""
    parts = split_url(url)
    host = parts["host"]
    out = []

    def add(triggered, label, desc, severity, weight):
        out.append({"label": label, "description": desc, "severity": severity, "weight": weight,
                    "triggered": bool(triggered), "id": f"IND_{uuid.uuid4().hex[:12]}"})
    if not host:
        return out, None
    site = domain_model.site_parts(host)
    brand = brand_in_host(host)
    homoglyph = None
    if "xn--" in host and not brand:            # аpple.com written with a Cyrillic 'а' etc.
        latin = _unconfuse(host)
        reg = registered_domain(latin)
        homoglyph = next((b for b, doms in BRAND_DOMAINS.items() if reg in doms), None) or brand_in_host(latin)
    tokens = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    exact = bool(brand) and any(t == brand or (len(brand) >= 6 and brand in t) or BRAND_ALIASES.get(t) == brand
                                for t in tokens)
    official = ", ".join(sorted(BRAND_DOMAINS.get(brand, ()))[:3]) if brand else ""
    if brand and exact:
        where = "as part of the sub-domain" if brand in site["subdomain"] else "inside the domain name"
        add(True, f"'{brand}' brand used in a domain it does not own",
            f"'{brand}' appears {where} of {host}, but the real {brand} sites are {official}. "
            "Attackers put a brand name in their own domain so the link looks official (domain spoofing).",
            "critical", 30)
    elif brand:
        add(True, f"Look-alike of {brand}",
            f"'{host}' imitates '{brand}' with a changed, swapped, missing or look-alike character "
            f"(e.g. 0 for o, 1 for l). The real {brand} sites are {official}.", "critical", 45)
    if homoglyph:
        add(True, f"Look-alike of {homoglyph} using letters from another alphabet",
            f"'{host}' is shown by browsers as '{_unconfuse(host, keep_unicode=True)}', which looks like "
            f"{homoglyph} but uses non-Latin look-alike letters (an IDN homograph attack).", "critical", 45)
    publish = site["platform"] or (host if host in trusted_domains.USER_CONTENT_HOSTS
                                   or registered_domain(host) in trusted_domains.USER_CONTENT_DOMAINS else None)
    add(publish, "Hosted on a free website platform / user-content service",
        f"The page lives on {publish}, where anyone can publish a page or form in minutes for free "
        "(Google Forms/Sites, SharePoint, web.app, netlify.app ...). Legitimate companies rarely ask for logins or "
        "payments there; in the PhiUSIIL dataset over 22,000 phishing sites used such platforms.", "medium", 14)
    login_path = re.search(r"(log-?in|sign-?in|logon|verify|verification|auth|account|password|kyc|otp|update|wp-admin)",
                           (parts["path"] + "?" + parts["query"]).lower())
    add(publish and login_path, "Login / verification page on a free platform",
        f"A '{login_path.group(1) if login_path else ''}' page on {publish}: real banks and companies host their "
        "sign-in pages on their own domain, not on free hosting.", "high", 20)
    fh, fh_brand, fh_word = hosted_name_words(host)
    fh_what = " and ".join(x for x in (f"the brand '{fh_brand}'" if fh_brand else "",
                                       f"the word '{fh_word}'" if fh_word else "") if x)
    add(bool(fh and (fh_brand or fh_word)) and not trusted_domains.is_trusted(url), HOSTED_NAME_LABEL,
        f"This site lives on {fh}, a free website host, and the name its uploader chose contains {fh_what}. "
        "Anyone can publish there in minutes; phishers pick names like these so the link looks official. "
        "(On 2026 data this fired on 23% of phishing sites on free hosts and 0.8% of popular real ones.)", "high", 20)
    target = _redirect_target(parts["query"])
    if (target and domain_model.site_parts(target)["site"] != site["site"]
            and not trusted_domains.is_trusted("https://" + target + "/")):
        t_brand = brand_in_host(target)
        add(True, "Link forwards you to another website",
            f"The address goes through {host} but carries a parameter that sends you on to {target}"
            + (f", which imitates '{t_brand}'" if t_brand else "") + ". Attackers use trusted sites' redirectors "
            "(open redirects) to get past filters.", "high", 20 + (15 if t_brand else 0))
    name = site["name"] or host
    words = [w for w in SENSITIVE_WORDS if w in name] + [w for w in ("kyc", "otp", "refund", "reward", "mfa", "2fa",
                                                                     "renew", "reset", "unlock", "kyc") if w in name]
    add(bool(words) and not trusted_domains.is_trusted(url), "Security / login words in the domain name",
        f"The domain name itself contains {', '.join(sorted(set(words))[:3])}. Real services keep such words in "
        "the page path, phishers put them in the name to look trustworthy.", "medium", 10)
    add(is_shortener(host), "Link shortener / dynamic QR service",
        "The real destination is hidden behind a shortener; it is followed below when live checks are on.",
        "medium", 10)
    ml = domain_model.assess(host)
    if ml:
        add(ml["flagged"] and not trusted_domains.is_trusted(url), "Domain name resembles phishing domains (ML model)",
            f"The domain-name model (trained on 41k real phishing and 382k legitimate domains) gives "
            f"'{ml['site']}' a {ml['probability'] * 100:.0f}% phishing likelihood; its alert level is "
            f"{ml['threshold'] * 100:.0f}% (flags about 1% of real legitimate domains).", "high", 0)
        popular = _popular_sites()
        add(ml.get("verify") and popular is not None and ml["site"] not in popular
            and not trusted_domains.is_trusted(url), DOMAIN_2026_LABEL,
            f"'{ml['site']}' scores {ml['probability'] * 100:.0f}%, above the level re-measured on 2026 websites "
            f"({(ml.get('verifyLevel') or 0) * 100:.0f}%, which only 1% of real 2026 sites reach). Check the site "
            "carefully before trusting it.", "medium", 0)
    return out, ml


_CONFUSABLE = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
                             "ј": "j", "ԁ": "d", "ɡ": "g", "ո": "n", "ѕ": "s", "һ": "h", "ӏ": "l", "ο": "o",
                             "α": "a", "ν": "v", "τ": "t", "κ": "k", "ı": "i", "ⅼ": "l"})


def _unconfuse(host: str, keep_unicode: bool = False) -> str:
    """Decode punycode labels and map common look-alike letters to Latin."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode")
            except Exception:
                pass
        labels.append(label if keep_unicode else label.translate(_CONFUSABLE))
    return ".".join(labels)


def _redirect_target(query: str) -> str | None:
    from urllib.parse import parse_qsl, unquote
    for key, value in parse_qsl(query, keep_blank_values=True):
        v = unquote(value).strip()
        if key.lower() in REDIRECT_PARAMS and v.lower().startswith(("http://", "https://", "//")):
            return split_url(v if "://" in v else "http:" + v)["host"] or None
    return None


def _page_indicators(url: str, page_box: dict | None = None) -> tuple[list[dict], dict]:
    """Live, read-only: follow the redirects and inspect the final page (see safe_fetch.py).
    page_box (optional) receives the page's HTML + final address for the Fake Login model (never saved)."""
    out = []

    def add(triggered, label, desc, severity, weight):
        out.append({"label": label, "description": desc, "severity": severity, "weight": weight,
                    "triggered": bool(triggered), "id": f"IND_{uuid.uuid4().hex[:12]}"})
    res = safe_fetch.fetch(url)
    chain = res["chain"]
    start_site = domain_model.site_parts(split_url(url)["host"])["site"]
    final_host = split_url(res["final_url"])["host"]
    final_site = domain_model.site_parts(final_host)["site"]
    hops = len(chain) - 1
    evidence = {"status": res["status"], "reason": res["reason"], "finalUrl": res["final_url"],
                "redirectChain": [f"{c['how']}: {c['url'][:120]}" + (f" ({c['status']})" if c["status"] else "")
                                  for c in chain]}
    if res["status"] == "refused" and "private/local" in res["reason"]:
        add(True, "Link points to a private / local network address",
            f"{res['final_url'][:80]} {res['reason']}. A public link has no reason to lead into a private network; "
            "the scanner refused to connect.", "high", 20)
    if hops and final_site != start_site:
        add(True, "Redirects to a different website",
            f"The link silently forwards {hops} time(s) and ends on {final_host} instead of {split_url(url)['host']}.",
            "high" if not trusted_domains.is_trusted(res["final_url"]) else "low",
            18 if not trusted_domains.is_trusted(res["final_url"]) else 3)
        brand = brand_in_host(final_host)
        add(bool(brand), "Redirect lands on a brand look-alike",
            f"The final site {final_host} uses the '{brand}' name but is not one of its official domains.",
            "critical", 25)
    add(hops >= 3, "Long redirect chain", f"{hops} hops before the page loads; attackers chain redirects to "
        "hide the destination from filters.", "medium", 10)
    if res["status"] == "ok" and res["html"]:
        if page_box is not None:
            page_box.update(html=res["html"], final_url=res["final_url"])
        pg = page_inspector.inspect(res["html"], res["final_url"])
        evidence["page"] = pg
        platform = domain_model.site_parts(final_host)["platform"]
        if pg["has_password"] and pg["brands_imitated"]:
            b = pg["brands_imitated"][0]
            add(True, "Fake login page: brand login on the wrong website",
                f"The page asks for a password and presents itself as {b} (title: \"{pg['title'][:60]}\"), but "
                f"{final_host} is not one of {b}'s official sites ({', '.join(sorted(BRAND_DOMAINS[b])[:3])}).",
                "critical", 35)
        elif pg["has_password"] and (platform or brand_in_host(final_host)):
            add(True, "Login form on a free platform / look-alike site",
                f"The page asks for a password on {final_host}.", "high", 22)
        add(pg["external_form_targets"], "Form sends your data to another website",
            f"What you type is submitted to {', '.join(pg['external_form_targets'])}, not to {final_site}.",
            "high", 22)
        add(pg["sensitive_fields"] and not trusted_domains.is_trusted(res["final_url"]),
            "Page asks for card / OTP / PIN / ID details",
            f"Input fields: {', '.join(pg['sensitive_fields'])}. Ask the real organisation through its official "
            "app or website instead.", "high", 18)
    return out, evidence


def _embedded_destination(url: str) -> str | None:
    """The website an open-redirect link really sends you to (google.com/url?q=..., ?redirect=..., ?next=...), when it
    is a DIFFERENT site than the link itself; else None."""
    from urllib.parse import parse_qsl, unquote
    from app.detectors.url_features_v2 import REDIRECT_PARAMS
    parts = split_url(url)
    own = registered_domain(parts["host"])
    for key, value in parse_qsl(parts["query"], keep_blank_values=True):
        v = unquote(value).strip()
        if key.lower() in REDIRECT_PARAMS and v.lower().startswith(("http://", "https://", "//")):
            dest = "http:" + v if v.startswith("//") else v
            if registered_domain(split_url(dest)["host"]) not in ("", own):
                return dest
    return None


def analyze_url(url: str, subtopic_title: str = "Malicious URL Analysis", subtopic_id: str | None = None,
                network: bool = True, _depth: int = 0) -> dict:
    url = (url or "").strip()
    if not url:
        return build_result(
            indicators=[], base_score=0, confidence=0,
            engine_name="CYBERGUARD URL Engine", threat_type=subtopic_title,
            explanation="No URL was submitted to analyze.",
        )

    features = extract_url_features(url)
    indicators = explain_url_features(url, features)
    indicators += _extra_rules(url)
    dom_inds, ml = _domain_indicators(url)
    indicators += dom_inds
    evidence = None
    registry_box: dict = {}
    page_box: dict = {}
    if network:  # network=False: model + structural rules only (no DNS/WHOIS/SSL/threat-intel/page calls)
        indicators += _live_indicators(url, registry_box)
        if settings.LIVE_PAGE_CHECKS:
            page_inds, evidence = _page_indicators(url, page_box)
            indicators += page_inds
    subs = _subtopic_models(url, subtopic_id)
    reg_model = _registry_model(registry_box.get("registry"), subtopic_id)
    if reg_model:
        subs.append(reg_model)
    login_model = _login_page_model(page_box, subtopic_id)
    if login_model:
        subs.append(login_model)
    elif _login_model_missing(page_box, subtopic_id):    # (4 Nov) never skip a missing model silently
        indicators.append({"label": "Fake login page model not installed (info only)",
                           "description": "The page was read, but the fake-login-page model (fake_login.joblib) is not "
                                          "in backend/app/ml/models on this computer, so it did not judge the page. "
                                          "The other checks above still ran.",
                           "severity": "low", "weight": 0, "triggered": False})
    sub = max(subs, key=_model_points) if subs else None        # the strongest model decides the floor
    for s_ in subs:
        if len(subs) == 1 or s_["indicator"]["triggered"]:
            indicators.append(s_["indicator"])
    rule_score = sum(i["weight"] for i in indicators if i["triggered"])

    # The domain-name model adds up to 40 points on top of the rules (it judges only the NAME, so it
    # supports the rules rather than overriding them).
    model_points = round(40 * ml["probability"]) if ml else 0
    blended = min(100, rule_score + model_points)
    confidence = min(95, 50 + min(rule_score, 40) + (abs(ml["probability"] - 0.5) * 20 if ml else 0))

    # A one-typo look-alike of a known brand's name (imtouken.com, robiox.com, trezr-suite.com) is at least "verify":
    # real companies do not register misspellings of other brands. (Added 20 Oct; checked against the top-20,000
    # real sites and 2,478 real pages from the urlscan collection: no new false alarm.)
    if any(i["triggered"] and i["label"].startswith("Look-alike of ") for i in indicators):
        blended = max(blended, 51)
    # Added 21 Oct (2026-link benchmark): brand / login words in a free-hosted site's name, a page planted in
    # WordPress system folders, and the domain-name model above its 2026 level are each at least "verify".
    if any(i["triggered"] and i["label"] in VERIFY_FLOOR_LABELS for i in indicators):
        blended = max(blended, 51)

    # (10 Nov) The look-alike model's "close to X - check carefully" (verify level, not "imitates") on a domain that
    # has been registered for 3+ years with nothing else wrong (kayak.co.in, craigslist.hk, oneindia.in, look.com):
    # look-alike phishing domains are days or months old, so the "verify" floor is not applied - the points stay.
    age_days = registry_box.get("ageDays")
    if age_days is None and isinstance(registry_box.get("registry"), dict):
        age_days = registry_box["registry"].get("ageDays")
    established = isinstance(age_days, (int, float)) and age_days >= 3 * 365
    other_red_flags = [i for i in indicators if i["triggered"] and i.get("weight", 0) > 0
                       and not i["label"].startswith("Look-alike domain model")]
    old_lookalike = bool(sub and established and sub["subtopic"] == "lookalike-domain" and sub["level"] == "medium"
                         and not other_red_flags)
    if old_lookalike:
        indicators.append({"label": "Established domain", "severity": "low", "weight": 0, "triggered": True,
                           "description": f"This domain was registered about {int(age_days) // 365} year(s) ago. "
                                          "Look-alike phishing domains are usually only days or months old, so the "
                                          "look-alike note alone is not treated as a threat."})
    # A subtopic's own trained model can only RAISE the score: alert level -> 71-100, verify level -> 51-70.
    if sub and sub["level"] in ("high", "medium") and not old_lookalike:
        blended = max(blended, _model_points(sub))

    # Open redirect (added 19 Oct): score the hidden destination with this same engine (one level deep).
    dest = _embedded_destination(url) if _depth == 0 else None
    if dest:
        d = analyze_url(dest, "Redirect destination", subtopic_id=subtopic_id, network=network, _depth=1)
        risky = d["riskScore"] >= 51
        indicators.append({"label": "Hidden redirect to another website",
                           "description": f"This link forwards to {dest[:120]} (a different website), which CyberGuard "
                                          f"scores {d['riskScore']}/100. Phishers hide their page behind trusted "
                                          "sites' redirect links (google.com/url?q=..., ?redirect=...).",
                           "severity": "critical" if risky else "medium", "weight": 15, "triggered": True})
        blended = max(blended, min(100, d["riskScore"] + 5)) if risky else min(100, blended + 15)
    # A shortener whose destination could not be followed: the real website is unknown -> "verify".
    host_now = split_url(url)["host"]
    followed = bool(evidence) and len(evidence.get("redirectChain") or evidence.get("chain") or []) > 1
    if subtopic_id == "redirect-analysis" and is_shortener(host_now) and not followed and _depth == 0:
        indicators.append({"label": "Destination hidden by a link shortener (not followed)",
                           "description": "The link goes through a shortener and its real destination could not be "
                                          "checked here, so nobody can tell yet where it leads. Expand it with the "
                                          "shortener's preview (e.g. add '+' to a bit.ly link) before opening it.",
                           "severity": "medium", "weight": 0, "triggered": True})
        blended = max(blended, 51)

    # Verified official site (real host, not user-content hosting, no redirect to an untrusted
    # site): cap the score low (never zero).
    trusted = trusted_domains.is_trusted(url) and not (dest and blended >= 51)
    if trusted:
        blended = min(blended, 15)
        confidence = max(confidence, 90)

    triggered = [i for i in indicators if i["triggered"]]
    for ind in indicators:
        ind.setdefault("id", f"IND_{uuid.uuid4().hex[:12]}")

    ml_note = (f" The domain-name model rates '{ml['site']}' {ml['probability'] * 100:.0f}% phishing-like."
               if ml else " (Domain-name model not applicable or not installed.)")
    if trusted:
        explanation = (f"{split_url(url)['host']} belongs to a well-known official site, so this link is treated as "
                       "low risk (score capped).")
    elif triggered:
        top = sorted(triggered, key=lambda i: -i["weight"])[:3]
        names = ", ".join(i["label"].lower() for i in top)
        explanation = f"Flagged {len(triggered)} indicator(s) for this URL, most notably: {names}.{ml_note}"
    else:
        explanation = f"No red flags were found in this URL.{ml_note}"

    result = build_result(
        indicators=indicators,
        base_score=blended,
        confidence=confidence,
        engine_name="CYBERGUARD URL Engine — rules + live checks"
                    + (" + " + " + ".join(x["model"] for x in subs) if subs else "")
                    + (" + domain-name model (PhiUSIIL + Tranco)" if ml else ""),
        threat_type=subtopic_title,
        explanation=explanation,
    )
    if ml:
        result["modelAssessment"] = {"site": ml["site"], "probability": round(ml["probability"], 4),
                                     "threshold": round(ml["threshold"], 4), "flagged": ml["flagged"]}
    if evidence:
        result["liveCheck"] = evidence
    if sub:
        result["subtopicModel"] = {k: sub[k] for k in ("subtopic", "model", "probability", "level", "domain",
                                                       "brandDomain", "tricks", "trainedAt")}
        result["subtopicModel"]["sameNameOtherEnding"] = bool(sub.get("sameNameOtherEnding"))
        result["subtopicModel"].update(alertThreshold=round(sub["thrAlert"], 4), verifyThreshold=round(sub["thrVerify"], 4))
    if len(subs) > 1:
        result["urlModels"] = [{"subtopic": x["subtopic"], "model": x["model"], "level": x["level"],
                                "probability": x["probability"]} for x in subs]
    return result


# ---- per-subtopic trained models ---------------------------------------------------------------------
def _lookalike(url: str):
    from app.detectors import lookalike_domain
    host = split_url(url)["host"]
    a = lookalike_domain.assess(host) if host else None
    if a is None or "thrAlert" not in a or a.get("noNearBrand") and a["probability"] < a["thrVerify"]:
        return None                                 # a known / protected / government site, or nothing close
    if any(registered_domain(host) in doms or host in doms for doms in BRAND_DOMAINS.values()):
        return None                                 # one of a brand's own listed domains (razorpay.me, paypal.me, wa.me)
    p, level, brand = a["probability"], a["level"], a.get("brandDomain")
    tricks = ", ".join(a.get("tricks") or []) or "small changes to the name"
    name = "Look-alike domain model"
    if level == "high":
        label = f"{name}: imitates {brand}"
    elif level == "medium":
        label = f"{name}: close to {brand} - check carefully"
    else:
        label = f"{name}: not a look-alike" + (f" (nearest well-known site: {brand})" if brand else "")
    desc = (f"The trained look-alike model (gradient-boosted trees; protected list = the 10,000 most visited sites "
            f"from Tranco + Indian banks and brands) rates '{a['domain']}' at {p * 100:.0f}%"
            + (f" as an imitation of {brand}" if brand else "")
            + f" (alert level {a['thrAlert'] * 100:.0f}%, which only 1% of real look-alike-but-genuine sites reach)."
            + (f" Tricks found: {tricks}." if level != "low" and brand else "")
            + (" The name is identical and only the ending differs; big brands own many of their country domains, "
               "so check who registered this one (WHOIS / the brand's official site) before trusting it."
               if a.get("sameNameOtherEnding") else ""))
    ind = {"label": label, "description": desc, "weight": 0, "triggered": level != "low",
           "severity": "critical" if level == "high" and p >= 0.95 else {"high": "high", "medium": "medium"}.get(level, "low"),
           "mitre": "T1583.001", "id": f"IND_{uuid.uuid4().hex[:12]}"}
    b = lookalike_domain.load_model() or {}
    return {**a, "subtopic": "lookalike-domain", "model": "Look-alike domain model (Tranco + dnstwist trained)",
            "indicator": ind, "trainedAt": b.get("trained_at"), "probability": round(p, 4)}


def _spoofing(url: str):
    from app.detectors import domain_spoofing
    host = split_url(url)["host"]
    a = domain_spoofing.assess(host) if host else None
    if a is None or "thrAlert" not in a:
        return None                     # no model, a known / brand-owned / government site, or no brand name inside
    p, level, brand = a["probability"], a["level"], a.get("brandDomain")
    name = "Domain spoofing model"
    label = {"high": f"{name}: uses the {a['brand']} name on a domain {a['brand']} does not own",
             "medium": f"{name}: carries the {a['brand']} name - check who owns it"}.get(
        level, f"{name}: brand name looks incidental here")
    signs = "; ".join(a.get("signs") or [])
    desc = (f"The trained domain-spoofing model (gradient-boosted trees; trained on real domains: PhiUSIIL phishing "
            f"vs Tranco + PhiUSIIL legitimate sites that also contain a brand name) rates '{a['domain']}' at "
            f"{p * 100:.0f}% (alert level {a['thrAlert'] * 100:.0f}%, reached by under 1% of genuine domains that "
            f"contain a brand name). What it saw: {signs}."
            + (f" The real site is {brand}; open it yourself instead of using this link." if level != "low" else ""))
    ind = {"label": label, "description": desc, "weight": 0, "triggered": level != "low",
           "severity": "critical" if level == "high" and p >= 0.95 else {"high": "high", "medium": "medium"}.get(level, "low"),
           "mitre": "T1583.001", "id": f"IND_{uuid.uuid4().hex[:12]}"}
    b = domain_spoofing.load_model() or {}
    return {**a, "subtopic": "domain-spoofing", "model": "Domain spoofing model (PhiUSIIL + Tranco trained)",
            "indicator": ind, "trainedAt": b.get("trained_at"), "probability": round(p, 4),
            "tricks": a.get("signs") or []}


def _manipulation(url: str):
    from app.detectors import url_manipulation
    a = url_manipulation.assess(url)
    if a is None or (a.get("noPath") and not a["findings"]):
        return None                     # no model, or a bare domain with nothing in the link to judge
    p, level = a["probability"], a["level"]
    name = "URL manipulation model"
    label = {"high": f"{name}: the link's structure is manipulated",
             "medium": f"{name}: unusual link structure - check carefully"}.get(level, f"{name}: link structure looks normal")
    found = "; ".join(a["findings"]) or "no single trick, but the overall shape of the link"
    desc = ("The trained URL-manipulation model (gradient-boosted trees on 745k real links: DEPHIDES PhishTank / "
            "CommonCrawl + the Kaggle malicious-URL set; scheme and 'www.' ignored) "
            + ("does not judge a bare domain; " if a.get("noPath") else f"rates this link at {p * 100:.0f}% "
               f"(alert level {a['thrAlert'] * 100:.0f}%, reached by about 1% of normal links); ")
            + f"what it found: {found}."
            + (" '@' tricks and disguised IP addresses have no innocent use in a link, so this is always high."
               if a.get("unambiguousTrick") else ""))
    ind = {"label": label, "description": desc, "weight": 0, "triggered": level != "low",
           "severity": "critical" if level == "high" and p >= 0.98 else {"high": "high", "medium": "medium"}.get(level, "low"),
           "mitre": "T1027", "id": f"IND_{uuid.uuid4().hex[:12]}"}
    b = url_manipulation.load_model() or {}
    return {**a, "subtopic": "url-manipulation", "model": "URL manipulation model (DEPHIDES + Kaggle trained)",
            "indicator": ind, "trainedAt": b.get("trained_at"), "probability": round(p, 4),
            "domain": split_url(url)["host"], "brandDomain": None, "tricks": a["findings"]}


def _link2026(url: str):
    """The 2026 link model (26 Oct): the whole link compared with real 2026 phishing links. General URL pages only.
    Only its ALERT level (0.5% of real links) raises a score; its "verify" level (5% of real links) is a note only."""
    from app.detectors import link_2026
    a = link_2026.assess(url)
    if a is None:
        return None
    p, level = a["probability"], a["level"]
    note = level == "medium"
    if note:
        a = {**a, "level": "low", "probability": min(p, a["thrVerify"])}
        level = "low"
    name = "2026 link model"
    label = (f"{name}: looks like this year's phishing links" if level == "high" else
             f"{name}: a little like recent phishing links (note only)" if note else f"{name}: looks normal")
    desc = (f"The 2026 link model (trained on real phishing links seen by urlscan.io in September-October 2026 and on "
            f"real 2026 sites, including sites on free website hosts; tested on later days and other sites) rates this "
            f"link {p * 100:.0f}% phishing-like (alert level {a['thrAlert'] * 100:.0f}%, reached by about 0.5% of real "
            f"links). It reads only the link text.")
    ind = {"label": label, "description": desc, "weight": 0, "triggered": level != "low" or note,
           "severity": {"high": "high", "medium": "medium"}.get(level, "low"), "mitre": "T1566.002",
           "id": f"IND_{uuid.uuid4().hex[:12]}"}
    return {**a, "subtopic": "link-2026", "model": "2026 link model (urlscan.io 2026 trained)", "indicator": ind,
            "domain": split_url(url)["host"], "brandDomain": None, "tricks": []}


SUBTOPIC_MODELS = {"lookalike-domain": _lookalike, "domain-spoofing": _spoofing, "url-manipulation": _manipulation,
                   "link-2026": _link2026}


# Pages that receive links from anywhere (a QR code, a "check this link" page) run EVERY trained URL
# model and let the strongest one decide.
ALL_URL_MODELS = {"qr-phishing", "malicious-url", "fraudulent-website", "general"}


def _subtopic_models(url: str, subtopic_id: str | None) -> list[dict]:
    fns = list(SUBTOPIC_MODELS.values()) if subtopic_id in ALL_URL_MODELS else \
        [SUBTOPIC_MODELS[subtopic_id]] if subtopic_id in SUBTOPIC_MODELS else []
    out = []
    for fn in fns:
        try:
            r = fn(url)
        except Exception:      # a broken / missing model never breaks the scan
            r = None
        if r:
            out.append(r)
    # A shortened link (bit.ly/3abc) has no structure to judge: the URL-manipulation model learned that most short
    # links in its data were malicious and alerted on EVERY one. For shorteners its verdict is capped at "verify";
    # the real destination is judged by following the link (live check) or by Redirect Analysis.
    if is_shortener(split_url(url)["host"]):
        for r in out:
            if "manipulation" in r.get("model", "").lower() and r["level"] == "high":
                r["level"] = "medium"
                r["probability"] = min(r["probability"], (r["thrAlert"] + r["thrVerify"]) / 2)
                r["indicator"] = {**r["indicator"], "label": "URL manipulation model: short link - verify where it leads",
                                  "severity": "medium",
                                  "description": "The link is shortened, so its structure says nothing about the real "
                                                 "destination; treated as 'verify' rather than an alert. "
                                                 + r["indicator"].get("description", "")}
    return out


def _registry_model(reg: dict | None, subtopic_id: str | None):
    """The domain-registration model as a subtopic model (SSL & Domain Analysis page + every general URL page)."""
    if not reg or reg.get("probability") is None or subtopic_id not in ({"ssl-domain-analysis"} | ALL_URL_MODELS):
        return None
    p, level = reg["probability"], reg["level"]
    facts = reg["facts"]
    text = ". ".join(reg["sentences"]) + "."
    return {"subtopic": "ssl-domain-analysis", "model": "Domain registration model", "probability": p, "level": level,
            "thrAlert": reg["thrAlert"], "thrVerify": reg["thrVerify"], "domain": facts.get("domain"),
            "brandDomain": None, "tricks": reg["sentences"], "trainedAt": reg.get("trainedAt"),
            "indicator": {"label": {"high": "Domain registration model: looks like a phishing domain",
                                    "medium": "Domain registration model: suspicious registration - verify",
                                    "low": "Domain registration model: registration looks normal"}[level],
                          "description": f"{text} The model (trained on registry records of real phishing and real "
                                         f"sites) rates this registration {p * 100:.0f}% phishing-like.",
                          "weight": 0, "triggered": level != "low",
                          "severity": {"high": "high", "medium": "medium"}.get(level, "low")}}


def _login_model_missing(page_box: dict, subtopic_id: str | None) -> bool:
    """True when the fake-login-page model would have judged this page but its file is not installed."""
    from app.detectors import fake_login
    if not page_box.get("html") or subtopic_id not in ({"fake-login-page"} | ALL_URL_MODELS):
        return False
    try:
        return fake_login.load() is None
    except Exception:
        return False


def _login_page_model(page_box: dict, subtopic_id: str | None):
    """The Fake Login Page model (21 Oct) as a subtopic model: judges the fetched page's HTML. Runs on the Fake Login
    Page page and every general URL page; it can only RAISE a score (like every subtopic model)."""
    from app.detectors import fake_login
    if not page_box.get("html") or subtopic_id not in ({"fake-login-page"} | ALL_URL_MODELS):
        return None
    try:
        a = fake_login.assess(page_box["html"], page_box.get("final_url") or "")
    except Exception:                                    # a model problem never breaks a scan
        return None
    if not a:
        return None
    p, level = a["probability"], a["level"]
    why = fake_login.reasons(a["facts"])
    host = split_url(page_box.get("final_url") or "")["host"]
    return {"subtopic": "fake-login-page", "model": "Fake login page model", "probability": p, "level": level,
            "thrAlert": a["thrAlert"], "thrVerify": a["thrVerify"], "domain": host, "brandDomain": None,
            "tricks": why[:4], "trainedAt": a.get("trainedAt"),
            "indicator": {"label": {"high": "Fake login page model: this looks like a copied login page",
                                    "medium": "Fake login page model: the page may be a fake login - verify",
                                    "low": "Fake login page model: the page looks normal"}[level],
                          "description": (f"The page at {host} " + ("; ".join(why) if why else "shows no typical fake-login clues")
                                          + f". The model (trained on {'real phishing pages and real login pages'}) rates "
                                            f"it {p * 100:.0f}% fake-login-like."),
                          "weight": 0, "triggered": level != "low",
                          "severity": {"high": "critical", "medium": "medium"}.get(level, "low")}}


def _model_points(m: dict) -> int:
    """A model's verdict on the 0-100 scale: alert level -> 71-100, verify level -> 51-70, below -> 0-50."""
    p, ta, tv = m["probability"], m["thrAlert"], m["thrVerify"]
    if m["level"] == "high":
        return min(100, 71 + round(29 * (p - ta) / max(1 - ta, 1e-6)))
    if m["level"] == "medium":
        return min(70, 51 + round(19 * (p - tv) / max(ta - tv, 1e-6)))
    return round(50 * min(p, tv) / max(tv, 1e-6))
