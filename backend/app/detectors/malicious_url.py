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
import os
import uuid
import joblib

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
from app.detectors import domain_model, page_inspector
from app.services import safe_fetch
import re

settings = get_settings()

def _live_indicators(url: str) -> list[dict]:
    host = urlparse(url if "://" in url else f"http://{url}").netloc.split("@")[-1].split(":")[0]
    if not host:
        return []
    indicators: list[dict] = []
    def add(triggered, label, desc, severity, weight):
        indicators.append({"label": label, "description": desc, "severity": severity, "weight": weight,
                            "triggered": bool(triggered), "id": f"IND_{uuid.uuid4().hex[:12]}"})
    with ThreadPoolExecutor(max_workers=5) as pool:
        dns_f = pool.submit(network_intel.resolve_domain, host)
        whois_f = pool.submit(network_intel.get_domain_age, host)
        ssl_f = pool.submit(network_intel.get_ssl_info, host)
        vt_f = pool.submit(threat_intelligence.check_virustotal_url_sync, url)
        uh_f = pool.submit(threat_intelligence.check_urlhaus_sync, url)
        dns_r, whois_r, ssl_r, vt_r, uh_r = dns_f.result(), whois_f.result(), ssl_f.result(), vt_f.result(), uh_f.result()
    if dns_r["status"] == "unresolvable":
        add(True, "Domain does not resolve", f"'{host}' does not resolve to any real server right now.", "critical", 30)
    if whois_r["status"] == "ok":
        age = whois_r["age_days"]
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
    return indicators


def _extra_rules(url: str) -> list[dict]:
    """Structural rules the generic URL features miss."""
    parts = split_url(url)
    sensitive = tuple(SENSITIVE_WORDS) + ("kyc", "otp", "bank", "wallet", "refund")
    path_query = (parts["path"] + "?" + parts["query"]).lower()
    ip_login = bool(IP_RE.match(parts["host"])) and any(w in path_query for w in sensitive)
    return [{"label": "Login-style page on a raw IP address",
             "description": "A page asking for login/KYC/account details is hosted on a bare IP address instead of a "
                            "named website. Real banks and services never do this.",
             "severity": "critical", "weight": 25, "triggered": ip_login}]


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


def _page_indicators(url: str) -> tuple[list[dict], dict]:
    """Live, read-only: follow the redirects and inspect the final page (see safe_fetch.py)."""
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


def analyze_url(url: str, subtopic_title: str = "Malicious URL Analysis", subtopic_id: str | None = None,
                network: bool = True) -> dict:
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
    if network:  # network=False: model + structural rules only (no DNS/WHOIS/SSL/threat-intel/page calls)
        indicators += _live_indicators(url)
        if settings.LIVE_PAGE_CHECKS:
            page_inds, evidence = _page_indicators(url)
            indicators += page_inds
    sub = _subtopic_model(url, subtopic_id)
    if sub:
        indicators.append(sub["indicator"])
    rule_score = sum(i["weight"] for i in indicators if i["triggered"])

    # The domain-name model adds up to 40 points on top of the rules (it judges only the NAME, so it
    # supports the rules rather than overriding them).
    model_points = round(40 * ml["probability"]) if ml else 0
    blended = min(100, rule_score + model_points)
    confidence = min(95, 50 + min(rule_score, 40) + (abs(ml["probability"] - 0.5) * 20 if ml else 0))

    # A subtopic's own trained model can only RAISE the score: alert level -> 71-100, verify level -> 51-70.
    if sub and sub["level"] == "high":
        span = max(1 - sub["thrAlert"], 1e-6)
        blended = max(blended, min(100, 71 + round(29 * (sub["probability"] - sub["thrAlert"]) / span)))
    elif sub and sub["level"] == "medium":
        span = max(sub["thrAlert"] - sub["thrVerify"], 1e-6)
        blended = max(blended, min(70, 51 + round(19 * (sub["probability"] - sub["thrVerify"]) / span)))

    # Verified official site (real host, not user-content hosting, no redirect to an untrusted
    # site): cap the score low (never zero).
    trusted = trusted_domains.is_trusted(url)
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
                    + (f" + {sub['model']}" if sub else "")
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
    return result


# ---- per-subtopic trained models ---------------------------------------------------------------------
def _lookalike(url: str):
    from app.detectors import lookalike_domain
    host = split_url(url)["host"]
    a = lookalike_domain.assess(host) if host else None
    if a is None or "thrAlert" not in a or a.get("noNearBrand") and a["probability"] < a["thrVerify"]:
        return None                                 # a known / protected / government site, or nothing close
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


SUBTOPIC_MODELS = {"lookalike-domain": _lookalike, "domain-spoofing": _spoofing}


def _subtopic_model(url: str, subtopic_id: str | None):
    fn = SUBTOPIC_MODELS.get(subtopic_id or "")
    if not fn:
        return None
    try:
        return fn(url)
    except Exception:          # a broken / missing model never breaks the scan
        return None
