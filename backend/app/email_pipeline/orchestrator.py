"""
Step 3a - Orchestrator: send each part of the email to the detector built for it.

    parse  ->  enrich  ->  fan-out (parallel)  ->  fuse
                             |- phishing text model .......... subject + body + sender
                             |- impersonation detectors ...... only the ones the email's claims point to
                             |- URL engine ................... every unique link (body, HTML, PDF/HTML attachments)
                             |- QR engine .................... every image (inline, attached, PDF pages)
                             |- attachment scanner ........... every real attachment
                             '- account-takeover signals ..... security notifications

Usage:
    from app.email_pipeline import analyze_email
    result = analyze_email(raw_bytes, db=db, user_id=user.id)

`network=False` skips live lookups (WHOIS, DNS, SSL, VirusTotal) - used by
tests and offline demos. Every detector failure is contained: one broken
detector never breaks the verdict.
"""
import logging
import os
import re
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

from app.detectors import (phishing, malicious_url, qr_analyzer, government_impersonation,
                           senior_management_impersonation, teacher_university_impersonation,
                           financial_impersonation, brand_impersonation, known_contact_impersonation)
from app.detectors.qr_decoder import decode_qr_image
from app.detectors.url_features_v2 import split_url, registered_domain
from app.email_pipeline import enrich as enrich_mod, attachments as att_mod, ato_signals, fusion
from app.email_pipeline import org_directory as orgs
from app.email_pipeline.parser import parse_email, parse_body_only
from app.email_pipeline.schemas import EmailEvent

log = logging.getLogger("cyberguard.email")

MAX_URLS = 10
MAX_QR_IMAGES = 6
URL_SUBTOPIC = "fraudulent-website"   # best-performing URL model in the benchmark (20/22 caught, 0 false alarms)
# BEC needs an actual REQUEST ("please transfer...", "buy gift cards"), not just a
# mention of money ("we have received your payment" is a receipt, not fraud).
BEC_OPENERS = re.compile(r"are you (?:at your desk|available|free)|quick favou?r|gift ?cards?|"
                         r"keep (?:this|it) (?:confidential|between us)|don'?t (?:tell|loop in|inform)", re.I)
MONEY_OR_DATA_REQUEST = re.compile(
    r"\b(?:please|kindly|can you|could you|i need you to|need you to|i need|urgently)\b[^.?!\n]{0,80}?"
    r"\b(?:buy|purchase|send|transfer|wire|process|pay|share|change|update)\b[^.?!\n]{0,80}?"
    r"(?:gift ?cards?|vouchers?|payment|amount|funds|money|invoice|vendor|bank (?:details|account)|"
    r"account (?:number|details)|salary|payroll|form ?16|w-?2|pan|aadhaar|otp|lakh|crore|rs\.?|inr|₹|\$)", re.I)


def _safe(name, fn, *args, **kwargs):
    t = time.time()
    try:
        r = fn(*args, **kwargs)
        log.debug("%s ok in %.2fs", name, time.time() - t)
        return r
    except Exception as e:  # one broken detector must not break the verdict
        log.warning("email pipeline: %s failed: %s", name, e)
        return None


# ---------------------------------------------------------------------------
# which impersonation detectors does this email call for?
# ---------------------------------------------------------------------------
def _impersonation_jobs(ev: EmailEvent, db, user_id) -> list[tuple[str, callable, tuple, dict]]:
    text = ev.full_text
    entities = orgs.find_entities(f"{ev.from_display_name}\n{text[:3000]}")
    cats = {e["category"] for e in entities}
    recipient_org = next((a.rsplit("@", 1)[-1] for a in ev.to_addresses
                          if a.rsplit("@", 1)[-1] not in orgs.FREEMAIL_DOMAINS), "")
    fields = {"senderEmail": ev.from_address}
    jobs = []

    if "government" in cats:
        jobs.append(("government-impersonation", government_impersonation.analyze_government_impersonation,
                     (text, fields, "Government Official Impersonation"), {}))
    if "bank" in cats:
        jobs.append(("financial-impersonation", financial_impersonation.analyze_financial_impersonation,
                     (text, fields, "Financial Institution Impersonation"), {}))
    if "brand" in cats:
        jobs.append(("brand-impersonation", brand_impersonation.analyze_brand_impersonation,
                     (text, fields, "Organization / Brand Impersonation"), {}))
    if "education" in cats or orgs.ACADEMIC_TITLES.search(f"{ev.from_display_name}\n{text[:2000]}"):
        f = dict(fields)
        if recipient_org.endswith(orgs.EDUCATION_SUFFIXES):
            f["institutionDomain"] = recipient_org
        jobs.append(("teacher-impersonation", teacher_university_impersonation.analyze_teacher_university_impersonation,
                     (text, f, "Teacher / University Authority Impersonation"), {}))
    vouched = bool(ev.auth.get("dmarc") == "pass"
                   and any(c["official"] and c["where"] != "body_header" for c in ev.claimed_entities))
    exec_claim = orgs.EXECUTIVE_TITLES.search(f"{ev.from_display_name}\n{text[-500:]}")
    if exec_claim or ((MONEY_OR_DATA_REQUEST.search(text) or BEC_OPENERS.search(text)) and not vouched):
        f = dict(fields)
        if recipient_org:
            f["companyDomain"] = recipient_org
        jobs.append(("management-impersonation", senior_management_impersonation.analyze_senior_management_impersonation,
                     (text, f, "Senior Management Impersonation"), {}))
    if db is not None and user_id and ev.from_display_name:
        f = dict(fields, claimedSenderName=ev.from_display_name)
        jobs.append(("contact-impersonation", known_contact_impersonation.analyze_known_contact_message,
                     (text, f, "Known Contact Impersonation"), {"db": db, "user_id": user_id}))
    return jobs


def _split_trusted(ev: EmailEvent, urls: list[str]) -> tuple[list[str], list[str]]:
    """Links pointing at the sender's OWN domain, when that sender is cryptographically
    authenticated (DMARC pass + aligned DKIM), are trusted and not re-scored:
    amazon.in linking to amazon.in is expected. Everything else is scanned."""
    a = ev.auth or {}
    if not (a.get("dmarc") == "pass" and a.get("dkim_aligned") and ev.from_domain):
        return urls, []
    own = registered_domain(ev.from_domain)
    official = set()
    for c in ev.claimed_entities:
        if c["official"] and c["where"] != "body_header":
            official |= {registered_domain(d) for d in c["_entity"]["domains"]}
    scan, trusted = [], []
    for u in urls:
        reg = registered_domain(split_url(u)["host"])
        (trusted if reg == own or reg in official else scan).append(u)
    return scan, trusted


def _unique_urls(urls: list[str], limit: int = MAX_URLS) -> list[str]:
    """One URL per host, capped."""
    seen, out = set(), []
    for u in urls:
        host = split_url(u)["host"]
        if not host or host in seen or u.lower().startswith(("javascript:", "data:")):
            continue
        seen.add(host)
        out.append(u)
    return out[:limit]


def _scan_qr_images(candidates: list[tuple[str, bytes]], network: bool = True) -> list[dict]:
    results = []
    tmpdir = tempfile.mkdtemp(prefix="cg_qr_")
    for idx, (name, data) in enumerate(candidates[:MAX_QR_IMAGES]):
        if not data:
            continue
        path = os.path.join(tmpdir, f"img{idx}.png")
        with open(path, "wb") as f:
            f.write(data)
        try:
            if not decode_qr_image(path).codes:
                continue  # an ordinary image (logo, photo), not a QR code
            r = qr_analyzer.analyze_qr(path, name, "QR Code in Email", "qr-phishing", network=network)
            r.pop("_target", None)
            r.pop("_target_type", None)
            results.append({"name": name, "result": r})
        except Exception as e:
            log.warning("QR scan failed for %s: %s", name, e)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
    return results


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------
def analyze_email(raw: bytes | str | None = None, *, ev: EmailEvent | None = None, db=None,
                  user_id: str | None = None, network: bool = True,
                  sender: str = "", subject: str = "") -> dict:
    """Analyze one email end to end. Returns a CYBERGUARD result dict with extra keys:
    category, mitre, components, trust, escalations, email (parsed summary)."""
    started = time.time()
    if ev is None:
        ev = parse_email(raw or b"")
        if not ev.is_structured and (sender or subject):
            # pasted body text + sender typed into the form's separate field
            body = raw if isinstance(raw, str) else (raw or b"").decode("utf-8", errors="ignore")
            ev = parse_body_only(body, sender=sender, subject=subject)
    if sender and not ev.from_address:
        ev.from_address = sender.strip().lower()
        ev.from_domain = ev.from_address.rsplit("@", 1)[-1] if "@" in ev.from_address else ""

    # Step 2: enrichment
    enrich_mod.enrich(ev, db=db, user_id=user_id, network=network)
    trust = enrich_mod.trust_signals(ev)

    components: list[dict] = []

    def add(kind, name, result):
        if result:
            components.append({"component": kind, "name": name, "score": int(result.get("riskScore", 0)), "result": result})

    sender_score = min(100, sum(i["weight"] for i in ev.enrichment_indicators if i["triggered"]))
    add("sender", "sender-authentication", {"riskScore": sender_score, "indicators": ev.enrichment_indicators,
                                            "classification": None, "analysisEngine": "CYBERGUARD Sender & Auth Checks",
                                            "explanation": f"{sum(1 for i in ev.enrichment_indicators if i['triggered'])} sender/authentication red flag(s)."})

    # Attachments run first: they can contribute extra links and QR images.
    att = _safe("attachments", att_mod.scan_attachments, ev.attachments, network=network)
    if att and att.get("attachment_count"):
        add("attachment", "attachment-scanner", att)

    link_urls = [ln.url for ln in ev.links] + (att.get("extracted_links", []) if att else [])
    urls, trusted_urls = _split_trusted(ev, _unique_urls(link_urls, limit=MAX_URLS * 3))
    urls = urls[:MAX_URLS]
    qr_candidates = (att.get("qr_candidates") if att else None) or [(a.filename, a.data) for a in ev.images]

    imp_jobs = _impersonation_jobs(ev, db, user_id)
    text = ev.full_text

    # The known-contact detector uses the request's DB session (not thread-safe),
    # so it runs on this thread; everything else runs in parallel.
    db_jobs = [j for j in imp_jobs if j[3].get("db") is not None]
    par_jobs = [j for j in imp_jobs if j[3].get("db") is None]

    with ThreadPoolExecutor(max_workers=8) as pool:
        f_phish = pool.submit(_safe, "phishing", phishing.analyze_text, text, sender=ev.from_address or None,
                              subtopic_title="Email Phishing", subtopic_id="email-analysis",
                              reply_to=ev.reply_to_address or None, scan_links=False) if text else None
        f_imp = [(name, pool.submit(_safe, name, fn, *args, **kw)) for name, fn, args, kw in par_jobs]
        f_url = [(u, pool.submit(_safe, "url", malicious_url.analyze_url, u, "Link in Email",
                                 subtopic_id=URL_SUBTOPIC, network=network)) for u in urls]
        f_qr = pool.submit(_safe, "qr", _scan_qr_images, qr_candidates, network) if qr_candidates else None
        f_ato = pool.submit(_safe, "ato", ato_signals.detect, ev)

        for name, fn, args, kw in db_jobs:
            add("impersonation", name, _safe(name, fn, *args, **kw))
        if f_phish:
            add("phishing", "phishing-text-model", f_phish.result())
        for name, f in f_imp:
            add("impersonation", name, f.result())
        for u, f in f_url:
            r = f.result()
            if r:
                r = dict(r, explanation=f"{u[:80]}: {r.get('explanation', '')}")
            add("url", "url-engine", r)
        for q in (f_qr.result() if f_qr else None) or []:
            add("qr", "qr-engine", q["result"])
        ato = f_ato.result()
        if ato and ato.get("is_security_notification"):
            add("account_takeover", "ato-signals", ato)

    result = fusion.fuse(ev, components, trust)
    result["email"] = ev.summary()
    result["links_scanned"] = urls
    result["links_trusted"] = trusted_urls
    result["elapsed_ms"] = int((time.time() - started) * 1000)
    result["_target"] = (ev.subject or ev.from_address or ev.body_text[:60] or "email")[:200]
    result["_target_type"] = "email"
    return result

