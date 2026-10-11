"""
Step 2 - Enrichment: answer "who really sent this, and can we prove it?"

Adds to the EmailEvent:
  * ev.auth                    SPF / DKIM / DMARC verdicts + DKIM signing domain
  * ev.originating_ip          first public IP in the Received chain
  * ev.sender_history          has this user received mail from this sender before?
  * ev.claimed_entities        organisations the email claims to be from
  * ev.enrichment_indicators   sender / authentication / link red flags

Each indicator uses the same shape as every other CYBERGUARD detector
({label, description, severity, weight, triggered}) plus "source" and
"mitre" so the fusion step and the UI can explain where it came from.
"""
import ipaddress
import re
import uuid

from app.email_pipeline import org_directory as orgs
from app.email_pipeline.schemas import EmailEvent
from app.detectors.url_features_v2 import split_url, registered_domain, brand_in_host

AUTH_RE = {k: re.compile(rf"\b{k}\s*=\s*([a-z]+)", re.I) for k in ("spf", "dkim", "dmarc")}
DKIM_DOMAIN_RE = re.compile(r"header\.(?:d|i)\s*=\s*@?([a-z0-9.\-]+)", re.I)
IP_IN_RECEIVED_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")
DOMAIN_IN_TEXT_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)
EMAIL_IN_NAME_RE = re.compile(r"[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})", re.I)
SCRIPTED_MAILERS = re.compile(r"phpmailer|swiftmailer|python|curl|sendblaster|mass mail|atomic mail|gammadyne", re.I)
REPLY_PREFIX = re.compile(r"^\s*(re|fw|fwd)\s*:", re.I)


def _ind(triggered, label, description, severity, weight, source, mitre=None):
    return {"id": f"IND_{uuid.uuid4().hex[:12]}", "label": label, "description": description,
            "severity": severity, "weight": weight, "triggered": bool(triggered),
            "source": source, "mitre": mitre}


# ---------------------------------------------------------------------------
# Authentication (SPF / DKIM / DMARC)
# ---------------------------------------------------------------------------
def parse_auth(ev: EmailEvent) -> dict:
    """Reads the receiving server's verdicts. 'none' = header present but no result,
    'unknown' = no authentication headers at all (e.g. pasted body text)."""
    text = ev.authentication_results or ""
    auth = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "dkim_domain": "", "available": False}
    if text:
        auth["available"] = True
        for k, rx in AUTH_RE.items():
            m = rx.search(text)
            auth[k] = m.group(1).lower() if m else "none"
        dm = DKIM_DOMAIN_RE.search(text)
        auth["dkim_domain"] = dm.group(1).lower() if dm else ""
    if auth["spf"] in ("unknown", "none") and ev.received_spf:
        auth["available"] = True
        auth["spf"] = ev.received_spf.split()[0].lower().strip(":;")
    # DKIM is "aligned" when the signing domain is the From domain's organisation.
    auth["dkim_aligned"] = bool(
        auth["dkim"] == "pass" and auth["dkim_domain"] and ev.from_domain
        and registered_domain(auth["dkim_domain"]) == registered_domain(ev.from_domain)
    )
    return auth


def originating_ip(ev: EmailEvent) -> str:
    # Received headers are newest-first; the sender's own hop is at the bottom.
    for hop in reversed(ev.received_chain):
        for ip in IP_IN_RECEIVED_RE.findall(hop):
            try:
                if ipaddress.ip_address(ip).is_global:
                    return ip
            except ValueError:
                continue
    return ""


# ---------------------------------------------------------------------------
# Sender history (needs the DB)
# ---------------------------------------------------------------------------
def lookup_sender_history(ev: EmailEvent, db=None, user_id: str | None = None) -> dict:
    if db is None or not user_id or not ev.from_address:
        return {"available": False}
    try:
        from app.db.models import SenderHistory
        row = (db.query(SenderHistory)
               .filter(SenderHistory.user_id == user_id, SenderHistory.sender_address == ev.from_address)
               .first())
        domain_seen = (db.query(SenderHistory)
                       .filter(SenderHistory.user_id == user_id, SenderHistory.sender_domain == ev.from_domain)
                       .count()) if ev.from_domain else 0
    except Exception:
        return {"available": False}
    if not row:
        return {"available": True, "first_time": True, "message_count": 0, "safe_count": 0,
                "domain_seen_before": domain_seen > 0}
    return {"available": True, "first_time": False, "message_count": row.message_count,
            "safe_count": row.safe_count, "domain_seen_before": True}


# ---------------------------------------------------------------------------
# Claimed identity
# ---------------------------------------------------------------------------
def claimed_entities(ev: EmailEvent) -> list[dict]:
    """Organisations the email presents itself as. Display name/subject claims
    are strong; a body mention counts only near the top (letterhead/greeting)."""
    out, seen = [], set()
    for where, text in (("display_name", ev.from_display_name), ("subject", ev.subject),
                        ("body_header", ev.body_text[:300])):
        for e in orgs.find_entities(text):
            if e["name"] in seen:
                continue
            seen.add(e["name"])
            out.append({"name": e["name"], "category": e["category"], "where": where,
                        "official": orgs.is_official_sender(e, ev.from_domain),
                        "_entity": e})
    return out


def _org_domain_of_recipient(ev: EmailEvent) -> str:
    for a in ev.to_addresses:
        d = a.rsplit("@", 1)[-1]
        if d and d not in orgs.FREEMAIL_DOMAINS:
            return d
    return ""


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------
def enrich(ev: EmailEvent, *, db=None, user_id: str | None = None, network: bool = True) -> EmailEvent:
    ev.auth = parse_auth(ev)
    ev.originating_ip = originating_ip(ev)
    ev.sender_history = lookup_sender_history(ev, db, user_id)
    ev.claimed_entities = claimed_entities(ev)

    ind: list[dict] = []
    a = ev.auth
    from_reg = registered_domain(ev.from_domain) if ev.from_domain else ""
    freemail = from_reg in orgs.FREEMAIL_DOMAINS or ev.from_domain in orgs.FREEMAIL_DOMAINS

    # ---- 1. Authentication -----------------------------------------------
    if a["available"]:
        ind.append(_ind(a["dmarc"] == "fail", "DMARC failed",
                        "The receiving mail server could not verify that this email really comes from "
                        f"{ev.from_domain or 'the sender domain'} — the classic sign of a spoofed sender.",
                        "critical", 30, "authentication", "T1566"))
        ind.append(_ind(a["spf"] in ("fail", "softfail"), f"SPF {a['spf']}",
                        "The server that delivered this email is not authorised to send for the sender's domain.",
                        "high", 15, "authentication", "T1566"))
        ind.append(_ind(a["dkim"] in ("fail", "none", "neutral", "permerror"),
                        "No valid DKIM signature" if a["dkim"] != "fail" else "DKIM signature failed",
                        "The message is not cryptographically signed by the sender's domain, or the signature broke "
                        "(content may have been altered).", "medium", 10, "authentication", "T1566"))
    else:
        ind.append(_ind(False, "Authentication results unavailable",
                        "No SPF/DKIM/DMARC headers were present (pasted text or a stripped file), so the sender "
                        "could not be verified. Upload the original .eml for a full check.",
                        "info", 0, "authentication"))

    # ---- 2. Display name & claimed identity ------------------------------------
    m = EMAIL_IN_NAME_RE.search(ev.from_display_name or "")
    ind.append(_ind(bool(m and ev.from_domain and registered_domain(m.group(1).lower()) != from_reg),
                    "Display name hides a different address",
                    f"The sender's name shows '{m.group(0) if m else ''}' but the real address is {ev.from_address}.",
                    "high", 20, "sender", "T1656"))

    strong_claims = [c for c in ev.claimed_entities if c["where"] in ("display_name", "subject")]
    fake_strong = [c for c in strong_claims if not c["official"] and ev.from_domain]
    ind.append(_ind(bool(fake_strong), "Sender impersonates an organisation",
                    (f"Claims to be {fake_strong[0]['name']} but sends from {ev.from_domain}, which is not one of "
                     f"its official domains.") if fake_strong else "Claimed organisation matches the sender domain.",
                    "critical", 30, "sender", "T1656"))

    body_claims = [c for c in ev.claimed_entities if c["where"] == "body_header" and not c["official"]
                   and c["category"] in ("government", "bank") and ev.from_domain]
    ind.append(_ind(bool(body_claims) and not fake_strong, "Message claims government/bank authority",
                    (f"The message opens as {body_claims[0]['name']} but was sent from {ev.from_domain}.")
                    if body_claims else "", "high", 16, "sender", "T1656"))

    # ---- 3. Look-alike sender domain ------------------------------------------
    lookalike_brand = brand_in_host(ev.from_domain) if ev.from_domain and not freemail else None
    if not lookalike_brand and ev.from_domain and not freemail:
        for c in ev.claimed_entities:
            if not c["official"]:
                for kw in c["_entity"]["keywords"]:
                    if len(kw) >= 3 and kw.replace(" ", "") in ev.from_domain.replace("-", ""):
                        lookalike_brand = c["name"]
                        break
            if lookalike_brand:
                break
    ind.append(_ind(bool(lookalike_brand), "Look-alike sender domain",
                    f"{ev.from_domain} uses the name '{lookalike_brand}' but is not an official domain of that "
                    "organisation (typosquatting / brand abuse).", "critical", 28, "sender", "T1583.001"))

    # ---- 4. Free email account claiming authority -------------------------------
    exec_claim = bool(orgs.EXECUTIVE_TITLES.search(ev.from_display_name or "")) or bool(
        orgs.EXECUTIVE_TITLES.search((ev.body_text or "")[-400:]))
    academic_claim = bool(orgs.ACADEMIC_TITLES.search(ev.from_display_name or ""))
    org_claim = bool(strong_claims)
    ind.append(_ind(freemail and (exec_claim or academic_claim or org_claim),
                    "Free email account claiming authority",
                    f"Sent from a personal {from_reg} account while presenting as "
                    f"{'an executive' if exec_claim else 'academic staff' if academic_claim else 'an organisation'}. "
                    "Real executives, banks and universities use their own domains.",
                    "high", 22, "sender", "T1656"))

    recipient_org = _org_domain_of_recipient(ev)
    ind.append(_ind(bool(exec_claim and recipient_org and from_reg and not freemail
                         and registered_domain(recipient_org) != from_reg),
                    "Executive name from an external domain",
                    f"The sender presents as a senior person but writes from {ev.from_domain}, not your "
                    f"organisation's domain {recipient_org}.", "high", 20, "sender", "T1656"))

    # ---- 5. Reply-To / Return-Path ------------------------------------------
    rt_dom = ev.reply_to_address.rsplit("@", 1)[-1] if "@" in ev.reply_to_address else ""
    rt_mismatch = bool(rt_dom and from_reg and registered_domain(rt_dom) != from_reg)
    ind.append(_ind(rt_mismatch, "Replies go to a different domain",
                    f"Replying would send your answer to {ev.reply_to_address}, not to {ev.from_address}.",
                    "high" if rt_dom in orgs.FREEMAIL_DOMAINS else "medium",
                    20 if rt_dom in orgs.FREEMAIL_DOMAINS else 14, "sender", "T1566"))
    rp_dom = ev.return_path.rsplit("@", 1)[-1] if "@" in ev.return_path else ""
    ind.append(_ind(bool(rp_dom and from_reg and registered_domain(rp_dom) != from_reg and not a.get("dkim_aligned")),
                    "Envelope sender differs from From address",
                    f"The technical sender (Return-Path) is {ev.return_path}. Common for mailing services, "
                    "suspicious when DKIM is not aligned either.", "low", 5, "sender"))

    # ---- 6. Fake reply thread ------------------------------------------------
    ind.append(_ind(bool(ev.is_structured and REPLY_PREFIX.match(ev.subject or "")
                         and not ev.in_reply_to and not ev.references),
                    "Fake reply thread",
                    "Subject starts with RE:/FW: but the email is not part of any existing conversation — "
                    "a trick to make it look trusted.", "medium", 12, "sender", "T1566"))

    # ---- 7. Sender history ------------------------------------------------
    h = ev.sender_history
    ind.append(_ind(bool(h.get("available") and h.get("first_time") and not h.get("domain_seen_before")),
                    "First-time sender",
                    "You have never received an email from this sender or domain before.",
                    "low", 6, "history"))

    # ---- 8. Sending software -------------------------------------------------
    ind.append(_ind(bool(ev.x_mailer and SCRIPTED_MAILERS.search(ev.x_mailer) and (org_claim or exec_claim)),
                    "Bulk/scripted mailer",
                    f"Sent with '{ev.x_mailer[:60]}', a script/bulk-mail tool, while claiming to be an organisation.",
                    "medium", 10, "sender"))

    # ---- 9. Newly registered sender domain (network) ---------------------------------
    if network and from_reg and not freemail:
        try:
            from app.services import network_intel
            age = network_intel.get_domain_age(from_reg)
        except Exception:
            age = {"status": "unavailable"}
        if age.get("status") == "ok":
            d = age["age_days"]
            ind.append(_ind(d < 30, "Newly registered sender domain",
                            f"{from_reg} was registered {d} day(s) ago. Phishing domains are usually days old.",
                            "critical", 25, "sender", "T1583.001"))
            ind.append(_ind(30 <= d < 180, "Young sender domain",
                            f"{from_reg} is only {d} days old.", "medium", 10, "sender"))

    # ---- 10. Links: what you see vs where it goes --------------------------------------
    deceptive = []
    for ln in ev.links:
        shown = DOMAIN_IN_TEXT_RE.search(ln.display_text or "")
        if not shown:
            continue
        real_host = split_url(ln.url)["host"]
        shown_reg = registered_domain(shown.group(1).lower())
        if real_host and shown_reg and registered_domain(real_host) != shown_reg:
            deceptive.append((shown.group(1), real_host))
    ind.append(_ind(bool(deceptive), "Link text hides the real destination",
                    (f"A link shows '{deceptive[0][0]}' but actually opens {deceptive[0][1]}"
                     + (f" (+{len(deceptive) - 1} more)" if len(deceptive) > 1 else "") + ".") if deceptive else "",
                    "critical", 25, "links", "T1566.002"))

    risky_scheme = [ln.url for ln in ev.links if ln.url.lower().startswith(("javascript:", "data:"))]
    ip_links = [ln.url for ln in ev.links if re.match(r"^https?://\d{1,3}(\.\d{1,3}){3}", ln.url)]
    ind.append(_ind(bool(risky_scheme or ip_links), "Link to raw IP or script",
                    f"Link points to {(risky_scheme or ip_links)[0][:80] if (risky_scheme or ip_links) else ''} "
                    "instead of a named website.", "high", 18, "links", "T1566.002"))
    ind.append(_ind(any(ln.display_text == "[form submit]" for ln in ev.links), "Form embedded in email",
                    "The email contains an HTML form that submits data directly — used to steal passwords "
                    "without opening a website.", "high", 20, "links", "T1566"))

    ev.enrichment_indicators = ind
    return ev


def trust_signals(ev: EmailEvent) -> dict:
    """Evidence the email is genuine. Fusion uses this to cut false alarms."""
    a, h = ev.auth or {}, ev.sender_history or {}
    official = [c for c in ev.claimed_entities if c["official"] and c["where"] != "body_header"]
    return {
        "dmarc_pass": a.get("dmarc") == "pass",
        "dkim_aligned": bool(a.get("dkim_aligned")),
        "spf_pass": a.get("spf") == "pass",
        "known_sender": bool(h.get("available") and h.get("safe_count", 0) >= 2),
        "official_domain_for_claim": bool(official) and not any(not c["official"] for c in ev.claimed_entities
                                                                 if c["where"] != "body_header"),
        "real_thread": bool(ev.in_reply_to or ev.references),
    }
