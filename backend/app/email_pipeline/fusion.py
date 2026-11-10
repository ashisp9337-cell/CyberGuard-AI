"""
Step 3b - Fusion: many detector results -> one verdict.

Rules, in order:
  1. Start from the strongest single piece of evidence.
  2. Corroboration: several independent detectors agreeing raises the score.
  3. Trust: an authenticated sender (DMARC pass + aligned DKIM), a known
     sender, an official domain for the claimed organisation and a real reply
     thread lower the score - but ONLY the text/sender evidence. A malicious
     link or attachment is never discounted, because real accounts get
     hacked and send real malware.
  4. Hard floors: combinations that are conclusive on their own (DMARC fail +
     impersonated organisation, executable attachment, deceptive link to a bad
     site ...) set a minimum score whatever the ML says.
  5. Genuine account-security notifications are re-labelled as possible
     account takeover instead of phishing.
"""
import re

from app.detectors.base import build_result

IMPERSONATION_CATEGORY = {
    "management-impersonation": ("Business Email Compromise (CEO / executive fraud)", ["T1566", "T1656", "T1534"]),
    "government-impersonation": ("Government impersonation scam", ["T1566", "T1656"]),
    "financial-impersonation": ("Bank / financial institution impersonation", ["T1566", "T1656"]),
    "brand-impersonation": ("Brand impersonation phishing", ["T1566", "T1656"]),
    "teacher-impersonation": ("Teacher / university authority impersonation", ["T1566", "T1656"]),
    "contact-impersonation": ("Known-contact impersonation", ["T1566", "T1656"]),
}
TEXT_COMPONENTS = ("phishing", "impersonation", "sender")
STRUCTURAL_LINK_LABELS = {"Unusually long URL", "High character entropy", "Excessive hyphens in domain/path",
                          "Excessive subdomains"}
SOFT_TEXT_LABELS = {"No sender email given to verify", "Urgency language detected", "Generic greeting",
                    "Multiple brands named in one message", "Spelling anomalies", "Sender domain not matched to any known brand",
                    "Message claims government/bank authority", "Claims to be a government agency"}
CONTENT_COMPONENTS = ("url", "qr", "attachment")


_ASK_SECRET_RE = re.compile(r"\b(?:enter|share|send|provide|confirm|update|verify|submit|reply|respond|type|give|tell|"
                            r"fill(?: in)?|re-?enter|validate|disclose)\b[^.\n]{0,50}?(?<![a-z])(?:password|passcode|otp|"
                            r"one[- ]time (?:password|code)|pin|cvv|card number|card details|account number|aadhaar|"
                            r"login (?:id|details|credentials)|credentials|net ?banking (?:id|password))(?![a-z])", re.I)


def asks_for_secret(text: str) -> bool:
    """(10 Nov) The text ASKS the reader to give a secret ('enter your password', 'share the OTP'), outside a
    'never share' warning. 'The PDF password is your date of birth' tells, it does not ask."""
    from app.detectors.phishing import _CRED_WARNING_RE
    return bool(_ASK_SECRET_RE.search(_CRED_WARNING_RE.sub(" ", text or "")))


CLAIM_TO_DETECTOR = {"government": "government-impersonation", "bank": "financial-impersonation",
                     "brand": "brand-impersonation", "education": "teacher-impersonation"}


def _claimed_impersonation(ev, imp_components):
    """The impersonation result for the organisation type the sender claims to be,
    checking display name/subject claims first, then the body."""
    flagged = {c["name"]: c for c in imp_components if c["score"] > 50}
    for where in ("display_name", "subject", "body_header"):
        for claim in ev.claimed_entities:
            if claim["where"] == where and not claim["official"]:
                det = CLAIM_TO_DETECTOR.get(claim["category"])
                if det in flagged:
                    return flagged[det]
    if "management-impersonation" in flagged and any(
            i["label"] == "Free email account claiming authority" and i["triggered"] for i in ev.enrichment_indicators):
        return flagged["management-impersonation"]
    return None


def _labels(indicators, triggered_only=True):
    return {i["label"] for i in indicators if i.get("triggered") or not triggered_only}


def fuse(ev, components: list[dict], trust: dict) -> dict:
    """components: [{"component": "phishing"|"impersonation"|"url"|"qr"|"attachment"|"sender"|"account_takeover",
                     "name": str, "score": int, "result": dict}]"""
    by = {}
    for c in components:
        by.setdefault(c["component"], []).append(c)

    def best(kind):
        items = by.get(kind, [])
        return max(items, key=lambda c: c["score"]) if items else None

    text_ev = max([best(k)["score"] for k in TEXT_COMPONENTS if best(k)] or [0])
    content_ev = max([best(k)["score"] for k in CONTENT_COMPONENTS if best(k)] or [0])
    enrich_labels = _labels(ev.enrichment_indicators)

    # -- 3. trust (text evidence only) --------------------------------------------
    hard_sender_flags = {"DMARC failed", "Sender impersonates an organisation", "Look-alike sender domain",
                         "Display name hides a different address", "Link text hides the real destination"}
    reduction = 0
    if trust.get("dmarc_pass") and trust.get("dkim_aligned") and not (enrich_labels & hard_sender_flags):
        reduction = 15 + (10 if trust.get("known_sender") else 0) \
            + (10 if trust.get("official_domain_for_claim") else 0) + (5 if trust.get("real_thread") else 0)
    text_adj = max(0, text_ev - reduction)
    # An authenticated sender that is the real organisation it claims to be (or a
    # known-good sender): wording alone cannot make it malicious. Content evidence
    # (links/attachments/QR) still can - compromised accounts send real malware.
    # (4 Nov) ...and a genuine brand mailing: the brand named in the email is the sender's OWN authenticated domain
    # (offers@mailer.amazon.in talking about Amazon). Brand wording alone then cannot make it "brand impersonation";
    # links to other sites, attachments and QR codes are still judged on their own.
    # Never for a free-mail address: anyone can own an @gmail.com account, and "Google Play gift cards" in the text
    # does not make a Gmail sender genuine (CEO gift-card fraud comes exactly from such accounts).
    from app.email_pipeline.org_directory import FREEMAIL_DOMAINS
    sender_domain = (getattr(ev, "from_domain", "") or "").lower()
    brand_is_sender = (bool(sender_domain) and sender_domain not in FREEMAIL_DOMAINS and
                       any(c["component"] == "impersonation" and c["name"] == "brand-impersonation"
                           and c["result"].get("senderVerifiedBrand") for c in components))
    vouched = (trust.get("dmarc_pass") and trust.get("dkim_aligned")
               and (trust.get("official_domain_for_claim") or trust.get("known_sender") or brand_is_sender)
               and not (enrich_labels & hard_sender_flags))
    if vouched:
        text_adj = min(text_adj, 25 if text_ev < 85 else 45)
        # (10 Nov) the bank's own authenticated newsletter: its click-tracking links (SendGrid, OneLink ...) are long
        # and random-looking by design. Length / randomness / hyphens alone prove nothing about such a link; anything
        # real about it (blocklist hit, look-alike name, dead or new domain, redirect to another site) still counts.
        def _link_score(c):
            fired = [i for i in (c["result"].get("indicators") or []) if i.get("triggered") and i.get("weight", 0) > 0]
            if c["component"] == "url" and fired and all(i["label"] in STRUCTURAL_LINK_LABELS for i in fired):
                return min(c["score"], 25)
            return c["score"]
        content_ev = max([_link_score(c) for c in components if c["component"] in CONTENT_COMPONENTS] or [0])
    # (10 Nov) An e-mail COPIED from Gmail / Outlook (no headers, so SPF / DKIM / DMARC cannot be read) whose sender
    # address is an official domain of the organisation it names (alerts@hdfcbank.net for HDFC Bank). The mail app
    # already ran those checks when it arrived, and these banks publish strict DMARC, so a forged From: rarely reaches
    # the inbox. Wording alone ("Dear Customer", "report immediately", "password-protected statement") then cannot make
    # it phishing - but links, attachments and QR codes are still judged on their own, exactly as for vouched mail.
    pasted_official_org = None
    if not vouched and not (ev.auth or {}).get("available") and sender_domain and sender_domain not in FREEMAIL_DOMAINS \
            and not (enrich_labels & hard_sender_flags) and not getattr(ev, "reply_to_address", ""):
        from app.email_pipeline.org_directory import official_sender_entity
        pasted_official_org = official_sender_entity(
            sender_domain, f"{getattr(ev, 'from_display_name', '')}\n{getattr(ev, 'subject', '')}\n{ev.full_text[:4000]}")
    if pasted_official_org is not None:
        fired = {i["label"] for c in components if c["component"] in TEXT_COMPONENTS
                 for i in (c["result"].get("indicators") or []) if i.get("triggered")}
        if fired & {"Financial lure / prize claim", "Account or parcel held until you pay"} or \
                any(l.startswith("Scam pattern") for l in fired) or asks_for_secret(ev.full_text):
            pasted_official_org = None          # genuine banks never ask for these, whoever the sender seems to be
    pasted_official = pasted_official_org is not None
    if pasted_official:
        text_adj = min(text_adj, 20 if text_ev < 85 else 50)

    # -- 1 + 2. strongest evidence + corroboration ---------------------------------------
    score = max(text_adj, content_ev)
    agreeing = [k for k in ("phishing", "impersonation", "sender", "url", "qr", "attachment")
                if best(k) and (best(k)["score"] - (reduction if k in TEXT_COMPONENTS else 0)) > 50
                and not ((vouched or pasted_official) and k in TEXT_COMPONENTS)]
    if len(agreeing) > 1:
        score += min(20, 7 * (len(agreeing) - 1))

    # -- 4. hard floors ------------------------------------------------------------------
    floors = []
    if "DMARC failed" in enrich_labels and enrich_labels & {"Sender impersonates an organisation", "Look-alike sender domain"}:
        floors.append((92, "Spoofed sender impersonating an organisation (DMARC fail)"))
    if enrich_labels & {"Sender impersonates an organisation", "Look-alike sender domain"}:
        floors.append((75, "Sender identity does not match the organisation it claims to be"))
    if "Link text hides the real destination" in enrich_labels:
        floors.append((70, "Link text disguises its real destination"))
        if best("url") and best("url")["score"] >= 60:
            floors.append((88, "Disguised link leads to a malicious site"))
    if best("attachment") and best("attachment")["score"] >= 40:
        floors.append((88, "Dangerous attachment"))
    if best("qr") and best("qr")["score"] >= 60:
        floors.append((78, "QR code leads to a suspicious destination"))
    if "Free email account claiming authority" in enrich_labels and best("impersonation") and best("impersonation")["score"] > 50:
        floors.append((80, "Authority claim from a personal email account"))
    for f, _ in floors:
        score = max(score, f)
    # (10 Nov) A body copied WITHOUT its sender line, with no link, attachment or QR code, and only soft wording
    # signals (urgency, "Dear Customer", no sender to check, several names): nothing proves it is fake and the sender
    # cannot be checked, so it is "check the sender" (at most 55), not a confirmed attack. Any request for a password /
    # OTP / money, a scam pattern or a risky link keeps the full score.
    no_sender_soft = False
    if not getattr(ev, "from_address", "") and not floors and content_ev == 0 and not ev.links \
            and not [a for a in ev.attachments if not a.is_inline] and score > 55:
        fired = {i["label"] for c in components for i in (c["result"].get("indicators") or []) if i.get("triggered")}
        if fired and fired <= SOFT_TEXT_LABELS:
            score, no_sender_soft = 55, True
    score = int(max(0, min(100, round(score))))

    # -- 5. category -------------------------------------------------------------------------
    ato = best("account_takeover")
    mitre: list[str] = []
    if ato and ato["result"].get("genuine_provider"):
        score = ato["score"]
        if score > 25:
            category = "Possible account takeover (genuine security alert)"
            mitre = ["T1078", "T1098"] + (["T1114.003"] if ato["result"]["signals"].get("forwarding_rule") else [])
        else:
            category = "Genuine account-security notification (informational)"
    elif score <= 25:
        category = "No threat detected"
    elif best("attachment") and best("attachment")["score"] >= 40:
        category, mitre = "Malware delivery (malicious attachment)", ["T1566.001", "T1204.002"]
    elif best("qr") and best("qr")["score"] >= 60 and best("qr")["score"] >= text_adj:
        category, mitre = "QR code phishing (quishing)", ["T1566.002"]
    elif not (vouched or pasted_official) and best("impersonation") and (
            best("impersonation")["score"] >= max(text_adj - 5, 51)
            # (10 Nov) the sender's name claims a BANK or a GOVERNMENT office its address does not belong to: that is
            # bank / government impersonation, even when the mail also carries a bad link (a brand like Microsoft
            # with a bad link stays "credential phishing", as before)
            or ("Sender impersonates an organisation" in enrich_labels
                and (_claimed_impersonation(ev, by.get("impersonation", [])) or {}).get("name")
                in ("financial-impersonation", "government-impersonation"))):
        imp = _claimed_impersonation(ev, by.get("impersonation", [])) or best("impersonation")
        category, mitre = IMPERSONATION_CATEGORY.get(imp["name"], ("Impersonation", ["T1656"]))
    elif best("url") and best("url")["score"] >= 60 or "Link text hides the real destination" in enrich_labels:
        category, mitre = "Credential phishing (malicious link)", ["T1566.002"]
    else:
        category, mitre = "Phishing email", ["T1566"]

    # -- indicators: sender/auth checks + every triggered detector finding ------------------------
    indicators, seen = [], set()
    if pasted_official:
        indicators.append({"id": "IND_official_sender", "label": "Official sender address (copied e-mail)",
                           "description": f"'{sender_domain}' is an official domain of {pasted_official_org['name']}. A "
                           "copied e-mail has no SPF / DKIM / DMARC results, so this is not proof - your mail app checked "
                           "them when it arrived. Its wording alone was not treated as a threat; its links, attachments "
                           "and QR codes were still checked. For full proof upload the original (.eml) file (Gmail: "
                           "⋮ > Download message).", "severity": "low", "weight": 0, "triggered": True})
        seen.add(indicators[0]["label"])
    for i in ev.enrichment_indicators:
        if i["label"] not in seen:
            seen.add(i["label"])
            indicators.append(i)
    for c in sorted(components, key=lambda c: -c["score"]):
        if c["component"] == "sender":
            continue
        if (vouched or pasted_official) and c["component"] in ("phishing", "impersonation"):
            continue  # overruled by sender authentication; still listed under "components"
        for i in c["result"].get("indicators", []):
            if i.get("triggered") and i["label"] not in seen:
                seen.add(i["label"])
                indicators.append(dict(i, source=i.get("source") or c["name"]))

    # -- explanation -----------------------------------------------------------------------
    a = ev.auth or {}
    auth_txt = (f"SPF {a.get('spf')}, DKIM {a.get('dkim')}, DMARC {a.get('dmarc')}" if a.get("available")
                else "sender authentication not available")
    top = sorted([i for i in indicators if i.get("triggered")], key=lambda i: -i.get("weight", 0))[:3]
    reasons = "; ".join(i["label"] for i in top) or "no red flags"
    ran = ", ".join(sorted({c["name"] for c in components}))
    trust_txt = f" Trust adjustments: -{reduction} (authenticated sender)." if reduction else ""
    if pasted_official:
        trust_txt += (f" The sender address is an official {pasted_official_org['name']} domain, so the wording alone "
                      "was not counted as a threat; links and attachments were still checked.")
    explanation = (f"{category} — risk {score}/100. Top reasons: {reasons}. "
                   f"Checked: {auth_txt}; {len(ev.links)} link(s); {len([x for x in ev.attachments if not x.is_inline])} "
                   f"attachment(s); detectors: {ran}.{trust_txt}")
    if floors:
        explanation += f" Escalated because: {max(floors)[1]}."
    if no_sender_soft:
        explanation += (" Only the message body was copied, so the sender could not be checked and nothing in it proves "
                        "it is fake: copy the whole e-mail including the sender line (Name <address>) and scan again.")

    recs = []
    if score > 70:
        recs += ["Quarantine this email and block the sender domain.",
                 "Do not click links, scan QR codes, or open attachments from this message."]
    if category.startswith("Business Email Compromise"):
        recs.append("Verify any payment or data request by calling the person on a known number — never by replying.")
    if category.startswith(("Possible account takeover", "Genuine account-security")):
        recs = []  # ATO engine already supplies its own recommendations
        recs += ato["result"].get("recommendations", [])[:2]

    contributions = sum(1 for c in components if c["score"] > 0)
    confidence = min(97, 55 + (15 if a.get("available") else 0) + 5 * min(contributions, 5))

    result = build_result(indicators=indicators, base_score=score, confidence=confidence,
                          engine_name="CYBERGUARD Email Intelligence Pipeline — Fusion",
                          threat_type=category, explanation=explanation, extra_recommendations=recs)
    result["category"] = category
    result["mitre"] = mitre
    result["trust"] = trust | {"reduction": reduction, "pasted_official": pasted_official}
    result["escalations"] = [r for _, r in sorted(floors, reverse=True)]
    result["components"] = [{"component": c["component"], "name": c["name"], "score": c["score"],
                             "classification": c["result"].get("classification"),
                             "engine": c["result"].get("analysisEngine"),
                             "explanation": c["result"].get("explanation", "")[:300]} for c in components]
    return result
