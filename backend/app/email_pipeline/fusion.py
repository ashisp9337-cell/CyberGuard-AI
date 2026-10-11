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
CONTENT_COMPONENTS = ("url", "qr", "attachment")


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
    vouched = (trust.get("dmarc_pass") and trust.get("dkim_aligned")
               and (trust.get("official_domain_for_claim") or trust.get("known_sender"))
               and not (enrich_labels & hard_sender_flags))
    if vouched:
        text_adj = min(text_adj, 25 if text_ev < 85 else 45)

    # -- 1 + 2. strongest evidence + corroboration ---------------------------------------
    score = max(text_adj, content_ev)
    agreeing = [k for k in ("phishing", "impersonation", "sender", "url", "qr", "attachment")
                if best(k) and (best(k)["score"] - (reduction if k in TEXT_COMPONENTS else 0)) > 50
                and not (vouched and k in TEXT_COMPONENTS)]
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
    elif not vouched and best("impersonation") and best("impersonation")["score"] >= max(text_adj - 5, 51):
        imp = _claimed_impersonation(ev, by.get("impersonation", [])) or best("impersonation")
        category, mitre = IMPERSONATION_CATEGORY.get(imp["name"], ("Impersonation", ["T1656"]))
    elif best("url") and best("url")["score"] >= 60 or "Link text hides the real destination" in enrich_labels:
        category, mitre = "Credential phishing (malicious link)", ["T1566.002"]
    else:
        category, mitre = "Phishing email", ["T1566"]

    # -- indicators: sender/auth checks + every triggered detector finding ------------------------
    indicators, seen = [], set()
    for i in ev.enrichment_indicators:
        if i["label"] not in seen:
            seen.add(i["label"])
            indicators.append(i)
    for c in sorted(components, key=lambda c: -c["score"]):
        if c["component"] == "sender":
            continue
        if vouched and c["component"] in ("phishing", "impersonation"):
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
    explanation = (f"{category} — risk {score}/100. Top reasons: {reasons}. "
                   f"Checked: {auth_txt}; {len(ev.links)} link(s); {len([x for x in ev.attachments if not x.is_inline])} "
                   f"attachment(s); detectors: {ran}.{trust_txt}")
    if floors:
        explanation += f" Escalated because: {max(floors)[1]}."

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
    result["trust"] = trust | {"reduction": reduction}
    result["escalations"] = [r for _, r in sorted(floors, reverse=True)]
    result["components"] = [{"component": c["component"], "name": c["name"], "score": c["score"],
                             "classification": c["result"].get("classification"),
                             "engine": c["result"].get("analysisEngine"),
                             "explanation": c["result"].get("explanation", "")[:300]} for c in components]
    return result
