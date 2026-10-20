"""
Government Official Impersonation detector.

Data source: app/ml/models/government_official_impersonation.joblib (TRAINED)
  TF-IDF + Logistic Regression, trained on 192 REAL government-agency
  impersonation phishing messages (HMRC/DVLA/Income Tax Dept tax-refund
  scams) plus synthetic examples covering themes the real data barely
  represents (arrest-warrant threats, immigration/visa fee scams, customs
  threats). See train_government_impersonation.py for exactly what's real
  vs synthetic. Auto-reloads on change.

Domain check: unlike banks or consumer brands, there is no fixed list of
"real government domains" — there are thousands of agencies worldwide. But
genuine government domains DO follow a recognizable pattern (.gov, .gov.in,
.gov.uk, .nic.in, .gc.ca, .gov.au, etc.), so this detector checks whether a
message CLAIMING to be from a government agency comes from a domain matching
that pattern, rather than needing a maintained list of specific agencies.
This is necessarily a loose heuristic: it will not catch a scam using a
government-TLD look-alike, and some real agencies may use non-standard
domains — it's one signal among several, not a verdict on its own.
"""
from __future__ import annotations

import os
import re
import uuid

import joblib

from app.detectors import phishing
from app.detectors.base import build_result

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "..", "ml", "models", "government_official_impersonation.joblib")

_model_cache: tuple[float, object] | None = None

# Claiming to represent a government body, in casual phrasing people actually use.
GOV_CLAIM_WORDS = (
    "government", "govt", "irs", "hmrc", "dvla", "income tax department", "income tax dept",
    "immigration department", "passport office", "social security", "court", "arrest warrant",
    "customs department", "election commission", "municipal corporation", "ministry of",
    "police department", "department of motor vehicles", "dmv", "benefits office",
)
GOV_TLD_PATTERN = re.compile(r"\.gov(\.[a-z]{2,3})?$|\.gc\.ca$|\.nic\.in$|\.mil$", re.I)


# ---------------------------------------------------------------------------------------------------------
# Indian government-impersonation SCAM SCRIPT (added 19 Oct after the Phase 2 audit: "digital arrest", fake
# CBI / police / TRAI / customs calls scored only 35-46). These scams follow a fixed script; each stage is a
# separate signal, and the COMBINATION decides the floor -- one word alone never does.
#   1. claims an agency      CBI, ED, NCB, police / cyber crime, TRAI, customs, RBI, income tax, UIDAI, court ...
#   2. threat                arrest / digital arrest / FIR / money laundering / drugs in a parcel / disconnection
#   3. isolation / secrecy   do not tell anyone, stay on the video call, do not disconnect
#   4. the ask               pay / transfer / security deposit / "verification account", share PIN / OTP / bank
#                            details, press 9 / call the officer, or a link to a NON-government website
# A genuine government notice informs ("processed", "completed", "dispatched", "paid successfully") and, if it has
# a link, it points to an official domain (.gov.in, .nic.in, .gov ...). Such a notice with NO threat and NO ask is
# capped low, so real ITR / UIDAI / passport messages are not flagged.
# ---------------------------------------------------------------------------------------------------------
AGENCY_RE = re.compile(
    r"\b(cbi|central bureau of investigation|enforcement directorate|\bed officer|ncb|narcotics control|"
    r"cyber ?crime|crime branch|police|inspector|commissioner|dcp|trai|telecom regulatory|customs|"
    r"reserve bank|rbi|income ?tax|electricity|itr|uidai|aadhaar|passport|parivahan|e-?challan|traffic police|court|"
    r"supreme court|high court|magistrate|ministry|government|govt|election commission|epfo|gst|gst department|municipal|electricity board|electricity (department|office|officer)|discom|power (department|office))\b", re.I)
THREAT_RE = re.compile(
    r"(digital(ly)? arrest|under arrest|arrest warrant|warrant (is )?issued|\bfir\b|case (has been )?registered|"
    r"money laundering|hawala|drugs?|narcotics|illegal (activity|items|parcel)|seized|legal action|court case|"
    r"non[- ]bailable|jail|prosecut|(electricity|power|light) (connection|supply)?[^.\n]{0,30}(cut|disconnect)|(connection|supply|power) will be (cut|disconnected)|suspend(ed)? (your )?(pan|aadhaar)|(number|sim|mobile|connection)[^.\n]{0,40}"
    r"(disconnect|block|deactivat|suspend)|will be (disconnected|blocked|deactivated|cancelled))", re.I)
SECRECY_RE = re.compile(
    r"(do ?n['o]?t (tell|inform|share this with|disconnect)|don't (tell|inform|disconnect)|tell (no ?one|nobody)|"
    r"keep (this|it) (secret|confidential)|stay on (the )?(video )?call|remain on (the )?call|confidential (investigation|matter))",
    re.I)
PAY_RE = re.compile(
    r"(transfer|pay|deposit|send)\b[^.\n]{0,60}(rs\.?|₹|inr|rupees|amount|deposit|fee|fine|account|upi)|"
    r"(security|refundable|verification) (deposit|amount|account)|rbi (verification|safe|secure) account|"
    r"clear your name|settle (the|this) case|processing fee|penalty", re.I)
CRED_RE = re.compile(
    r"(submit|share|enter|send|provide|update|verify)\b[^.\n]{0,40}(atm pin|\bpin\b|otp|cvv|card (number|details)|"
    r"bank (account )?details|account number|net ?banking|password)", re.I)
CALLBACK_RE = re.compile(r"(press [0-9]|call (the )?(officer|inspector|executive)|contact (the )?([a-z]+ )?(officer|inspector)|talk to (the )?officer|"
                         r"(officer|inspector) will call|join (the )?video call)", re.I)
INFO_RE = re.compile(r"\b(has been|is|was) (processed|completed|dispatched|delivered|approved|confirmed|credited|"
                     r"paid successfully|received|generated)\b|\bpaid successfully\b|appointment is confirmed", re.I)
LINK_RE = re.compile(r"\b((?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,24})(?:/[^\s]*)?", re.I)
OFFICIAL_TLD = re.compile(r"(\.gov(\.[a-z]{2,3})?|\.nic\.in|\.gc\.ca|\.mil)$", re.I)


def _links(text: str) -> list[str]:
    out = []
    for m in LINK_RE.finditer(text):
        host = m.group(1).lower().split("://")[-1]
        if "." in host and not re.fullmatch(r"[\d.]+", host) and not host.endswith((".txt", ".pdf")):
            out.append(host)
    return out


def scam_script(text: str) -> tuple[list[dict], int, int | None]:
    """-> (indicators, floor, cap). floor raises the score for a scam script; cap limits a genuine notice."""
    low = text.lower()
    agency = AGENCY_RE.search(low)
    threat, secrecy = THREAT_RE.search(low), SECRECY_RE.search(low)
    pay, cred, callback = PAY_RE.search(low), CRED_RE.search(low), CALLBACK_RE.search(low)
    links = _links(low)
    bad_links = [h for h in links if not OFFICIAL_TLD.search(h)]
    ask = pay or cred or callback or bad_links
    inds: list[dict] = []
    if not agency:
        return inds, 0, None

    def ev(m):
        return f' ("{m.group(0).strip()[:60]}")' if hasattr(m, "group") else ""
    inds.append(_ind(True, "Claims to be a government agency", f"The message speaks for an official body{ev(agency)}.",
                     "low", 5))
    if threat:
        inds.append(_ind(True, "Threat of arrest, legal case or disconnection",
                         f"Government scams frighten the victim first{ev(threat)}. Real agencies send written notices; "
                         "they never arrest anyone over a phone or video call (there is no 'digital arrest').",
                         "high", 20))
    if secrecy:
        inds.append(_ind(True, "Told to keep it secret / stay on the call",
                         f"Isolating the victim{ev(secrecy)} is the hallmark of 'digital arrest' scams.", "critical", 25))
    if pay:
        inds.append(_ind(True, "Asks for money", f"A payment / deposit is demanded{ev(pay)}. No agency collects fines or "
                         "'verification deposits' by transfer or UPI to an officer's account.", "critical", 25))
    if cred:
        inds.append(_ind(True, "Asks for PIN / OTP / bank details", f"{ev(cred).strip()} -- no government body ever "
                         "asks for these.", "critical", 30))
    if callback:
        inds.append(_ind(True, "Pushes you to call / press a key", f"Moves the victim to a phone or video call{ev(callback)}.",
                         "high", 15))
    if bad_links:
        inds.append(_ind(True, "Link to a non-government website",
                         f"Claims to be a government agency but links to {bad_links[0]}, which is not an official "
                         "government domain (.gov.in, .nic.in, .gov ...).", "high", 25))
    floor = 0
    if threat and (secrecy or pay or cred or callback):
        floor = 85 if (secrecy or pay or cred) else 71
    elif (pay or cred) and (bad_links or callback or threat):
        floor = 80
    elif pay or cred or (bad_links and re.search(r"\b(pay|fee|fine|refund|claim|pending|due)\b", low)):
        floor = 71
    elif threat:
        floor = 55
    cap = None
    if INFO_RE.search(low) and not (threat or secrecy or ask):
        cap = 25          # a genuine informational notice: no threat, no ask, official links only
    return inds, floor, cap


def _domain_of(email: str) -> str:
    return email.strip().lower().rsplit("@", 1)[-1] if "@" in email else ""


def _claims_government(text: str) -> bool:
    low = text.lower()
    return any(w in low for w in GOV_CLAIM_WORDS)


def _ind(triggered: bool, label: str, description: str, severity: str, weight: int) -> dict:
    return {"id": f"IND_{uuid.uuid4().hex[:12]}", "label": label, "description": description,
            "severity": severity, "weight": weight, "triggered": bool(triggered)}


def _get_model():
    global _model_cache
    if not os.path.exists(MODEL_PATH):
        _model_cache = None
        return None
    mtime = os.path.getmtime(MODEL_PATH)
    if _model_cache and _model_cache[0] == mtime:
        return _model_cache[1]
    try:
        model = joblib.load(MODEL_PATH)
    except Exception:
        model = None
    _model_cache = (mtime, model)
    return model


def analyze_government_impersonation(text: str, extra_field_values: dict, subtopic_title: str) -> dict:
    text = text or ""
    sender_email = (extra_field_values or {}).get("senderEmail", "").strip().lower()
    indicators: list[dict] = []

    if _claims_government(text):
        actual_domain = _domain_of(sender_email)
        if sender_email and not GOV_TLD_PATTERN.search(actual_domain):
            indicators.append(_ind(
                True, "Sender domain doesn't match a government pattern",
                f"The message claims to represent a government agency, but '{actual_domain}' doesn't match "
                "a recognized government domain pattern (.gov, .gov.in, .gov.uk, .nic.in, etc.). This is a "
                "loose signal, not proof — some agencies use other domains, and a scammer could pick a "
                "look-alike government-style domain.",
                "medium", 25,
            ))
        elif not sender_email:
            indicators.append(_ind(
                True, "No sender email given to verify",
                "The message claims to represent a government agency, but no sender email was provided "
                "to check against a government domain pattern.",
                "low", 5,
            ))

    general = phishing._rule_indicators(text, sender=sender_email or None, reply_to=None) if text.strip() else []
    indicators.extend(general)
    pattern_inds, pattern_floor = phishing.scam_patterns(text, "government") if text.strip() else ([], 0)
    indicators.extend(pattern_inds)
    script_inds, floor, cap = scam_script(text) if text.strip() else ([], 0, None)
    indicators.extend(script_inds)

    rule_score = sum(i["weight"] for i in indicators if i["triggered"])
    model = _get_model()
    model_used = model is not None and bool(text.strip())
    proba = None
    if model_used:
        try:
            proba = float(model.predict_proba([text])[0][1])
            blended = 0.65 * (proba * 100) + 0.35 * min(rule_score, 100)
            confidence = 60 + abs(proba - 0.5) * 60
        except Exception:
            model_used = False
            blended = min(rule_score, 100)
            confidence = 40 + min(rule_score, 50)
    else:
        blended = min(rule_score, 100)
        confidence = 40 + min(rule_score, 50)

    if floor:
        blended = max(blended, floor)
        confidence = max(confidence, 80)
    elif cap is not None:
        blended = min(blended, cap)
    if pattern_floor:
        blended = max(blended, pattern_floor)
    for ind in indicators:
        ind.setdefault("id", f"IND_{uuid.uuid4().hex[:12]}")
    triggered = [i for i in indicators if i["triggered"]]

    if not text.strip():
        explanation, blended, confidence = "No content was submitted to analyze.", 0, 0
    elif triggered:
        top = sorted(triggered, key=lambda i: -i["weight"])[:3]
        names = ", ".join(i["label"].lower() for i in top)
        model_note = f" Trained classifier: {proba*100:.0f}% probability of impersonation." if model_used else " (Trained model unavailable — rule-based only.)"
        explanation = f"{len(triggered)} indicator(s) triggered, most notably: {names}.{model_note}"
    else:
        model_note = f"the trained classifier assessed a {proba*100:.0f}% probability of impersonation" if model_used else "no trained model was available"
        explanation = f"No rule-based indicators were triggered; {model_note}."

    return build_result(
        indicators=indicators, base_score=blended, confidence=confidence,
        engine_name=f"CYBERGUARD Impersonation Engine — {'TF-IDF+LogReg (192 real + synthetic)' if model_used else 'Rule-Based (model unavailable)'}",
        threat_type=subtopic_title, explanation=explanation,
    )