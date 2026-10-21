"""
Real phishing/scam text detector: combines a trained TF-IDF + Logistic
Regression model with deterministic rule-based indicators extracted from
the ACTUAL submitted text (not random). If the trained model file is
missing, the detector still runs on rules alone and reports the model as
unavailable rather than fabricating a confidence score.

Each phishing subtopic (email / SMS / social media) can have its own
independently-trained model file — see MODEL_FILES below. Subtopics not
listed fall back to the shared DEFAULT_MODEL_FILE.
"""
import os
import re
import uuid
import joblib

from app.core.config import get_settings
from app.detectors.base import build_result

settings = get_settings()

# subtopic_id -> model filename (relative to settings.MODELS_DIR).
# Train each with: python -m app.ml.training.train_phishing --data <file> --out <filename> --pos-label <label>
MODEL_FILES = {
    "email-analysis": "phishing_email.joblib",
    "sms-analysis": "phishing_sms.joblib",
    "social-media-analysis": "phishing_social.joblib",
}
DEFAULT_MODEL_FILE = "phishing_pipeline.joblib"

_model_cache: dict[str, tuple[float, object]] = {}  # filename -> (mtime, model)


def _get_model(subtopic_id: str | None):
    """
    Loads the model for a subtopic, auto-reloading it if the .joblib file
    on disk has changed since it was last cached (so a freshly retrained
    model is picked up without needing to restart the backend). If the
    file is missing, unreadable, or fails to load, returns None — the
    caller falls back to rule-based-only scoring rather than crashing.
    """
    filename = MODEL_FILES.get(subtopic_id or "", DEFAULT_MODEL_FILE)
    path = os.path.join(settings.MODELS_DIR, filename)

    if not os.path.exists(path):
        _model_cache.pop(filename, None)
        return None

    mtime = os.path.getmtime(path)
    cached = _model_cache.get(filename)
    if cached and cached[0] == mtime:
        return cached[1]

    try:
        model = joblib.load(path)
    except Exception:
        model = None
    _model_cache[filename] = (mtime, model)
    return model


URGENCY_WORDS = [
    "urgent", "immediately", "act now", "verify your account", "suspended",
    "expire", "act fast", "limited time", "final notice", "click here now",
    "action required", "your account will be locked", "unusual activity",
    "confirm your identity", "response required", "within 24 hours",
    "avoid suspension", "restricted access", "security alert",
]
CREDENTIAL_WORDS = [
    "password", "otp", "one-time code", "one-time password", "pin", "cvv",
    "login credentials", "ssn", "social security", "security question",
    "date of birth", "account number", "routing number", "card number",
    "bank details", "account details", "upi pin", "aadhaar number",
]
MONEY_WORDS = [
    "wire transfer", "gift card", "bitcoin", "crypto", "claim your prize",
    "you have won", "lottery", "refund", "tax rebate", "unclaimed funds",
    "inheritance", "cashapp", "venmo", "western union", "processing fee",
    "double your money", "guaranteed returns", "guaranteed profit", "send funds",
]
KNOWN_BRANDS = [
    "paypal", "microsoft", "amazon", "apple", "bank", "google", "netflix",
    "facebook", "instagram", "linkedin", "irs", "fedex", "ups", "dhl",
    "chase", "wells fargo", "hdfc", "sbi", "icici",
]
LINK_RE = re.compile(r"https?://\S+|www\.\S+")
# Bare domains ("indiapost-track.cyou", "netflix-billing-help.com/pay") -- SMS scams rarely write http://.
# Only common / abused endings, a letter in the name, and not part of an e-mail address.
BARE_DOMAIN_RE = re.compile(
    r"(?<![@\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|in|net|org|co|info|biz|top|xyz|cyou|click|shop|"
    r"online|site|live|club|vip|icu|app|link|me|io|help|support|store|tech|website|space|fun|buzz|rest|cfd|sbs|"
    r"lol|mobi|ws|cc|ly|gd|to|tk|ml|ga|cf|gq|pw|cn|ru|su|id|pk|bd|ng)(?:/[^\s]*)?)(?![\w-])", re.I)


ABUSED_TLDS = {"top", "xyz", "cyou", "click", "shop", "online", "site", "live", "club", "vip", "icu", "link", "help",
               "support", "store", "website", "space", "fun", "buzz", "rest", "cfd", "sbs", "lol", "tk", "ml", "ga", "cf",
               "gq", "pw", "su", "ws"}
RISKY_HOST_WORDS = re.compile(r"(login|log-in|signin|verify|secure|update|account|billing|kyc|support|help|track|"
                              r"redeliver|delivery|refund|reward|claim|bonus|wallet|unlock|appeal|confirm)", re.I)


def risky_bare_domains(text: str) -> list[str]:
    """Bare domains that LOOK risky on their own: abused ending, a hyphenated name, or phishing words in the name.
    (A plain shop / short-link domain in a marketing SMS is not counted as a suspicious link by itself.)"""
    out = []
    for url in bare_domains(text):
        host = url[7:].split("/")[0].lower()
        labels = host.split(".")
        if labels[-1] in ABUSED_TLDS or "-" in ".".join(labels[:-1]) or RISKY_HOST_WORDS.search(".".join(labels[:-1])):
            out.append(url)
    return out


_OTP_GIVEN = re.compile(r"\b(otp|one[- ]time (password|code)|verification code|security code|code)\b[^.\n]{0,60}"
                        r"\b(is|:)\s*\d{4,8}\b|\b\d{4,8}\b[^.\n]{0,15}\bis (your|the)( [a-z0-9&-]+){0,2} (otp|code|one[- ]time|verification code)", re.I)
_DONT_SHARE = re.compile(r"\b(do not|don'?t|never) (share|disclose|tell)", re.I)
_OTP_ASK = re.compile(r"\b(share|send|forward|tell|reply( with)?|enter|give)\b[^.\n]{0,25}\b(otp|code|pin)\b", re.I)


def otp_notice(text: str) -> bool:
    """A real one-time-code SMS GIVES you a code and says 'do not share it'; a scam ASKS you to share one.
    True for a code delivery with that warning, no request and no link."""
    t = text or ""
    if not (_OTP_GIVEN.search(t) and _DONT_SHARE.search(t)) or LINK_RE.search(t) or risky_bare_domains(t):
        return False
    asks = [m for m in _OTP_ASK.finditer(t) if not _DONT_SHARE.search(t[max(0, m.start() - 12):m.end()])]
    return not asks


def bare_domains(text: str) -> list[str]:
    """Untrusted bare domains in the text, as http:// links (trusted sites such as swiggy.com are left out)."""
    from app.detectors import trusted_domains
    out = []
    for m in BARE_DOMAIN_RE.finditer(text or ""):
        d = m.group(1).rstrip(".,;:)")
        host = d.split("/")[0].lower()
        if not re.search(r"[a-z]", host.split(".")[0]) or host.count(".") > 5:
            continue
        url = "http://" + d
        if not trusted_domains.is_trusted(url) and url not in out:
            out.append(url)
    return out


# ---------------------------------------------------------------------------------------------------------
# Scam PATTERNS (added 19 Oct, Phase 2 audit). Each pattern needs a COMBINATION of signals -- one word alone never
# fires -- and sets a minimum score (the model-weighted blend could otherwise keep a textbook scam below 51).
# ---------------------------------------------------------------------------------------------------------
_P = lambda rx: re.compile(rx, re.I)  # noqa: E731
_PARCEL = (_P(r"\b(parcel|package|shipment|consignment|courier|delivery|india ?post|speed ?post|fedex|dhl|blue ?dart|dtdc)\b"),
           _P(r"(on hold|held|undeliver|could ?n[o']?t be delivered|incomplete address|address (is )?incomplete|failed (delivery|attempt)|"
              r"re-?deliver|reschedul|customs|returned to sender|pending (delivery|payment))"),
           _P(r"\b(pay|fee|charge|charges|duty|rs\.?|inr|₹|\$)\b|₹"))
_INVEST = (_P(r"\b(crypto|bitcoin|btc|usdt|forex|trading|trade|invest(ment|ing)?|profits?|returns?|earn(ed|ing)?|income)\b"),
           _P(r"\b(dm|inbox|telegram|whatsapp|message (him|her|me)|contact (him|her|me)|add (him|her|me))\b|(?<![\w.])@[a-z0-9_]{4,}"),
           _P(r"(\$ ?\d|rs\.? ?\d|₹ ?\d|\d+ ?(k|lakh|lac)\b|per day|daily|weekly|guarantee|100 ?%|legit|risk[- ]free|"
              r"double your)"))
_TASK = (_P(r"\b(like|subscribe|rate|review|watch)\b[^.\n]{0,40}\b(videos?|products?|posts?|hotels?|apps?)\b"),
         _P(r"\b(earn|income|salary|paid|commission)\b"),
         _P(r"(registration|joining|activation|security) (fee|charge|amount|deposit)|\bfee\b"))
_APPEAL = (_P(r"\b(account|page|channel|profile|handle)\b"),
           _P(r"\b(deleted|disabled|deactivated|suspended|removed|banned|terminated|restricted)\b"),
           _P(r"(copyright|violat|community (guidelines|standards)|infring|appeal|verify (your )?(account|identity)|blue ?tick|"
              r"verification badge)"))
_BILLING = (_P(r"\b(payment|billing|card|subscription|membership|order)\b"),
            _P(r"(failed|declined|could ?n[o']?t (be )?process|unable to process|on hold|expired|unpaid|will be (cancel|suspend))"),
            _P(r"\b(update|verify|confirm|re-?enter|add)\b[^.\n]{0,30}\b(billing|payment|card|details|method|information)\b"))
_EMERG = (_P(r"(stuck|stranded|accident|in (the )?hospital|lost (my )?(phone|wallet|passport|bag)|card (is |got |was )?blocked|"
             r"robbed|police station|emergency|urgent(ly)? need)"),
          _P(r"\b(send|transfer|pay|need|lend)\b[^.\n]{0,40}(rs\.? ?\d|₹ ?\d|\$ ?\d|money|amount|gpay|google pay|phonepe|paytm|"
             r"upi|account)"),
          _P(r"\b(it'?s|this is|i am|i'm)\s+[a-z]+|\b(mum|mom|dad|bhai|bro|aunty|uncle|sis)\b|my (phone|number)"))
_BEC = (_P(r"\b(ceo|cfo|md|managing director|director|chairman|president|boss|founder|partner)\b"),
        _P(r"\b(wire|transfer|payment|remit|gift ?cards?|deposit|funds|invoice)\b"),
        _P(r"(strictly confidential|keep (this|it) confidential|confidential (deal|matter|transaction|acquisition)|"
           r"tell (no ?one|nobody)|do ?n[o']?t (tell|call|discuss|inform|share)|keep (this|it) (between us|quiet|secret)|"
           r"be discreet|i'?m in a meeting|can'?t (talk|take calls))"))
# academic authority scams (added 21 Oct after a live check of realistic Indian college messages)
_ACAD = r"(principal|hod|head of (the )?department|professor|prof\.?|dean|registrar|vice[- ]chancellor|exam(ination)? cell|" \
        r"controller of exam\w*|placement (cell|officer)|training (&|and) placement|t ?& ?p cell|teacher|faculty|" \
        r"class coordinator|warden)"
_ACAD_FAVOUR = (_P(r"\b" + _ACAD + r"\b"),
                _P(r"(gift ?cards?|new (whats ?app |mobile |phone )?number|personal number|(small|quick|urgent) favou?r|"
                   r"i'?m in a meeting|can'?t (talk|take calls))"),
                _P(r"\b(buy|purchase|codes?|urgent(ly)?|asap|immediately|right now|kindly|whats ?app|text me|message me)\b"))
_ACAD_FEE = (_P(r"\b(internship|offer letter|job offer|placement|scholarship|stipend|fellowship|admit card|hall ticket|"
                r"degree|certificate|result)s?\b"),
             _P(r"(security deposit|registration (fee|charge)|processing (fee|charge)|release (fee|charge)|verification fee|"
                r"refundable deposit|pay (a |the )?(small )?(fee|amount|deposit)|pay (rs\.?|inr|₹) ?\d)"))
_OTP_REQ = (_P(r"\b(send|share|tell|forward|give|read out)\s+(me\s+)?(the\s+|your\s+|that\s+|this\s+)?(otp|one[- ]time password|"
               r"verification code|(\d[- ]digit )?code (you|that) (just )?(received|got))"),)
_OTP_SAFE = _P(r"(do ?n[o']?t|never|no one|nobody|not to)\s+(\w+\s+){0,3}(send|share|tell|forward|give|read out)")
_SCHOLAR_HOLD = (_P(r"\b(scholarship|stipend|fellowship|nsp|pm[- ]?yasasvi|post[- ]matric)\b"),
                 _P(r"(on hold|pending|stopped|blocked|rejected|withheld|cancell?ed|will be (lapsed|cancell?ed))"),
                 _P(r"\b(update|verify|submit|share|send|confirm|re-?enter)\b[^.\n]{0,40}\b(bank|aadhaa?r|account|kyc|"
                    r"details|ifsc|pan)\b"))
SCAM_PATTERNS = [
    # (name, regexes that must ALL match, needs a link?, floor, description[, unless-regex])
    ("Parcel held - pay a fee", _PARCEL, False, 71,
     "A parcel 'on hold' that you must pay a small fee to release: the most common delivery scam (India Post, FedEx, DHL ...)."),
    ("Investment / crypto profit pitch", _INVEST, False, 71,
     "Promises trading or crypto profits and pushes you to a private chat (Telegram / WhatsApp / DM): investment fraud."),
    ("Paid task scam", _TASK, False, 71,
     "Pays you to like / rate / review things but asks for a joining fee first: the 'task' scam."),
    ("Fake account-violation appeal", _APPEAL, True, 71,
     "Says your account will be deleted / was flagged and sends you to an outside link to 'appeal' or 'verify': credential phishing."),
    ("Billing update request", _BILLING, True, 71,
     "Payment 'failed' and you must update card / billing details through a link: card-detail phishing."),
    ("Emergency money request", _EMERG, False, 71,
     "Someone you know is 'stuck' / in trouble and needs money sent right now: the emergency scam (verify by calling them on "
     "their usual number)."),
    ("Secret payment request from an executive", _BEC, False, 75,
     "A senior person asks for a payment and to keep it secret: CEO fraud / business e-mail compromise."),
    ("Gift card / favour request from a teacher or principal", _ACAD_FAVOUR, False, 71,
     "A principal / HOD / professor 'in a meeting' asks for gift cards or a favour on a new number: a real college would "
     "never do this. Call the person on the number you already know."),
    ("Fee for an offer letter, scholarship or admit card", _ACAD_FEE, False, 71,
     "Asks for a deposit or fee to release an internship / offer letter, scholarship, admit card or certificate: colleges "
     "and real companies collect fees only through their official portal, never to release a letter."),
    ("Asks for your OTP", _OTP_REQ, False, 75,
     "Asks you to send the one-time code you just received: whoever has that code can log in or pay as you. No teacher, "
     "bank or company ever needs it.", _OTP_SAFE),
    ("Scholarship on hold - update bank details", _SCHOLAR_HOLD, False, 71,
     "Says your scholarship is on hold and asks for bank / Aadhaar details: real scholarships (NSP) are updated only on "
     "scholarships.gov.in, never through a message."),
]


# which patterns belong to which detector (a pattern raising an unrelated detector would mislabel the threat --
# e.g. CEO fraud must stay "Business Email Compromise", not become "Brand impersonation")
PATTERNS_FOR = {
    "brand": ("Parcel held - pay a fee", "Fake account-violation appeal", "Billing update request", "Paid task scam"),
    "financial": ("Investment / crypto profit pitch", "Billing update request"),
    "management": ("Secret payment request from an executive",),
    "teacher": ("Paid task scam", "Gift card / favour request from a teacher or principal",
                "Fee for an offer letter, scholarship or admit card", "Asks for your OTP",
                "Scholarship on hold - update bank details"),
    "contact": ("Emergency money request",),
    "government": (),
}


def scam_patterns(text: str, topic: str | None = None) -> tuple[list[dict], int]:
    """-> (indicators of the scam patterns that match, minimum score they justify). topic limits the patterns to the
    ones that belong to that impersonation detector (None = all, for the SMS / social / message checks)."""
    low = (text or "").lower()
    if not low.strip():
        return [], 0
    has_link = bool(LINK_RE.search(text) or bare_domains(text))
    # all parts of a pattern must appear CLOSE TOGETHER (one ~300-character window), so a long newsletter that
    # mentions "director" in one paragraph and "funds" in another never matches
    windows = [low[i:i + 300] for i in range(0, max(len(low) - 150, 1), 150)] or [low]
    inds, floor = [], 0
    allowed = PATTERNS_FOR.get(topic) if topic else None
    for name, rxs, needs_link, fl, desc, *unless in SCAM_PATTERNS:
        if allowed is not None and name not in allowed:
            continue
        hits = None
        for w in windows:
            found = [rx.search(w) for rx in rxs]
            # unless: a match only counts when it is not part of a warning ("do not share the OTP")
            if all(found) and unless:
                found[-1] = next((m for m in rxs[-1].finditer(w)
                                  if not unless[0].search(w[max(0, m.start() - 30):m.end()])), None)
            if all(found):
                hits = found
                break
        if hits and (has_link or not needs_link):
            ev = "; ".join(f'"{h.group(0).strip()[:30]}"' for h in hits)
            inds.append({"label": f"Scam pattern: {name}", "description": f"{desc} Evidence: {ev}.", "severity": "critical",
                         "weight": 0, "triggered": True})
            floor = max(floor, fl)
    return inds, floor
GENERIC_GREETING_RE = re.compile(r"^\s*(dear (customer|user|member|sir/madam)|hello,)", re.I)
MISSPELLINGS = ["verifiy", "recieve", "acount", "securty", "confimation", "immediatly", "informations", "kindly", "beneficery"]


def _rule_indicators(text: str, sender: str | None, reply_to: str | None = None) -> list[dict]:
    lower = text.lower()
    indicators = []

    def add(triggered, label, desc, severity, weight):
        indicators.append({"label": label, "description": desc, "severity": severity, "weight": weight, "triggered": bool(triggered)})

    urgency_hit = any(w in lower for w in URGENCY_WORDS)
    add(urgency_hit, "Urgency language detected",
        "Message pressures the recipient to act immediately ('act now', 'account will be suspended').",
        "high", 18)

    cred_hit = any(w in lower for w in CREDENTIAL_WORDS) and not otp_notice(text)
    add(cred_hit, "Credential request",
        "Content asks the recipient for a password, OTP, PIN, or similar sensitive credential.",
        "critical", 25)

    links = LINK_RE.findall(text) + risky_bare_domains(text)
    add(len(links) > 0, "Suspicious embedded link",
        f"Message contains {len(links)} embedded link(s); verify destination before clicking.",
        "high", 20 if links else 0)

    money_hit = any(w in lower for w in MONEY_WORDS)
    add(money_hit, "Financial lure / prize claim",
        "References unexpected money, gift cards, cryptocurrency, or prize claims — a classic scam lure.",
        "critical", 22)

    generic_greeting = bool(GENERIC_GREETING_RE.search(text))
    add(generic_greeting, "Generic greeting",
        "Message lacks personalization typical of legitimate correspondence.", "low", 5)

    sender_lower = (sender or "").lower()
    domain_mismatch = bool(sender) and any(
        brand in text.lower() and brand not in sender_lower for brand in KNOWN_BRANDS
    )
    add(domain_mismatch, "Sender domain mismatch",
        "The claimed brand in the message body does not match the sender's domain.",
        "high", 20)

    misspelling_markers = sum(lower.count(m) for m in MISSPELLINGS)
    add(misspelling_markers > 0, "Spelling anomalies",
        "Contains spelling inconsistencies typical of templated scam content.", "low", 6)

    # Reply-To pointing somewhere different from the From address is a
    # classic BEC/phishing tell — legitimate mail rarely does this.
    reply_to_mismatch = False
    if reply_to and sender:
        reply_domain = reply_to.split("@")[-1].lower()
        sender_domain = sender.split("@")[-1].lower()
        reply_to_mismatch = bool(reply_domain) and bool(sender_domain) and reply_domain != sender_domain
    add(reply_to_mismatch, "Reply-To domain mismatch",
        f"Replies are routed to a different domain ({reply_to}) than the sender ({sender}) — common in spoofed mail.",
        "critical", 22)

    return indicators


def _link_destination_indicator(text: str, subtopic_id: str | None) -> dict | None:
    """
    Real integration: run the actual malicious-URL detector against links
    found in the email body, and fold the worst result into this scan.
    Checks at most 3 links to keep scan time bounded.
    """
    links = (LINK_RE.findall(text) + bare_domains(text))[:3]
    if not links:
        return None
    from app.detectors import malicious_url  # local import avoids a module-load cycle
    worst_score, worst_url = 0, None
    for link in links:
        try:
            result = malicious_url.analyze_url(link, "Embedded link check", subtopic_id=subtopic_id)
            if result["riskScore"] > worst_score:
                worst_score, worst_url = result["riskScore"], link
        except Exception:
            continue
    if worst_url is None:
        return None
    return {
        "label": "Malicious link destination", "severity": "critical" if worst_score >= 70 else "high",
        "description": f"An embedded link ({worst_url}) scored {worst_score}/100 for malicious characteristics when analyzed directly.",
        "weight": min(30, round(worst_score * 0.35)), "triggered": worst_score >= 40,
    }


# Signs that a social-media post asks for something a scammer wants (money, details, a click, a contact) - added 21 Oct.
# The social model learned from YouTube / SMS spam, where plain self-promotion ("new video, link in bio", "subscribe
# to our channel", "vote for our project") is labelled spam. Promotion is not a scam, so on the social-media page the
# model ALONE (no rule fired, none of these signs) can no longer push a post past 50.
# Measured (links scored without network): held-out real SMS scams caught 665 -> 644 of 800 (the ones held at 50 are
# mostly app / recharge adverts), real SMS wrongly flagged 11 -> 10 of 800; 20 normal social posts wrongly flagged
# 6 -> 2 (the 2 left contain "win a free" or a Medium link - anyone can publish there). "free" right before
# webinar / workshop / class / event is not a scam sign (a free event asks for nothing).
SOCIAL_SCAM_SIGNS = re.compile(
    r"https?://|www\.|\b[a-z0-9-]+\.(?:com|net|org|in|ly|xyz|top|info|co|me|link|site|online|club|biz)\b|\d{5,}|₹|"
    r"\brs\.?\s?\d|\$|£|€|\bmoney|\bcash|\bpay|\bpaid|\bsend\b|\bupi\b|\bbank|\baccount|\bverif|\bpassword|\botp\b|"
    r"\bpin\b|\bkyc|\blogin|\bclaim|\bprize|\bwin\b|\bwon\b|\bwinner|\breward|\bgift|\blottery|\bcash ?back|"
    r"\bfree\b(?!\s+(?:online\s+)?(?:webinar|workshop|seminar|session|class|classes|course|masterclass|event|entry|"
    r"demo|trial|talk|meetup|bootcamp)s?\b)|"
    r"\burgent|\bsuspend|\bblock|\bexpire|\bcall\b|\btxt\b|\btext\b|\bwhatsapp|\btelegram|\bdm me|\bcontact|\binvest|"
    r"\bcrypto|\bbitcoin|\bearn|\bincome|\bjob\b|\bloan|\bcredit|\bdebit|\bcard\b|\boffer|\bdeal\b|\bdiscount|\bcode\b|"
    r"\bstop\b|\bunsubscri|\bdetails\b|\bclick|\bconfirm|\bdeliver|\bparcel|\bpackage|\bshipment|\block|\baccess\b|"
    r"\bidentity|\bdisabl|\blog ?in|\bsign ?in|\bsupport|\bsettle|\bpoints\b|\bredeem|\bpenalt|\bfine\b|\btax|\brefund|"
    r"\bsecurity|\bupdate your|\bsingles|\bdating|\brebate|\breclaim", re.I)


def analyze_text(text: str, sender: str | None = None, subtopic_title: str = "Phishing Detection",
                  subtopic_id: str | None = None, reply_to: str | None = None,
                  scan_links: bool = True) -> dict:
    text = (text or "").strip()
    rule_indicators = _rule_indicators(text, sender, reply_to)

    # scan_links=False: the caller (e.g. the email pipeline) scores links itself
    link_indicator = _link_destination_indicator(text, subtopic_id) if text and scan_links else None
    if link_indicator:
        rule_indicators.append(link_indicator)
    pattern_inds, pattern_floor = scam_patterns(text) if text else ([], 0)
    rule_indicators.extend(pattern_inds)

    rule_score = sum(i["weight"] for i in rule_indicators if i["triggered"])

    model = _get_model(subtopic_id)
    model_used = model is not None and bool(text)
    proba = None
    if model_used:
        try:
            proba = float(model.predict_proba([text])[0][1])  # P(phishing/spam)
            model_score = proba * 100
            # Blend: model carries more weight when the text is long enough
            # to be meaningfully vectorized; rules always contribute explainability.
            blended = 0.6 * model_score + 0.4 * min(rule_score, 100)
            confidence = 65 + abs(proba - 0.5) * 60  # more confident away from 0.5
        except Exception:
            # A corrupt, incompatible, or otherwise broken model file must
            # never crash a scan — fall back to rule-based-only scoring,
            # same as if no model were configured at all.
            model_used = False
            blended = min(rule_score, 100)
            confidence = 40 + min(rule_score, 50)
    else:
        blended = min(rule_score, 100)
        confidence = 40 + min(rule_score, 50)  # lower confidence without ML backing

    triggered = [i for i in rule_indicators if i["triggered"]]
    if not text:
        explanation = "No content was submitted to analyze."
        blended = 0
        confidence = 0
    elif not triggered and not model_used:
        explanation = "No rule-based phishing indicators were detected in the submitted text, and no trained model was available to provide a second opinion."
    elif not triggered:
        explanation = f"The trained classifier assessed this content as {'likely phishing/scam' if model.predict([text])[0] == 1 else 'likely legitimate'} (model confidence {confidence:.0f}%). No rule-based indicators were additionally triggered."
    else:
        top = sorted(triggered, key=lambda i: -i["weight"])[:3]
        names = ", ".join(i["label"].lower() for i in top)
        model_note = f" A trained classifier corroborated this with a phishing probability of {proba*100:.0f}%." if model_used else " (Trained model unavailable — indicators are rule-based only.)"
        explanation = f"Detected {len(triggered)} indicator(s), most notably: {names}.{model_note}"

    # links that were checked and found NOT risky do not count as a scam sign; the bare "contains a link" note neither
    only_safe_links = all(i["label"] == "Suspicious embedded link" for i in triggered)
    if (subtopic_id == "social-media-analysis" and model_used and only_safe_links and blended > 50
            and not SOCIAL_SCAM_SIGNS.search(LINK_RE.sub(" ", text))):
        blended = 50
        explanation += (" The post reads like promotion, but it asks for nothing a scammer wants (no risky link, money, "
                        "details or contact request), so the score is held at 50.")
    if pattern_floor and text:
        blended = max(blended, pattern_floor)
        confidence = max(confidence, 80)
    elif text and otp_notice(text):
        blended = min(blended, 20)           # a genuine code delivery ("... is 482913. Do not share it")
    for ind in rule_indicators:
        ind["id"] = f"IND_{uuid.uuid4().hex[:12]}"

    return build_result(
        indicators=rule_indicators,
        base_score=blended,
        confidence=confidence,
        engine_name=f"CYBERGUARD Phishing Engine — {'TF-IDF+LogReg' if model_used else 'Rule-Based (model unavailable)'}",
        threat_type=subtopic_title,
        explanation=explanation,
    )