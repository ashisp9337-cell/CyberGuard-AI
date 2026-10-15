"""
Subtopic classifier + router (the "auto-detect" middle layer).

    input --classify()--> subtopic --route()--> analysis_service.run_scan(...)  (unchanged)

The classifier ONLY decides which existing subtopic an input belongs to. It
never decides whether the input is malicious and never scores it: identifying
a message as an email does not make it phishing, and identifying an image does
not make it a deepfake. The detector that run_scan already uses for that
subtopic does all of the analysis, and its result is returned unchanged.

How each input is classified (most reliable signal first):
  1. File type from magic bytes + extension (images, video, audio, e-mail files).
  2. Structure of the text: RFC-822 e-mail headers, a single URL, log formats
     (syslog, HTTP access log, firewall/flow records, process telemetry, audit
     records), authentication/session events via account_takeover.parse_log.
  3. Supplied metadata (extraFieldValues: platform, source, sender, ...).
  4. For impersonation: the identity the message CLAIMS (sender fields,
     signature, "this is ..." / "Dear <org> customer"), resolved against the
     existing organisation directory, title patterns and the user's saved
     contacts -- not loose keyword hits anywhere in the text.
No ML model is trained or used here: the only trainable data available is the
templated per-category threat data, which would not generalise to "which
category is this", and parsing is more reliable for file and log types.

If the subtopic cannot be determined reliably, nothing is guessed and no
detector is called (RoutingError "undetermined"), except where the repository
already has a general fallback detector (impersonation.analyze_identity, and
the general URL analysis that every url-security subtopic uses).
If the subtopic is known but no detector exists for it, RoutingError
"unavailable" is raised instead of calling an unrelated detector.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from urllib.parse import unquote

# Subtopic ids + titles exactly as in the frontend (src/data/modules.ts).
TITLES = {
    "phishing": {
        "email-analysis": "Email Analysis", "sms-analysis": "SMS / Message Analysis",
        "social-media-analysis": "Social Media Message Analysis", "qr-phishing": "QR Code Phishing Detection",
        "fraudulent-website": "Fraudulent Website Detection", "malicious-url": "Malicious URL Analysis",
    },
    "deepfake": {
        "image-analysis": "Image Analysis", "video-analysis": "Video Analysis",
        "audio-analysis": "Voice & Audio Analysis", "video-call": "Video Call Analysis",
        "ai-multimedia": "AI-Generated Multimedia Detection",
    },
    "impersonation": {
        "government-impersonation": "Government Official Impersonation",
        "management-impersonation": "Senior Management Impersonation",
        "teacher-impersonation": "Teacher / University Authority Impersonation",
        "financial-impersonation": "Financial Institution Impersonation",
        "brand-impersonation": "Organization / Brand Impersonation",
        "contact-impersonation": "Friend / Relative / Known Contact Impersonation",
        "generic": "Digital Impersonation (category undetermined)",
    },
    "credential": {
        "failed-logins": "Multiple Failed Login Attempts", "password-spraying": "Password Spraying Detection",
        "unusual-location": "Unusual Location Login", "unknown-device": "Unknown Device Detection",
        "session-activity": "Suspicious Session Activity", "behavior-changes": "Sudden Account Behavior Changes",
    },
    "url-security": {
        "domain-spoofing": "Domain Spoofing Detection", "lookalike-domain": "Look-Alike Domain Detection",
        "url-manipulation": "URL Manipulation Detection", "redirect-analysis": "Redirect Analysis",
        "ssl-domain-analysis": "SSL & Domain Analysis", "fake-login-page": "Fake Login Page Detection",
        "general": "Malicious URL & Website Analysis (general)",
    },
    "cyber-threat": {
        "malware-detection": "Malware Detection", "network-traffic": "Suspicious Network Traffic Detection",
        "api-abuse": "API Abuse Detection", "data-exfiltration": "Data Exfiltration Detection",
        "abnormal-activity": "Abnormal User Activity Detection", "insider-threat": "Insider Threat Detection",
        "log-analysis": "System & Application Log Analysis",
    },
}

# The existing detector entry point run_scan uses for each subtopic, and whether it exists.
# (status: "ok" | "unavailable"; note explains shared/limited detectors honestly.)
DETECTORS = {
    ("phishing", "email-analysis"): ("email_pipeline.analyze_email", "ok", ""),
    ("phishing", "sms-analysis"): ("phishing.analyze_text (phishing_sms.joblib)", "ok", ""),
    ("phishing", "social-media-analysis"): ("phishing.analyze_text (phishing_social.joblib)", "ok", ""),
    ("phishing", "qr-phishing"): ("qr_analyzer.analyze_qr", "ok", ""),
    ("phishing", "fraudulent-website"): ("malicious_url.analyze_url", "ok", ""),
    ("phishing", "malicious-url"): ("malicious_url.analyze_url", "ok", ""),
    ("deepfake", "image-analysis"): ("deepfake.analyze_media", "ok", "metadata-only; no trained model"),
    ("deepfake", "video-analysis"): ("deepfake.analyze_media", "ok", "returns 'model unavailable' (no trained video model)"),
    ("deepfake", "video-call"): ("deepfake.analyze_media (video path)", "ok",
                                 "no dedicated video-call detector; the existing video path is used"),
    ("deepfake", "ai-multimedia"): ("deepfake.analyze_media (modality path)", "ok",
                                    "no dedicated AI-generation detector; the modality detector is used"),
    ("deepfake", "audio-analysis"): ("-", "unavailable", "no audio/voice detector exists in the repository"),
    **{("impersonation", s): (fn, "ok", "") for s, fn in {
        "government-impersonation": "government_impersonation.analyze_government_impersonation",
        "management-impersonation": "senior_management_impersonation.analyze_senior_management_impersonation",
        "teacher-impersonation": "teacher_university_impersonation.analyze_teacher_university_impersonation",
        "financial-impersonation": "financial_impersonation.analyze_financial_impersonation",
        "brand-impersonation": "brand_impersonation.analyze_brand_impersonation",
        "contact-impersonation": "known_contact_impersonation.analyze_known_contact_message",
        "generic": "impersonation.analyze_identity (existing generic fallback)"}.items()},
    **{("credential", s): ("account_takeover.analyze_event", "ok", f"own trained model for this subtopic: cred_{s}.joblib")
       for s in TITLES["credential"]},
    **{("url-security", s): ("malicious_url.analyze_url", "ok", "one shared detector for all URL subtopics")
       for s in TITLES["url-security"]},
    **{("cyber-threat", s): ("cyber_threat.analyze_event_text", "ok", "one shared rule engine for all subtopics")
       for s in TITLES["cyber-threat"]},
}


class RoutingError(Exception):
    """Raised instead of calling a detector. code: 'undetermined' | 'unavailable' | 'unsupported'."""

    def __init__(self, code: str, message: str, details: dict | None = None):
        super().__init__(message)
        self.code, self.message, self.details = code, message, details or {}


@dataclass
class Classification:
    module_id: str
    subtopic_id: str
    method: str                       # how it was decided (file-type, email-headers, log-format, ...)
    reasons: list[str] = field(default_factory=list)
    secondary: list[str] = field(default_factory=list)   # other subtopics the input also fits
    status: str = "routed"            # routed | fallback

    @property
    def subtopic_title(self) -> str:
        return TITLES[self.module_id][self.subtopic_id]

    def to_dict(self) -> dict:
        entry, det_status, note = DETECTORS[(self.module_id, self.subtopic_id)]
        return {"mode": "auto", "moduleId": self.module_id, "subtopicId": self.subtopic_id,
                "subtopicTitle": self.subtopic_title, "method": self.method, "reasons": self.reasons,
                "secondary": self.secondary, "status": self.status, "detector": entry, "detectorNote": note}


# ---------------------------------------------------------------------------
# File-type detection (magic bytes first, extension second)
# ---------------------------------------------------------------------------
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
VIDEO_EXT = {".mp4", ".mov", ".avi", ".mkv", ".webm", ".m4v"}
AUDIO_EXT = {".mp3", ".wav", ".ogg", ".flac", ".m4a", ".aac", ".opus"}
EMAIL_EXT = {".eml", ".msg"}
TEXT_EXT = {".txt", ".log", ".csv", ".json"}


def file_kind(file_path: str | None, file_name: str | None) -> str | None:
    """'image' | 'video' | 'audio' | 'email' | 'text' | 'pdf' | 'executable' | 'archive' | 'unknown' | None."""
    if not file_path and not file_name:
        return None
    head = b""
    if file_path and os.path.exists(file_path):
        with open(file_path, "rb") as f:
            head = f.read(64)
    ext = os.path.splitext(file_name or file_path or "")[1].lower()
    if head.startswith(b"\x89PNG") or head.startswith(b"\xff\xd8\xff") or head[:6] in (b"GIF87a", b"GIF89a") \
            or (head[:4] == b"RIFF" and head[8:12] == b"WEBP") or head.startswith(b"BM"):
        return "image"
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return "audio"
    if head[:4] == b"RIFF" and head[8:12] == b"AVI ":
        return "video"
    if head[4:8] == b"ftyp":
        return "audio" if head[8:11] in (b"M4A", b"M4B") else "video"
    if head.startswith(b"\x1aE\xdf\xa3"):                       # Matroska / WebM
        return "video"
    if head.startswith(b"ID3") or head[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2") \
            or head.startswith(b"OggS") or head.startswith(b"fLaC"):
        return "audio"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"MZ") or head.startswith(b"\x7fELF"):
        return "executable"
    if head.startswith(b"PK\x03\x04"):
        return "archive"
    if head.startswith(b"\xd0\xcf\x11\xe0"):                    # OLE: Outlook .msg / old Office
        return "email" if ext == ".msg" else "archive"
    for kind, exts in (("image", IMAGE_EXT), ("video", VIDEO_EXT), ("audio", AUDIO_EXT),
                       ("email", EMAIL_EXT), ("text", TEXT_EXT)):
        if ext in exts and not head:
            return kind
    if ext in EMAIL_EXT:
        return "email"
    if head and all(b in b"\t\r\n" or 32 <= b < 127 or b >= 128 for b in head):
        return "text"
    return "unknown"


def _read_text(file_path: str | None, limit: int = 200_000) -> str:
    if not file_path or not os.path.exists(file_path):
        return ""
    with open(file_path, "rb") as f:
        return f.read(limit).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Text structure helpers
# ---------------------------------------------------------------------------
HEADER_RE = re.compile(r"^(from|to|subject|date|received|message-id|reply-to|return-path|cc|"
                       r"mime-version|content-type|authentication-results|delivered-to)\s*:", re.I)
SINGLE_URL_RE = re.compile(r"^(?:https?://|www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?(?:[/?#]\S*)?$", re.I)
URL_IN_TEXT_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')]+", re.I)


def is_email_text(text: str) -> bool:
    """True when the text starts with an RFC-822 header block (From: plus at least one other header)."""
    lines = [ln for ln in text.strip().splitlines()[:40]]
    names = set()
    for ln in lines:
        if not ln.strip():
            break                                   # end of the header block
        m = HEADER_RE.match(ln)
        if m:
            names.add(m.group(1).lower())
        elif not ln[:1].isspace():                  # a non-header, non-continuation line: not a header block
            break
    return "from" in names and len(names) >= 2


def single_url(text: str | None) -> str | None:
    t = (text or "").strip()
    if t and "\n" not in t and " " not in t and SINGLE_URL_RE.match(t):
        return t
    return None


# ---------------------------------------------------------------------------
# Module 1: phishing
# ---------------------------------------------------------------------------
SOCIAL_HOSTS = ("instagram.com", "facebook.com", "fb.com", "fb.me", "m.me", "twitter.com", "x.com", "t.co",
                "linkedin.com", "lnkd.in", "tiktok.com", "snapchat.com", "youtube.com", "youtu.be",
                "t.me", "discord.gg", "discord.com", "reddit.com", "threads.net", "pinterest.com")
SOCIAL_PLATFORMS = ("instagram", "facebook", "messenger", "twitter", "linkedin", "tiktok", "snapchat",
                    "youtube", "telegram", "discord", "reddit", "threads", "pinterest")
SMS_PLATFORMS = ("sms", "text", "imessage", "rcs", "whatsapp", "signal")


def _classify_phishing(text, url_input, kind, file_text, extra) -> Classification:
    m = "phishing"
    if kind == "image":
        return Classification(m, "qr-phishing", "file-type", ["Image file: the QR-code phishing detector is the "
                                                              "phishing detector that accepts images"])
    if kind == "email":
        return Classification(m, "email-analysis", "file-type", [".eml/.msg e-mail file"])
    if kind in ("pdf", "executable", "archive", "audio", "video", "unknown"):
        raise RoutingError("unsupported", f"A {kind} file cannot be analysed by any phishing detector. "
                           "Upload an e-mail (.eml), a QR image, or paste the message / URL.")
    body = text or file_text or ""
    if kind == "text" and file_text and is_email_text(file_text):
        return Classification(m, "email-analysis", "email-headers", ["Uploaded text file has an e-mail header block"])

    url = (url_input or "").strip() or single_url(body)
    if url:
        parts = _split(url)
        if parts["path"] in ("", "/") and not parts["query"]:
            return Classification(m, "fraudulent-website", "url-structure",
                                  ["Input is a website address (domain / home page only)"])
        return Classification(m, "malicious-url", "url-structure", ["Input is a single URL with a path or query"])

    if not body.strip():
        raise RoutingError("undetermined", "Nothing to analyse: paste the message, e-mail or URL, or upload a file.")
    if is_email_text(body):
        return Classification(m, "email-analysis", "email-headers", ["Text starts with an e-mail header block (From:, Subject:, ...)"])

    platform = str(extra.get("platform") or extra.get("source") or "").strip().lower()
    if platform in SOCIAL_PLATFORMS:
        return Classification(m, "social-media-analysis", "metadata", [f"Source platform given: {platform}"])
    if platform in SMS_PLATFORMS:
        return Classification(m, "sms-analysis", "metadata", [f"Source platform given: {platform}"])

    # Social-media evidence must be structural: a platform link/handle AND a platform reference.
    hosts = [h for h in (_split(u)["host"] for u in URL_IN_TEXT_RE.findall(body)) if h]
    social_link = any(h == s or h.endswith("." + s) for h in hosts for s in SOCIAL_HOSTS)
    handle = bool(re.search(r"(?<![\w.])@[A-Za-z0-9_.]{3,30}\b(?!\.[a-z]{2,})", body))
    named = any(re.search(rf"\b{p}\b", body, re.I) for p in SOCIAL_PLATFORMS)
    social_terms = bool(re.search(r"\b(DM|direct message|followers?|your (post|page|reel|story|profile)|"
                                  r"verified badge|blue tick|copyright (strike|violation))\b", body, re.I))
    evidence = sum([social_link, handle, named, social_terms])
    if social_link or (named and evidence >= 2):
        reasons = [r for r, ok in (("social-platform link", social_link), ("@handle", handle),
                                   ("platform named", named), ("social-platform terms", social_terms)) if ok]
        return Classification(m, "social-media-analysis", "message-structure", reasons)
    # The SMS/message detector is the general detector for short messages (as specified).
    return Classification(m, "sms-analysis", "message-structure",
                          ["Short message without e-mail headers or social-platform evidence -> general message detector"])


def _split(url: str) -> dict:
    from app.detectors.url_features_v2 import split_url
    return split_url(url)


# ---------------------------------------------------------------------------
# Module 2: deepfake
# ---------------------------------------------------------------------------
CALL_NAME_RE = re.compile(r"(zoom|gmt\d{8}|meet|teams|webex|skype|video[\s_-]?call|call[\s_-]?recording)", re.I)


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "y")


def _classify_deepfake(kind, file_name, extra) -> Classification:
    m = "deepfake"
    if kind is None:
        raise RoutingError("undetermined", "Deepfake analysis needs a media file: upload an image, video or audio clip.")
    declared_ai = _truthy(extra.get("aiGenerated")) or _truthy(extra.get("suspectedAiGenerated"))
    source = str(extra.get("source") or extra.get("captureType") or "").lower()
    if kind == "audio":
        raise RoutingError("unavailable", "Voice/audio deepfake detection is not implemented in this system, "
                           "so the clip was not analysed.", {"moduleId": m, "subtopicId": "audio-analysis"})
    if kind == "image":
        if declared_ai:
            return Classification(m, "ai-multimedia", "metadata", ["Image declared as possibly AI-generated"],
                                  secondary=["image-analysis"])
        return Classification(m, "image-analysis", "file-type", ["Image file"])
    if kind == "video":
        if source in ("video-call", "call-recording", "videocall") or CALL_NAME_RE.search(file_name or ""):
            return Classification(m, "video-call", "metadata",
                                  ["Video identified as a call recording from its metadata/file name"],
                                  secondary=["video-analysis"])
        if declared_ai:
            return Classification(m, "ai-multimedia", "metadata", ["Video declared as possibly AI-generated"],
                                  secondary=["video-analysis"])
        return Classification(m, "video-analysis", "file-type", ["Video file"])
    raise RoutingError("unsupported", f"A {kind} file is not a supported media type for deepfake analysis.")


# ---------------------------------------------------------------------------
# Module 3: impersonation
# ---------------------------------------------------------------------------
ENTITY_TO_SUBTOPIC = {"government": "government-impersonation", "bank": "financial-impersonation",
                      "brand": "brand-impersonation", "education": "teacher-impersonation"}
RELATION_RE = re.compile(
    r"\b(this is|it'?s|i am|i'm|your)\s+(own\s+)?(mom|mum|mother|dad|father|papa|mummy|bro|brother|sister|sis|"
    r"son|daughter|beta|uncle|aunt|aunty|auntie|cousin|bhai|didi|friend|buddy|wife|husband)\b", re.I)
NEW_NUMBER_RE = re.compile(r"\b(my (new|other) number|new number|changed my number|lost my phone|phone is broken)\b", re.I)
SELF_ID_RE = re.compile(r"\b(this is|i am|i'm|we are|on behalf of|from (the )?|team|dear [a-z ]{2,30} (customer|user|student|employee|member))", re.I)


def _claim_zones(text: str, extra: dict) -> list[tuple[str, float]]:
    """Places where a sender claims an identity, with weights. Body mentions count much less.
    A raw e-mail is parsed first (existing parser), so mail-server headers such as
    'Received: from mx.google.com' are never mistaken for an identity claim."""
    sender = " ".join(str(extra.get(k, "")) for k in ("claimedSenderName", "sender", "senderEmail", "senderName",
                                                     "claimedRole", "fromName") if extra.get(k))
    subject = ""
    if is_email_text(text):
        from app.email_pipeline.parser import parse_email
        ev = parse_email(text)
        sender = " ".join(filter(None, [sender, ev.from_display_name, ev.from_address]))
        subject, text = ev.subject, ev.body_text
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    signature = " ".join(lines[-3:]) if len(lines) > 1 else ""
    first = lines[0] if lines else ""
    self_ids = " ".join(text[max(0, m.start()):m.end() + 60] for m in SELF_ID_RE.finditer(text))
    return [(sender, 3.0), (subject, 2.0), (signature, 2.5), (self_ids, 2.5), (first, 1.5), (text, 0.5)]


def _classify_impersonation(text, extra, db, user_id) -> Classification:
    from app.email_pipeline import org_directory as orgs

    m = "impersonation"
    if not (text or "").strip():
        raise RoutingError("undetermined", "Paste the message that claims to come from someone.")
    scores: dict[str, float] = {}
    reasons: dict[str, set] = {}

    def vote(sub, w, why):
        scores[sub] = scores.get(sub, 0) + w
        reasons.setdefault(sub, set()).add(why)

    for zone, weight in _claim_zones(text, extra):
        if not zone:
            continue
        for e in orgs.find_entities(zone):
            sub = ENTITY_TO_SUBTOPIC.get(e["category"])
            if sub:
                vote(sub, weight, f"claims to be {e['name']}")
        if orgs.EXECUTIVE_TITLES.search(zone):
            vote("management-impersonation", weight, f"executive title ({orgs.EXECUTIVE_TITLES.search(zone).group(0)})")
        if orgs.ACADEMIC_TITLES.search(zone):
            vote("teacher-impersonation", weight, f"academic role ({orgs.ACADEMIC_TITLES.search(zone).group(0)})")
        if RELATION_RE.search(zone):
            vote("contact-impersonation", weight, f"personal relationship claim ({RELATION_RE.search(zone).group(0)})")

    # Sender domain of an official organisation (e.g. @incometax.gov.in) or a saved contact.
    if NEW_NUMBER_RE.search(text):
        vote("contact-impersonation", 2.0, "says it is writing from a new/changed number")
    claimed = str(extra.get("claimedSenderName") or "").strip()
    if claimed and db is not None and user_id:
        try:
            from app.detectors.known_contact_impersonation import _find_contact
            if _find_contact(db, user_id, claimed):
                vote("contact-impersonation", 4.0, f"'{claimed}' is one of your saved contacts")
        except Exception:
            pass

    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    if not ranked or ranked[0][1] < 2.0 or (len(ranked) > 1 and ranked[1][1] >= ranked[0][1] * 0.8):
        why = ("no claimed identity found" if not ranked else
               "competing identity claims: " + ", ".join(f"{s} ({v:.1f})" for s, v in ranked[:3]))
        return Classification(m, "generic", "claimed-identity", [why], secondary=[s for s, _ in ranked[:3]],
                              status="fallback")
    top = ranked[0][0]
    return Classification(m, top, "claimed-identity", sorted(reasons[top]),
                          secondary=[s for s, v in ranked[1:3] if v >= 2.0])


# ---------------------------------------------------------------------------
# Module 4: credential theft / account takeover
# ---------------------------------------------------------------------------
CREDENTIAL_FIELDS = ("failedAttempts", "impossibleTravel", "newDevice", "anonymizingNetwork", "passwordResetRecent",
                     "mfaChanged", "privilegeEscalation", "unusualHour", "unusualLocation", "recoveryChanged",
                     "forwardingRule", "newCredentialCreated", "massDownload", "successAfterFailures",
                     "passwordSpraying")


def _classify_credential(text, extra) -> Classification:
    from app.detectors import account_takeover

    m = "credential"
    sig = dict(account_takeover.parse_log(text or "")) if hasattr(account_takeover, "parse_log") else {}
    for k in CREDENTIAL_FIELDS:                      # explicit event fields win
        v = extra.get(k)
        if k == "failedAttempts":
            try:
                sig[k] = max(int(float(v or 0)), int(sig.get(k) or 0))
            except (TypeError, ValueError):
                pass
        elif _truthy(v):
            sig[k] = True
    if _truthy(extra.get("passwordSpraying")):
        sig["distinctFailedUsers"] = max(5, int(sig.get("distinctFailedUsers") or 0))

    matches = []
    if (sig.get("distinctFailedUsers") or 0) >= 5:
        matches.append(("password-spraying", "failures against many different accounts from one source"))
    if sig.get("impossibleTravel") or sig.get("unusualLocation"):
        matches.append(("unusual-location", "login from an unusual / impossible location"))
    if sig.get("newDevice"):
        matches.append(("unknown-device", "login from a new or unknown device"))
    changed = [k for k in ("mfaChanged", "passwordResetRecent", "recoveryChanged", "forwardingRule",
                           "newCredentialCreated") if sig.get(k)]
    if changed:
        matches.append(("behavior-changes", "account settings changed: " + ", ".join(changed)))
    if (sig.get("failedAttempts") or 0) > 0 or sig.get("successAfterFailures"):
        matches.append(("failed-logins", f"{sig.get('failedAttempts') or 0} failed login attempt(s)"))
    session = [k for k in ("massDownload", "privilegeEscalation", "anonymizingNetwork") if sig.get(k)]
    if session:
        matches.append(("session-activity", "in-session activity: " + ", ".join(session)))
    # Login history: the RBA risk model compares each login with the account's own earlier logins,
    # so a log of only SUCCESSFUL logins is still something to analyse (new country / device etc.).
    events = account_takeover.events_from_log(text) if text and hasattr(account_takeover, "events_from_log") else []
    if events:
        ml = account_takeover.model_assessment(text) if hasattr(account_takeover, "model_assessment") else None
        if ml and ml["level"] in ("high", "medium"):
            reasons = ml["reasons"] or []
            loc = next((r for r in reasons if r.startswith(("country", "network", "IP address"))), None)
            dev = next((r for r in reasons if r.startswith(("device type", "operating system", "browser"))), None)
            # a new country / network is the bigger alarm, so location wins when both changed
            sub, first = (("unusual-location", loc) if loc else ("unknown-device", dev) if dev else
                          ("unusual-location", reasons[0] if reasons else ""))
            if all(s != sub for s, _ in matches):
                matches.append((sub, "risk model: " + (first or "login unusual for this account")))
        elif not matches and not sig.get("unusualHour"):
            matches.append(("unusual-location", f"{len(events)} login(s) checked against the account's own history"))
    if not matches and sig.get("unusualHour"):
        matches.append(("session-activity", "activity at an unusual hour"))

    if not matches:
        raise RoutingError("undetermined", "No authentication or session events were found. Paste login/session "
                           "log lines (e.g. 'Failed password for root from 1.2.3.4') or provide the event fields.")
    primary, why = matches[0]
    return Classification(m, primary, "auth-event-parser", [why], secondary=[s for s, _ in matches[1:]])


# ---------------------------------------------------------------------------
# Module 5: malicious URL / website
# ---------------------------------------------------------------------------
LOGIN_WORDS = {"login", "logon", "signin", "signon", "auth", "authenticate", "verify", "verification", "account",
               "accounts", "password", "passwd", "credential", "credentials", "webmail", "owa", "session", "otp",
               "kyc", "sso", "oauth", "wp-login"}


def _login_path(path: str, query: str) -> bool:
    """True when a whole path/query word is a login word (not letters inside a random token like '3kYcQ9z')."""
    words = [w for w in re.split(r"[^a-z0-9]+", (path + " " + query).lower().replace("log-in", "login")
                                 .replace("sign-in", "signin")) if w]
    return any(w in LOGIN_WORDS or (w.endswith((".php", ".html", ".aspx")) and w.split(".")[0] in LOGIN_WORDS)
               for w in words)


def _classify_url(text, url_input) -> Classification:
    from app.detectors import url_features_v2 as uf

    m = "url-security"
    url = (url_input or "").strip() or single_url(text)
    if not url:
        raise RoutingError("undetermined", "Enter a single URL or website address to analyse.")
    p = uf.split_url(url)
    host, path, query = p["host"], p["path"], p["query"]
    if not host:
        raise RoutingError("unsupported", "That does not look like a valid URL.")
    tokens = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    brand = uf.brand_in_host(host)
    exact_brand = brand and any(t == brand or brand in t or uf.BRAND_ALIASES.get(t) == brand for t in tokens)
    found = []
    if "xn--" in host or (brand and not exact_brand):
        found.append(("lookalike-domain", f"host imitates the '{brand}' name with altered characters" if brand
                      else "punycode (internationalised) host, which can imitate another name"))
    if brand and exact_brand:
        found.append(("domain-spoofing", f"'{brand}' appears in a host that is not {brand}'s official domain"))
    manip = [w for w, ok in (("@ in address", p["has_at"]), ("raw IP host", uf._is_ip_host(host)),
                             ("non-standard port", p["has_port"]),
                             ("heavy encoding", url.count("%") >= 6 or unquote(url) != url and len(url) > 120),
                             ("very long URL", len(url) > 200)) if ok]
    if manip:
        found.append(("url-manipulation", "address tricks: " + ", ".join(manip)))
    if uf.is_shortener(host) or uf.has_redirect_param(query):
        found.append(("redirect-analysis", "shortener or redirect parameter pointing to another site"))
    from app.detectors import trusted_domains
    from app.detectors.domain_model import site_parts
    publish = (site_parts(host)["platform"] or host in trusted_domains.USER_CONTENT_HOSTS
               or uf.registered_domain(host) in trusted_domains.USER_CONTENT_DOMAINS)
    if _login_path(path, query) or (publish and not uf.is_shortener(host)):
        found.append(("fake-login-page", "path/query of a login or verification page" if _login_path(path, query)
                      else "page on a free platform where anyone can publish forms"))
    if url.lower().startswith("http://"):
        found.append(("ssl-domain-analysis", "plain HTTP (no TLS)"))

    # A sign-in page on a free hosting platform is the textbook fake login page, even when it also
    # spoofs a brand name: make that the main subtopic and keep the rest as secondary.
    if publish and _login_path(path, query):
        found.sort(key=lambda f: f[0] != "fake-login-page")
    if not found:
        return Classification(m, "general", "url-structure", ["no single structural category stands out; the "
                              "existing general URL analysis is used"], status="fallback")
    return Classification(m, found[0][0], "url-structure", [found[0][1]], secondary=[s for s, _ in found[1:]])


# ---------------------------------------------------------------------------
# Module 6: cyber threat (log / event formats)
# ---------------------------------------------------------------------------
CYBER_PATTERNS = [
    # (subtopic, regex, description) -- each regex recognises a LOG/EVENT FORMAT, not a threat.
    ("data-exfiltration", re.compile(
        r"(\b(bytes_out|bytes_sent|sent_bytes|out_bytes|upload(ed)?_bytes)\s*[=:]\s*\d+|"
        r"\b(uploaded|copied|transferred|exported|synced)\b[^\n]{0,40}\b\d+(\.\d+)?\s?(kb|mb|gb|tb)\b|"
        r"\b(scp|rsync|rclone|curl\s+(-T|--upload-file)|aws s3 cp|gsutil cp|azcopy)\b)", re.I),
        "data-transfer records"),
    ("malware-detection", re.compile(
        r"(\b(event ?id|eventcode)\s*[=:]?\s*(1|4688)\b[^\n]*(image|process|commandline)|"
        r"\b(commandline|parentimage|parent_process|process_name|image)\s*[=:]|"
        r"\b(sha256|sha1|md5|imphash)\s*[=:]\s*[a-f0-9]{32,64}\b|\b[a-f0-9]{64}\b)", re.I),
        "process / file telemetry"),
    ("api-abuse", re.compile(
        r"\"(GET|POST|PUT|PATCH|DELETE) (/api/|/v\d+/|/graphql|/rest/)[^\"]*\" \d{3}|"
        r"\b(api[_-]?key|x-api-key|client_id|access_token|bearer)\b[^\n]{0,40}(/api/|/v\d+/|endpoint)|"
        r"\b(endpoint|route)\s*[=:]\s*/(api|v\d+)/", re.I),
        "API access-log records"),
    ("network-traffic", re.compile(
        r"(\bSRC=\S+\s+DST=\S+|\b(src_?ip|dst_?ip|source_ip|dest_ip)\s*[=:]\s*\d|"
        r"\b(DPT|SPT|dst_?port|src_?port)\s*[=:]\s*\d+|\bPROTO=(TCP|UDP|ICMP)\b|"
        r"\b\d{1,3}(\.\d{1,3}){3}[.:]\d+\s*(->|>|→)\s*\d{1,3}(\.\d{1,3}){3}[.:]\d+|"
        r"\b(ACCEPT|DROP|DENY|REJECT|ALLOW|BLOCK)\b[^\n]*\b(TCP|UDP|ICMP)\b)", re.I),
        "network flow / firewall records"),
    ("insider-threat", re.compile(
        r"\b(usb|removable (media|storage|drive)|mass storage|print(ed)? job|printer|"
        r"forward(ed)? to (personal|external)|personal (e-?mail|gmail|drive)|"
        r"(hr|payroll|salary|confidential|restricted|source code) (share|folder|files?|database|repo))\b", re.I),
        "internal data-handling audit records"),
    ("abnormal-activity", re.compile(
        r"\b(user(name)?|account|uid)\s*[=:]\s*\S+[^\n]{0,80}\b(action|activity|event|operation|op)\s*[=:]\s*\S+", re.I),
        "per-user activity audit records"),
    ("log-analysis", re.compile(
        r"(^\s*<?\d{0,3}>?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+(\[\d+\])?:|"
        r"^\s*\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\n]{0,40}\b(DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRITICAL|FATAL)\b|"
        r"\"(GET|POST|HEAD|PUT|DELETE) \S+ HTTP/[\d.]+\" \d{3}|"
        r"\b(event ?id|eventcode)\s*[=:]?\s*\d{3,5}\b)", re.I | re.M),
        "system / application log lines"),
]


def _classify_cyber(text, kind, file_text) -> Classification:
    m = "cyber-threat"
    if kind in ("executable", "archive", "pdf", "image", "video", "audio", "email", "unknown"):
        raise RoutingError("unavailable", "File-based malware analysis is not implemented: the existing cyber-threat "
                           "detector analyses event/log text only. Paste the related log or event lines instead.",
                           {"moduleId": m, "subtopicId": "malware-detection"})
    body = text or file_text or ""
    if not body.strip():
        raise RoutingError("undetermined", "Paste the log lines or event records to analyse.")
    lines = [ln for ln in body.splitlines() if ln.strip()]
    hits = []
    for sub, rx, desc in CYBER_PATTERNS:
        n = sum(1 for ln in lines if rx.search(ln))
        if n:
            hits.append((sub, n, desc))
    if not hits:
        raise RoutingError("undetermined", "This does not look like a log or event record, so the type of activity "
                           "could not be determined. Paste the raw log/event lines (firewall, API access, process, "
                           "audit or system log), or open the specific detection type.")
    # Order of CYBER_PATTERNS is the priority; ties broken by it, not by guessing.
    sub, n, desc = hits[0]
    return Classification(m, sub, "log-format", [f"{n} line(s) of {desc}"], secondary=[h[0] for h in hits[1:]])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def classify(*, module_id: str, text_input: str | None, url_input: str | None, file_path: str | None,
             file_name: str | None, extra_field_values: dict | None, db=None, user_id: str | None = None
             ) -> Classification:
    extra = extra_field_values or {}
    kind = file_kind(file_path, file_name)
    file_text = _read_text(file_path) if kind in ("text", "email") else ""
    if module_id == "phishing":
        return _classify_phishing(text_input, url_input, kind, file_text, extra)
    if module_id == "deepfake":
        return _classify_deepfake(kind, file_name, extra)
    if module_id == "impersonation":
        return _classify_impersonation(text_input or file_text, extra, db, user_id)
    if module_id == "credential":
        return _classify_credential(text_input or file_text, extra)
    if module_id == "url-security":
        return _classify_url(text_input, url_input)
    if module_id == "cyber-threat":
        return _classify_cyber(text_input, kind, file_text)
    raise RoutingError("unsupported", f"Unknown module '{module_id}'.")


def route(*, module_id: str, text_input: str | None, url_input: str | None, file_path: str | None,
          file_name: str | None, extra_field_values: dict | None, db=None, user_id: str | None = None):
    """Classify, then call the EXISTING run_scan for that subtopic with the ORIGINAL inputs.
    Returns (result, classification). Raises RoutingError without calling any detector."""
    from app.services import analysis_service

    c = classify(module_id=module_id, text_input=text_input, url_input=url_input, file_path=file_path,
                 file_name=file_name, extra_field_values=extra_field_values, db=db, user_id=user_id)
    _, det_status, note = DETECTORS[(module_id, c.subtopic_id)]
    if det_status != "ok":
        raise RoutingError("unavailable", note, {"moduleId": module_id, "subtopicId": c.subtopic_id})
    # Subtopics that have no id of their own in run_scan use the id run_scan already handles.
    run_id = {"video-call": "video-analysis", "generic": "identity-generic", "general": "general"}.get(
        c.subtopic_id, c.subtopic_id)
    result = analysis_service.run_scan(
        module_id=module_id, subtopic_id=run_id, subtopic_title=c.subtopic_title,
        text_input=text_input, url_input=url_input, file_path=file_path, file_name=file_name,
        extra_field_values=extra_field_values, db=db, user_id=user_id,
    )
    return result, c
