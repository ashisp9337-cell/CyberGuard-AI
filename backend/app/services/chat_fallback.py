"""
Backup answers when the AI (Gemini) cannot answer - not configured, Google overloaded, quota used up, no internet.
Answers come straight from the user's own CyberGuard data and detectors, so the assistant keeps working in a demo:

  * a pasted link / message ("is this safe?")  -> the real CyberGuard scan (chat_scan)
  * "my scans" / "last scan"                   -> recent scans
  * "alerts" / "notifications"                 -> recent alerts
  * "summary" / "score" / "how am I doing"     -> security overview
  * "settings", "reports"                      -> those
  * anything else                              -> what it can still do
Never makes anything up: no data -> says so.
"""
from __future__ import annotations

import re

from app.services import chat_scan

_LINK_RE = re.compile(r"(?i)\bhttps?://\S+|\bwww\.\S+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|net|org|top|xyz|shop|"
                      r"click|link|info|online|site|cyou|live|app|io|co)\b(?:/\S*)?")
_CHECK_RE = re.compile(r"(?i)\b(is (this|it|that) (safe|real|legit|a scam|fake|genuine)|safe\??$|scam\??$|check (this|it)|"
                       r"verify (this|it)|phishing\??$)")
_INTENTS = [
    ("alerts", re.compile(r"(?i)\b(alerts?|notifications?|warnings?)\b")),
    ("overview", re.compile(r"(?i)\b(summary|overview|score|how am i|status|posture|threats? (count|so far))\b")),
    ("scans", re.compile(r"(?i)\b(scans?|history|last (check|result)|recent)\b")),
    ("settings", re.compile(r"(?i)\b(settings?|sensitivity|preferences?)\b")),
    ("reports", re.compile(r"(?i)\breports?\b")),
]
_LABEL = {"safe": "safe", "low_risk": "low risk", "suspicious": "suspicious", "high_risk": "HIGH RISK",
          "critical": "CRITICAL", "unverified": "no verdict"}


_QUESTION_RE = re.compile(r"(?i)\b(what|how|why|when|who|which|explain|tell me|can you (explain|tell)|define|"
                          r"teach|describe|difference|meaning of)\b")


def _looks_like_content_to_check(message: str) -> bool:
    """A pasted link / message to check - not a general question about security ("In one sentence, what is
    phishing?" is a question, not a message to scan - found by chat_check.py on 21 Oct)."""
    if _LINK_RE.search(message):
        return True
    if _QUESTION_RE.search(message[:60]):
        return False
    rest = _strip_question(message)
    if _CHECK_RE.search(message) and rest != message.strip() and len(rest) >= 25:
        return True                                   # "is this safe? <pasted message>"
    return len(message) > 80


def _strip_question(message: str) -> str:
    """'is this safe? <pasted text>' -> '<pasted text>' (the question itself is not part of the content)."""
    m = re.match(r"(?is)^\s*(is (this|it) (safe|real|legit|a scam|fake|genuine)|check (this|it)|verify (this|it)|"
                 r"can you check( this)?)\s*[?:.!-]*\s*", message)
    rest = message[m.end():] if m else message
    return rest.strip() or message.strip()


# The fixed sentences of the backup answers in the user's chosen reply language (data such as scan names stays as is).
TEXT = {
    "en": {"busy": "The AI assistant is busy or unreachable right now.",
           "not_configured": "The AI assistant isn't set up on this server (GEMINI_API_KEY is empty).",
           "head": "So this answer comes straight from CyberGuard's own data and detectors.",
           "checked_as": "Checked as", "reasons": "Main reasons", "todo": "What to do",
           "no_scans": "You have no scans yet.", "scans": "Your most recent scans",
           "no_alerts": "You have no alerts.", "alerts": "Your latest alerts", "unread": "unread",
           "score": "Security score", "total": "Scans", "flagged": "flagged",
           "no_reports": "You have no generated reports yet.", "reports": "Your reports",
           "settings": "Alert sensitivity: {s}. Notifications: {n}; e-mail notifications: {e}.",
           "on": "on", "off": "off",
           "help": "I can still:\n• check a link, SMS, message or e-mail - just paste it here\n• show your recent scans, "
                   "alerts or security summary\n• show your settings or reports\nGeneral questions need the AI - "
                   "please try again in a minute."},
    "hi": {"busy": "AI सहायक अभी व्यस्त है या उपलब्ध नहीं है।",
           "not_configured": "इस सर्वर पर AI सहायक सेट नहीं है (GEMINI_API_KEY खाली है)।",
           "head": "इसलिए यह जवाब सीधे CyberGuard के अपने डेटा और डिटेक्टरों से है।",
           "checked_as": "जाँच का प्रकार", "reasons": "मुख्य कारण", "todo": "क्या करें",
           "no_scans": "आपका अभी कोई स्कैन नहीं है।", "scans": "आपके हाल के स्कैन",
           "no_alerts": "आपका कोई अलर्ट नहीं है।", "alerts": "आपके नए अलर्ट", "unread": "अपठित",
           "score": "सुरक्षा स्कोर", "total": "स्कैन", "flagged": "संदिग्ध",
           "no_reports": "आपकी अभी कोई रिपोर्ट नहीं है।", "reports": "आपकी रिपोर्ट",
           "settings": "अलर्ट संवेदनशीलता: {s}। सूचनाएँ: {n}; ई-मेल सूचनाएँ: {e}।", "on": "चालू", "off": "बंद",
           "help": "मैं अभी भी कर सकता हूँ:\n• कोई लिंक, SMS, संदेश या ई-मेल जाँचना - बस यहाँ पेस्ट करें\n• आपके हाल के "
                   "स्कैन, अलर्ट या सुरक्षा सारांश दिखाना\n• आपकी सेटिंग्स या रिपोर्ट दिखाना\nसामान्य सवालों के लिए AI "
                   "चाहिए - कृपया एक मिनट बाद फिर कोशिश करें।"},
    "or": {"busy": "AI ସହାୟକ ବର୍ତ୍ତମାନ ବ୍ୟସ୍ତ ଅଛି କିମ୍ବା ଉପଲବ୍ଧ ନାହିଁ।",
           "not_configured": "ଏହି ସର୍ଭରରେ AI ସହାୟକ ସେଟ୍ ହୋଇନାହିଁ (GEMINI_API_KEY ଖାଲି ଅଛି)।",
           "head": "ତେଣୁ ଏହି ଉତ୍ତର ସିଧାସଳଖ CyberGuard ର ନିଜସ୍ୱ ଡାଟା ଓ ଡିଟେକ୍ଟରରୁ ଆସିଛି।",
           "checked_as": "ଯାଞ୍ଚର ପ୍ରକାର", "reasons": "ମୁଖ୍ୟ କାରଣ", "todo": "କଣ କରିବେ",
           "no_scans": "ଆପଣଙ୍କର ଏପର୍ଯ୍ୟନ୍ତ କୌଣସି ସ୍କାନ୍ ନାହିଁ।", "scans": "ଆପଣଙ୍କର ସାମ୍ପ୍ରତିକ ସ୍କାନ୍",
           "no_alerts": "ଆପଣଙ୍କର କୌଣସି ଆଲର୍ଟ ନାହିଁ।", "alerts": "ଆପଣଙ୍କର ନୂଆ ଆଲର୍ଟ", "unread": "ପଢ଼ାଯାଇନାହିଁ",
           "score": "ସୁରକ୍ଷା ସ୍କୋର", "total": "ସ୍କାନ୍", "flagged": "ସନ୍ଦେହଜନକ",
           "no_reports": "ଆପଣଙ୍କର ଏପର୍ଯ୍ୟନ୍ତ କୌଣସି ରିପୋର୍ଟ ନାହିଁ।", "reports": "ଆପଣଙ୍କ ରିପୋର୍ଟ",
           "settings": "ଆଲର୍ଟ ସମ୍ବେଦନଶୀଳତା: {s}। ସୂଚନା: {n}; ଇ-ମେଲ୍ ସୂଚନା: {e}।", "on": "ଚାଲୁ", "off": "ବନ୍ଦ",
           "help": "ମୁଁ ଏବେ ବି କରିପାରିବି:\n• କୌଣସି ଲିଙ୍କ, SMS, ମେସେଜ୍ କିମ୍ବା ଇ-ମେଲ୍ ଯାଞ୍ଚ - କେବଳ ଏଠାରେ ପେଷ୍ଟ କରନ୍ତୁ\n"
                   "• ଆପଣଙ୍କ ସାମ୍ପ୍ରତିକ ସ୍କାନ୍, ଆଲର୍ଟ କିମ୍ବା ସୁରକ୍ଷା ସାରାଂଶ ଦେଖାଇବା\n• ଆପଣଙ୍କ ସେଟିଂସ୍ କିମ୍ବା ରିପୋର୍ଟ "
                   "ଦେଖାଇବା\nସାଧାରଣ ପ୍ରଶ୍ନ ପାଇଁ AI ଆବଶ୍ୟକ - ଦୟାକରି ଏକ ମିନିଟ୍ ପରେ ପୁଣି ଚେଷ୍ଟା କରନ୍ତୁ।"},
}


def answer(db, user_id: str, message: str, reason: str, cache: dict | None = None,
           language: str | None = None) -> tuple[str, list[dict]]:
    """-> (reply text, [chat scan summaries]). reason: "busy" | "not_configured" (or a sentence), shown to the user
    in the chosen reply language (en / hi / or)."""
    from app.services.chat_tools import build_tools
    t = TEXT.get(language or "en", TEXT["en"])
    head = f"⚠️ {t.get(reason, reason)} {t['head']}\n\n"
    if _looks_like_content_to_check(message):
        s = chat_scan.run(db, user_id, _strip_question(message), cache)
        if "error" in s:
            return head + s["error"], []
        lines = [f"{t['checked_as']}: {s['checked_as']}."]
        if s["main_reasons"]:
            lines.append(f"{t['reasons']}:\n" + "\n".join(f"• {r}" for r in s["main_reasons"][:4]))
        if s["recommended_actions"]:
            lines.append(f"{t['todo']}:\n" + "\n".join(f"• {r}" for r in s["recommended_actions"][:3]))
        return head + "\n\n".join(lines), [s]

    tools = {f.__name__: f for f in build_tools(db, user_id)}
    intent = next((name for name, rx in _INTENTS if rx.search(message)), None)
    if intent == "scans":
        scans = tools["get_recent_scans"](5)
        if not scans:
            return head + t["no_scans"], []
        rows = [f"• {s['subtopic']}: {s['target'][:70]} - {s['risk_score']}/100 ({_LABEL.get(s['classification'], s['classification'])})"
                for s in scans]
        return head + f"{t['scans']}:\n" + "\n".join(rows), []
    if intent == "alerts":
        alerts = tools["get_alerts"](5)
        if not alerts:
            return head + t["no_alerts"], []
        rows = [f"• [{a['severity']}] {a['title']}" + (f" ({t['unread']})" if a["status"] == "active" else "") for a in alerts]
        return head + f"{t['alerts']}:\n" + "\n".join(rows), []
    if intent == "overview":
        o = tools["get_security_overview"]()
        b = o["severity_breakdown"]
        return head + (f"{t['score']}: {o['security_score']}/100. {t['total']}: {o['total_scans']}, {t['flagged']}: "
                       f"{o['active_threats']} (critical {b['critical']}, high {b['high']}, medium {b['medium']})."), []
    if intent == "settings":
        st = tools["get_settings"]()
        return head + t["settings"].format(s=st["sensitivity"], n=t["on"] if st["notifications_enabled"] else t["off"],
                                           e=t["on"] if st["email_notifications"] else t["off"]), []
    if intent == "reports":
        reps = tools["get_reports"](5)
        if not reps:
            return head + t["no_reports"], []
        return head + f"{t['reports']}:\n" + "\n".join(f"• {r['title']} ({r['format']})" for r in reps), []
    return head + t["help"], []
