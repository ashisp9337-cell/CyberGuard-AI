"""
Alerts: tell the admin / SOC automatically when a serious threat is detected.

Flow
    scan finishes -> risk score >= ALERT_MIN_SCORE (default 71 = high risk / critical)
                  -> user has "critical alerts" switched on in Settings
                  -> same threat on same target not already alerted in the last ALERT_DEDUP_MINUTES
                  -> send to every configured channel (Telegram, email, WhatsApp)
                  -> record what happened on the scan's threat event (event_metadata["alerts"])

Channels are configured in backend/.env. A channel with no settings is
reported as "not_configured" and simply skipped, so the app works with
any mix of channels set up.

Sending runs AFTER the scan response has been returned (FastAPI background
task), so a slow Telegram/SMTP server never makes a scan slower, and a
failure is recorded instead of crashing anything.
"""
import hashlib
import hmac
import html
import logging
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.parser import BytesHeaderParser
from email.utils import getaddresses, make_msgid, parseaddr

import requests

from app.core.config import get_settings

logger = logging.getLogger("cyberguard.alerts")

SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}


# ---------------------------------------------------------------------------
# Channel status
# ---------------------------------------------------------------------------
def telegram_configured() -> bool:
    s = get_settings()
    return bool(s.TELEGRAM_BOT_TOKEN and s.TELEGRAM_CHAT_ID)


def email_configured() -> bool:
    s = get_settings()
    return bool(s.SMTP_HOST and s.ALERT_EMAIL_TO and (s.SMTP_FROM or s.SMTP_USER))


def whatsapp_configured() -> bool:
    s = get_settings()
    if not s.WHATSAPP_TO.strip():
        return False
    provider = s.WHATSAPP_PROVIDER.strip().lower()
    if provider == "twilio":
        return bool(s.TWILIO_ACCOUNT_SID and s.TWILIO_AUTH_TOKEN and s.TWILIO_WHATSAPP_FROM)
    if provider == "callmebot":
        return bool(s.CALLMEBOT_APIKEY)
    return False


def channel_status() -> dict:
    s = get_settings()
    return {"telegram": telegram_configured(), "email": email_configured(), "whatsapp": whatsapp_configured(),
            "whatsappProvider": s.WHATSAPP_PROVIDER.strip().lower(),
            "minScore": s.ALERT_MIN_SCORE, "dedupMinutes": s.ALERT_DEDUP_MINUTES}


def _email_recipients() -> list[str]:
    """ALERT_EMAIL_TO may hold several addresses separated by commas."""
    return [addr for _, addr in getaddresses([get_settings().ALERT_EMAIL_TO]) if addr]


# ---------------------------------------------------------------------------
# Message
# ---------------------------------------------------------------------------
def build_alert(scan: dict) -> dict:
    """scan: {id, threatType, classification, severity, riskScore, target, explanation,
              indicators, responseActions, mitre, moduleId}  ->  {"subject", "text", "html"}"""
    s = get_settings()
    sev = scan.get("severity", "high")
    level = scan.get("classification", "").replace("_", " ").upper()
    target = (scan.get("target") or "")[:160]
    top = [i for i in scan.get("indicators", []) if i.get("triggered")]
    top = sorted(top, key=lambda i: -i.get("weight", 0))[:3]
    actions = [a for a in scan.get("responseActions", []) if a.get("priority") == "immediate"][:3] \
        or scan.get("responseActions", [])[:3]
    mitre_ids = scan.get("mitre") or sorted({t for i in scan.get("indicators", []) if i.get("triggered")
                                             for t in ([i["mitre"]] if isinstance(i.get("mitre"), str) else (i.get("mitre") or []))})
    try:
        from app.services.mitre import brief as _mitre_brief
        mitre = [f"{d['id']} {d['name']}" if d["name"] != "MITRE ATT&CK technique" else d["id"]
                 for d in _mitre_brief([m for m in mitre_ids if isinstance(m, str)][:6])]
    except Exception:
        mitre = [m for m in mitre_ids if isinstance(m, str)]
    link = f"{s.APP_BASE_URL.rstrip('/')}/scan-history"

    subject = f"[CYBERGUARD {level}] {scan.get('threatType', 'Threat')} — risk {scan.get('riskScore')}"

    lines = [f"{SEVERITY_ICON.get(sev, '⚠️')} CYBERGUARD ALERT — {level} ({scan.get('riskScore')}/100)",
             f"Threat: {scan.get('threatType', '')}",
             f"Target: {target}", "",
             f"Why: {scan.get('explanation', '')[:400]}"]
    if top:
        lines += ["", "Evidence:"] + [f"• {i['label']}" for i in top]
    if actions:
        lines += ["", "Do now:"] + [f"• {a['title']}" for a in actions]
    if mitre:
        lines += ["", "MITRE ATT&CK:"] + [f"• {m}" for m in mitre[:6]]
    lines += ["", f"Scan ID: {scan.get('id', '')}", link]
    text = "\n".join(lines)

    e = html.escape
    h = [f"<b>{SEVERITY_ICON.get(sev, '⚠️')} CYBERGUARD ALERT — {e(level)} ({scan.get('riskScore')}/100)</b>",
         f"<b>Threat:</b> {e(scan.get('threatType', ''))}",
         f"<b>Target:</b> <code>{e(target)}</code>", "",
         f"<b>Why:</b> {e(scan.get('explanation', '')[:400])}"]
    if top:
        h += ["", "<b>Evidence:</b>"] + [f"• {e(i['label'])}" for i in top]
    if actions:
        h += ["", "<b>Do now:</b>"] + [f"• {e(a['title'])}" for a in actions]
    if mitre:
        h += ["", "<b>MITRE ATT&amp;CK:</b> " + e(", ".join(mitre[:6]))]
    h += ["", f"Scan ID: <code>{e(scan.get('id', ''))}</code>"]

    # WhatsApp: plain text, *bold* heading, kept short (WhatsApp/CallMeBot limits).
    whatsapp = ("*" + lines[0] + "*\n" + "\n".join(lines[1:]))[:1500]

    # Email: a small HTML version (with the plain text as fallback for old mail apps).
    colour = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04"}.get(sev, "#0891b2")
    def _list(title, items):
        return (f'<p style="margin:14px 0 4px;font-weight:bold">{title}</p><ul style="margin:0;padding-left:20px">'
                + "".join(f"<li>{e(x)}</li>" for x in items) + "</ul>") if items else ""
    email_html = (
        '<div style="font-family:Arial,sans-serif;max-width:600px;color:#111">'
        f'<div style="background:{colour};color:#fff;padding:14px 18px;border-radius:8px 8px 0 0">'
        f'<b>CYBERGUARD ALERT — {e(level)}</b><br>Risk score {scan.get("riskScore")}/100</div>'
        '<div style="border:1px solid #ddd;border-top:0;padding:16px 18px;border-radius:0 0 8px 8px">'
        f'<p style="margin:0 0 6px"><b>Threat:</b> {e(scan.get("threatType", ""))}</p>'
        f'<p style="margin:0 0 6px"><b>Target:</b> <code>{e(target)}</code></p>'
        f'<p style="margin:10px 0 0"><b>Why:</b> {e(scan.get("explanation", "")[:400])}</p>'
        + _list("Evidence", [i["label"] for i in top])
        + _list("Do now", [a["title"] for a in actions])
        + (f'<p style="margin:14px 0 0"><b>MITRE ATT&amp;CK:</b> {e(", ".join(mitre[:6]))}</p>' if mitre else "")
        + f'<p style="margin:18px 0 0"><a href="{e(link)}" style="background:#0891b2;color:#fff;padding:9px 14px;'
          'border-radius:6px;text-decoration:none">Open in CYBERGUARD</a></p>'
        + f'<p style="margin:16px 0 0;color:#666;font-size:12px">Scan ID: {e(str(scan.get("id", "")))}</p></div></div>'
    )
    return {"subject": subject, "text": text, "html": "\n".join(h), "whatsapp": whatsapp, "email_html": email_html}


# ---------------------------------------------------------------------------
# Senders
# ---------------------------------------------------------------------------
def _result(channel: str, status: str, error: str = "") -> dict:
    return {"channel": channel, "status": status, "error": error[:300],
            "at": datetime.now(timezone.utc).isoformat()}


def send_telegram(message: dict) -> dict:
    if not telegram_configured():
        return _result("telegram", "not_configured")
    s = get_settings()
    try:
        r = requests.post(f"https://api.telegram.org/bot{s.TELEGRAM_BOT_TOKEN}/sendMessage",
                          json={"chat_id": s.TELEGRAM_CHAT_ID, "text": message["html"], "parse_mode": "HTML",
                                "disable_web_page_preview": True},
                          timeout=10)
        if r.ok and r.json().get("ok"):
            return _result("telegram", "sent")
        return _result("telegram", "failed", f"HTTP {r.status_code}: {r.text}")
    except Exception as exc:  # network down, bad token, ...
        return _result("telegram", "failed", str(exc))


# ---------------------------------------------------------------------------
# CyberGuard's own emails (alerts, sign-in codes, reset links)
# ---------------------------------------------------------------------------
# Alerts usually go to the same Gmail inbox the email watcher reads. An alert email quotes the
# phishing it reports, so without this the watcher would flag the alert itself and send another
# alert about it, again and again. Every email CyberGuard sends carries a signature only this
# server can make (HMAC with the server secret), and the watcher skips signed emails.
OWN_MAIL_HEADER = "X-CyberGuard-Sig"
OWN_MAIL_ID_HEADER = "X-CyberGuard-Id"
OWN_SUBJECT_PREFIX = "[CYBERGUARD"


def own_mail_signature(mail_id: str) -> str:
    key = hashlib.sha256(b"cyberguard-own-mail|" + get_settings().JWT_SECRET.encode()).digest()
    return hmac.new(key, (mail_id or "").strip().encode(), hashlib.sha256).hexdigest()[:40]


def is_own_mail(raw: bytes) -> bool:
    """True for an email that CyberGuard itself sent (so it must not be scanned and alerted on again)."""
    try:
        h = BytesHeaderParser().parsebytes(raw if isinstance(raw, bytes) else str(raw).encode())
    except Exception:
        return False
    mid, sig = str(h.get(OWN_MAIL_ID_HEADER, "") or "").strip(), str(h.get(OWN_MAIL_HEADER, "") or "").strip()
    if sig:                                  # signed: valid only with the right signature
        return bool(mid) and hmac.compare_digest(sig, own_mail_signature(mid))
    # Alerts sent before signatures existed: our own address + our alert subject, with no sign of spoofing.
    s = get_settings()
    ours = parseaddr(s.SMTP_FROM or s.SMTP_USER)[1].strip().lower()
    sender = parseaddr(str(h.get("From", "") or ""))[1].strip().lower()
    subject = " ".join(str(h.get("Subject", "") or "").split()).upper()
    auth = " ".join(str(v) for v in (h.get_all("Authentication-Results") or [])).lower()
    spoofed = any(f in auth for f in ("dmarc=fail", "spf=fail", "dkim=fail", "spf=softfail"))
    return bool(ours) and sender == ours and subject.startswith(OWN_SUBJECT_PREFIX) and not spoofed


def send_mail(to: list[str], subject: str, text: str, html: str | None = None, channel: str = "email") -> dict:
    """Send one email through the SMTP settings in .env (used by alerts and by OTP codes)."""
    if not (get_settings().SMTP_HOST and (get_settings().SMTP_FROM or get_settings().SMTP_USER)):
        return _result(channel, "not_configured")
    s = get_settings()
    to = [a for a in to if a]
    if not to:
        return _result(channel, "failed", "no recipient address")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = s.SMTP_FROM or s.SMTP_USER
    msg["To"] = ", ".join(to)
    sender_domain = parseaddr(s.SMTP_FROM or s.SMTP_USER)[1].rpartition("@")[2] or None
    msg["Message-ID"] = make_msgid(domain=sender_domain)
    mail_id = secrets.token_hex(16)
    msg[OWN_MAIL_ID_HEADER] = mail_id
    msg[OWN_MAIL_HEADER] = own_mail_signature(mail_id)              # lets the watcher skip our own mail
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    # Gmail shows App Passwords as "abcd efgh ijkl mnop" -- the spaces are not part of it.
    password = s.SMTP_PASSWORD.replace(" ", "")
    try:
        if s.SMTP_PORT == 465:   # SSL from the first byte
            smtp = smtplib.SMTP_SSL(s.SMTP_HOST, s.SMTP_PORT, timeout=15)
        else:                    # 587 (or 25): plain connection, upgraded with STARTTLS
            smtp = smtplib.SMTP(s.SMTP_HOST, s.SMTP_PORT, timeout=15)
        with smtp:
            smtp.ehlo()
            if s.SMTP_PORT not in (25, 465):
                smtp.starttls()
                smtp.ehlo()
            if s.SMTP_USER:
                smtp.login(s.SMTP_USER, password)
            smtp.send_message(msg, to_addrs=to)
        return _result(channel, "sent")
    except smtplib.SMTPAuthenticationError:
        return _result(channel, "failed", "Login refused. For Gmail use a 16-letter App Password, not your normal password.")
    except Exception as exc:
        return _result(channel, "failed", str(exc))


def send_email(message: dict) -> dict:
    if not email_configured():
        return _result("email", "not_configured")
    to = _email_recipients()
    if not to:
        return _result("email", "failed", "ALERT_EMAIL_TO has no valid address")
    return send_mail(to, message["subject"], message["text"], message.get("email_html"))


def send_whatsapp(message: dict) -> dict:
    if not whatsapp_configured():
        return _result("whatsapp", "not_configured")
    s = get_settings()
    body = message.get("whatsapp") or message["text"]
    to = s.WHATSAPP_TO.strip().replace(" ", "")
    try:
        if s.WHATSAPP_PROVIDER.strip().lower() == "twilio":
            r = requests.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{s.TWILIO_ACCOUNT_SID}/Messages.json",
                data={"From": s.TWILIO_WHATSAPP_FROM,
                      "To": to if to.startswith("whatsapp:") else f"whatsapp:{to}", "Body": body},
                auth=(s.TWILIO_ACCOUNT_SID, s.TWILIO_AUTH_TOKEN), timeout=15)
            ok = r.status_code in (200, 201)
        else:  # callmebot: a simple GET; it answers 200 with an HTML page, which says ERROR on failure
            r = requests.get("https://api.callmebot.com/whatsapp.php",
                             params={"phone": to.lstrip("+"), "text": body, "apikey": s.CALLMEBOT_APIKEY},
                             timeout=20)
            ok = r.status_code == 200 and "error" not in r.text.lower()
        if ok:
            return _result("whatsapp", "sent")
        return _result("whatsapp", "failed", f"HTTP {r.status_code}: {r.text}")
    except Exception as exc:
        return _result("whatsapp", "failed", str(exc))


def send_all(message: dict, email: bool = True) -> list[dict]:
    """email=False: the user switched "Email Notifications" off in Settings."""
    return [send_telegram(message),
            send_email(message) if email else _result("email", "disabled_by_user"),
            send_whatsapp(message)]


# ---------------------------------------------------------------------------
# Called after every scan (as a background task)
# ---------------------------------------------------------------------------
def _dedup_key(module_id: str, threat_type: str, target: str) -> str:
    return hashlib.sha256(f"{module_id}|{threat_type}|{(target or '').strip().lower()}".encode()).hexdigest()[:16]


# Settings -> "Alert sensitivity": which risk level sends an alert to the owner / SOC.
#   conservative = critical only (86+), balanced = high risk and critical (ALERT_MIN_SCORE, 71+),
#   aggressive = suspicious and above (51+). Older saved values "low" / "high" mean conservative / aggressive.
ALERT_FLOOR = 51            # the lowest any sensitivity can alert at: callers only skip scans below this


def alert_threshold(sensitivity: str | None) -> int:
    level = (sensitivity or "balanced").strip().lower()
    if level in ("conservative", "low"):
        return 86
    if level in ("aggressive", "high"):
        return ALERT_FLOOR
    return get_settings().ALERT_MIN_SCORE


def alert_for_scan(scan_id: str) -> list[dict]:
    """Decide whether to alert for this scan, send it, and record the outcome. Never raises."""
    from app.db.database import SessionLocal
    from app.db.models import Scan, ThreatEvent, UserSettings

    s = get_settings()
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return []
        prefs = db.query(UserSettings).filter(UserSettings.user_id == scan.user_id).first()
        if (scan.risk_score or 0) < alert_threshold(prefs.sensitivity if prefs is not None else None):
            return []
        if prefs is not None and not prefs.notifications_enabled:
            return []

        events = (db.query(ThreatEvent).filter(ThreatEvent.user_id == scan.user_id)
                  .order_by(ThreatEvent.timestamp.desc()).limit(200).all())
        event = next((e for e in events if (e.event_metadata or {}).get("scanId") == scan_id), None)

        key = _dedup_key(scan.module_id, scan.threat_type, scan.target)
        since = datetime.now(timezone.utc) - timedelta(minutes=s.ALERT_DEDUP_MINUTES)
        for e in events:
            meta = e.event_metadata or {}
            ts = e.timestamp if e.timestamp.tzinfo else e.timestamp.replace(tzinfo=timezone.utc)
            if e is not event and ts >= since and meta.get("alertKey") == key and \
                    any(a.get("status") == "sent" for a in meta.get("alerts", [])):
                outcome = [_result("all", "suppressed_duplicate")]
                break
        else:
            result = scan.result or {}
            message = build_alert({
                "id": scan.id, "moduleId": scan.module_id, "threatType": scan.threat_type,
                "classification": scan.classification, "severity": scan.severity, "riskScore": scan.risk_score,
                "target": scan.target, "explanation": scan.explanation,
                "indicators": result.get("indicators", []), "responseActions": result.get("responseActions", []),
                "mitre": result.get("mitre", []),
            })
            outcome = send_all(message, email=prefs.email_notifications if prefs is not None else True)

        if event is not None:
            meta = dict(event.event_metadata or {})
            meta["alertKey"] = key
            meta["alerts"] = list(meta.get("alerts", [])) + outcome
            event.event_metadata = meta     # reassign so SQLAlchemy saves the JSON change
            db.commit()
        for o in outcome:
            logger.info("alert %s for scan %s: %s %s", o["channel"], scan_id, o["status"], o["error"])
        return outcome
    except Exception:
        logger.exception("alerting failed for scan %s", scan_id)
        return []
    finally:
        db.close()