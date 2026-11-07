"""
Telegram forwarding (added 21 Oct): forward a suspicious message - or send a screenshot - to your CyberGuard bot
and it replies with CyberGuard's verdict.

  * ONLY the owner's chat (TELEGRAM_CHAT_ID in backend/.env, the same chat that receives alerts) is answered.
    Messages from anyone else are ignored and never scanned.
  * The bot asks Telegram for new messages ("long polling") - no public web address or webhook is needed, and it
    stops with the backend. Messages sent while the backend was off for more than 2 minutes are skipped.
  * Text: the same detectors as the chat / Scan page. Photos: read on this computer (QR + OCR, the image is not
    sent to the AI). Every check is saved to Scan History with source "telegram" for the CyberGuard owner account
    (AUTOMATION_USER_EMAIL, or the first account). No AI is used, so no Gemini quota is spent.
  * The reply IS the alert, so these scans send no extra Telegram / e-mail alert.
Switch off with TELEGRAM_INBOX=false in backend/.env.
"""
from __future__ import annotations

import logging
import os
import tempfile
import threading
import time

import requests

from app.core.config import get_settings


def _clean(exc) -> str:
    """Error text without the bot token (a failed request's message contains the URL, and the URL holds the token)."""
    from app.services.notifier import redact
    return redact(exc)


logger = logging.getLogger("cyberguard.telegram")
API = "https://api.telegram.org/bot{token}/{method}"
FILE_API = "https://api.telegram.org/file/bot{token}/{path}"
MAX_PHOTO_BYTES = 10 * 1024 * 1024
SKIP_OLDER_THAN = 120            # seconds before the backend started
MAX_PER_MINUTE = 20

HELP = ("🛡️ CyberGuard bot\n\nForward me a suspicious SMS, WhatsApp / Telegram message, e-mail text or link - or send "
        "a screenshot or a QR code - and I'll check it with CyberGuard's detectors.\n\nEvery check is saved to your "
        "Scan History.")


class TelegramInbox:
    def __init__(self):
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = 0.0
        self._recent: list[float] = []
        self.status = {"state": "stopped", "handled": 0, "ignored": 0, "lastError": ""}

    # -- lifecycle ---------------------------------------------------------------------------------------------
    @staticmethod
    def configured() -> bool:
        s = get_settings()
        return bool(s.TELEGRAM_INBOX and s.TELEGRAM_BOT_TOKEN and s.TELEGRAM_CHAT_ID)

    def start(self) -> bool:
        if not self.configured() or (self._thread and self._thread.is_alive()):
            return False
        self._stop.clear()
        self._started = time.time()
        self._thread = threading.Thread(target=self._loop, name="telegram-inbox", daemon=True)
        self._thread.start()
        logger.info("Telegram forwarding started (only chat %s is answered)", get_settings().TELEGRAM_CHAT_ID)
        return True

    def stop(self) -> None:
        self._stop.set()

    # -- Telegram API ------------------------------------------------------------------------------------------
    def _call(self, method: str, http_timeout: float = 15, **params):
        """http_timeout = how long WE wait for Telegram. It must not be called 'timeout': getUpdates has its own
        Telegram parameter 'timeout' (long polling) in params - the same name twice made every poll fail."""
        s = get_settings()
        r = requests.post(API.format(token=s.TELEGRAM_BOT_TOKEN, method=method), json=params, timeout=http_timeout)
        data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        if r.status_code == 409:
            raise RuntimeError("another program is reading this bot's messages (or a webhook is set)")
        if not data.get("ok"):
            raise RuntimeError(f"Telegram {method}: HTTP {r.status_code} {str(data.get('description', ''))[:120]}")
        return data["result"]

    def reply(self, chat_id, text: str, reply_to: int | None = None) -> None:
        try:
            params = {"chat_id": chat_id, "text": text[:4000], "disable_web_page_preview": True}
            if reply_to:
                params["reply_to_message_id"] = reply_to
            self._call("sendMessage", **params)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Telegram reply failed: %s", _clean(exc))

    # -- main loop ---------------------------------------------------------------------------------------------
    def _loop(self) -> None:
        offset, wait = None, 5
        self.status["state"] = "running"
        while not self._stop.is_set():
            try:
                params = {"timeout": 25, "allowed_updates": ["message"]}
                if offset is not None:
                    params["offset"] = offset
                updates = self._call("getUpdates", http_timeout=35, **params)   # 35 s > Telegram's 25 s wait
                wait = 5
                for u in updates:
                    offset = u["update_id"] + 1          # acknowledged: Telegram will not send it again
                    msg = u.get("message")
                    if msg:
                        self.handle(msg)
            except Exception as exc:  # noqa: BLE001 - network down, Telegram busy ...
                self.status["lastError"] = _clean(exc)[:200]
                logger.warning("Telegram forwarding: %s (retrying in %s s)", _clean(exc), wait)
                self._stop.wait(wait)
                wait = min(wait * 2, 120)
        self.status["state"] = "stopped"

    def handle(self, msg: dict) -> str | None:
        """Process one incoming message. Returns the reply text (None = ignored)."""
        s = get_settings()
        chat_id = str((msg.get("chat") or {}).get("id", ""))
        if chat_id != str(s.TELEGRAM_CHAT_ID).strip():
            self.status["ignored"] += 1                  # not the owner: never scanned, never answered
            return None
        if msg.get("date", time.time()) < self._started - SKIP_OLDER_THAN:
            return None
        now = time.time()
        self._recent = [t for t in self._recent if now - t < 60]
        if len(self._recent) >= MAX_PER_MINUTE:
            text = "⏳ Too many messages in one minute - wait a moment and send it again."
            self.reply(chat_id, text, msg.get("message_id"))
            return text
        self._recent.append(now)
        text = self._check(msg)
        self.status["handled"] += 1
        self.reply(chat_id, text, msg.get("message_id"))
        return text

    def _check(self, msg: dict) -> str:
        from app.automation.engine import owner_user_id
        from app.db.database import SessionLocal
        from app.services import chat_scan, screenshot_reader

        body = (msg.get("text") or msg.get("caption") or "").strip()
        if body.lower() in ("/start", "/help", "help"):
            return HELP
        db = SessionLocal()
        try:
            uid = owner_user_id(db)
            if uid is None:
                return "⚠️ There is no CyberGuard account yet - sign up in the app first."
            scans, notes = [], []
            photo_path = self._download_image(msg)
            if photo_path:
                try:
                    info = screenshot_reader.scan(db, uid, photo_path, "telegram-photo.jpg", source="telegram",
                                                  alert=False)
                    scans += info["scans"]
                    if info["ocr"] == "not_installed" and not info["qr"]:
                        notes.append("Text reading (OCR) is not installed on the CyberGuard PC, so only QR codes in "
                                     "pictures are checked.")
                finally:
                    try:
                        os.remove(photo_path)
                    except OSError:
                        pass
            if body and not (photo_path and body == (msg.get("caption") or "").strip() and len(body) < 12):
                s_ = chat_scan.run(db, uid, body[:4000], source="telegram", alert=False)
                if "scan_id" in s_:
                    scans.append(s_)
            if not scans:
                return ("🤔 I couldn't find a message, link or QR code to check. Forward the suspicious message, paste "
                        "the link, or send a clear screenshot." + ("\n\n" + notes[0] if notes else ""))
            return "\n\n".join(format_verdict(x) for x in scans) + ("\n\n" + notes[0] if notes else "")
        finally:
            db.close()

    def _download_image(self, msg: dict) -> str | None:
        s = get_settings()
        file_id = None
        if msg.get("photo"):
            file_id = msg["photo"][-1]["file_id"]                       # the largest size
        doc = msg.get("document") or {}
        if not file_id and str(doc.get("mime_type", "")).startswith("image/"):
            file_id = doc["file_id"]
        if not file_id:
            return None
        try:
            info = self._call("getFile", file_id=file_id)
            if int(info.get("file_size") or 0) > MAX_PHOTO_BYTES:
                return None
            r = requests.get(FILE_API.format(token=s.TELEGRAM_BOT_TOKEN, path=info["file_path"]), timeout=20)
            r.raise_for_status()
            data = r.content[:MAX_PHOTO_BYTES]
            ext = os.path.splitext(info["file_path"])[1].lower() or ".jpg"
            fd, path = tempfile.mkstemp(suffix=ext if ext in (".jpg", ".jpeg", ".png", ".webp") else ".jpg")
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            return path
        except Exception as exc:  # noqa: BLE001
            logger.warning("Telegram photo download failed: %s", _clean(exc))
            return None


LABELS = {"safe": "✅ Safe", "low_risk": "🟢 Low risk", "suspicious": "🟡 Suspicious - verify first",
          "high_risk": "🔴 High risk", "critical": "⛔ Critical - do not interact", "unverified": "⚪ No verdict"}


def format_verdict(s_: dict) -> str:
    lines = [f"🛡️ CyberGuard: {s_['risk_score']}/100 - {LABELS.get(s_['verdict'], s_['verdict'])}",
             f"Checked as: {s_.get('checked_as', '')}"]
    reasons = [r.split(":", 1)[0] for r in s_.get("main_reasons", [])[:3]]
    if reasons:
        lines.append("Why: " + "; ".join(reasons))
    acts = s_.get("recommended_actions", [])[:2]
    if acts and s_["risk_score"] >= 51:
        lines.append("What to do:\n" + "\n".join(f"• {a}" for a in acts))
    lines.append(f"Saved to Scan History ({s_['scan_id']}).")
    return "\n".join(lines)


inbox = TelegramInbox()
