"""
Centralized backend configuration, loaded from environment variables.
Never hardcode secrets here — see .env.example for the full list.
"""
from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    ENVIRONMENT: str = "development"

    # Database: PostgreSQL ONLY (the one and final database of CyberGuard). Set in backend/.env:
    #   DATABASE_URL=postgresql+psycopg2://user:password@localhost:5432/cyberguard
    # The schema is created and upgraded by Alembic:  alembic upgrade head
    DATABASE_URL: str = ""

    JWT_SECRET: str = "dev-secret-change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    COOKIE_NAME: str = "cyberguard_session"
    COOKIE_SECURE: bool = False  # set True behind HTTPS in production

    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""

    TURNSTILE_SECRET_KEY: str = ""

    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    URLHAUS_API_KEY: str = ""

    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-flash-latest"

    CORS_ORIGINS: str = "http://localhost:5173"

    # ---- Alerts to the admin / SOC (Module 6) ----
    # Telegram: create a bot with @BotFather, then put its token and your chat id here.
    TELEGRAM_BOT_TOKEN: str = ""
    TELEGRAM_CHAT_ID: str = ""
    # Email via SMTP (Gmail: smtp.gmail.com, port 587, and an App Password -- not your normal password).
    # Port 587 = STARTTLS, port 465 = SSL; both work.
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    ALERT_EMAIL_TO: str = ""          # comma-separated SOC / admin addresses
    # WhatsApp. Two providers:
    #   callmebot (free, personal use, sends only to YOUR OWN number):
    #       save +34 644 95 73 56, WhatsApp it "I allow callmebot to send me messages", it replies with an apikey.
    #   twilio (official, can message other people): account SID, auth token and the sandbox/sender number.
    WHATSAPP_PROVIDER: str = "callmebot"   # callmebot | twilio
    WHATSAPP_TO: str = ""                  # your number with country code, e.g. +919876543210
    CALLMEBOT_APIKEY: str = ""
    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""
    TWILIO_WHATSAPP_FROM: str = ""         # e.g. whatsapp:+14155238886 (Twilio sandbox number)
    ALERT_MIN_SCORE: int = 71         # 71+ = high risk and critical
    ALERT_DEDUP_MINUTES: int = 1440   # same threat on the same target is alerted once per window (24 h)
    APP_BASE_URL: str = "http://localhost:5173"   # used for the "open in CYBERGUARD" link
    # Auto-quarantine: emails scoring this or more are held in quarantine automatically.
    AUTO_QUARANTINE: bool = True
    QUARANTINE_MIN_SCORE: int = 71
    # Real, REVERSIBLE quarantine (nothing is ever deleted; every move is logged and can be undone):
    #  * Gmail: a dangerous inbox email is MOVED to the label below (out of the inbox, not deleted);
    #    "Release" moves it back to the inbox.
    MAILBOX_QUARANTINE: bool = True
    MAILBOX_QUARANTINE_LABEL: str = "CyberGuard-Quarantine"
    #  * Downloads: a dangerous new download is MOVED to QUARANTINE_DIR (renamed so it cannot be run by a
    #    double-click); "Restore" puts it back where it was.
    FILE_QUARANTINE: bool = True
    FILE_QUARANTINE_MIN_SCORE: int = 71
    QUARANTINE_DIR: str = "./quarantine"

    # ---- One-time codes (OTP) for signup and login ----
    OTP_TTL_MINUTES: int = 10        # a code stops working after this
    OTP_MAX_ATTEMPTS: int = 5        # wrong guesses before the code is burned
    OTP_RESEND_SECONDS: int = 60     # wait before "Resend code" works again
    OTP_MAX_RESENDS: int = 5
    RATE_LIMIT_ENABLED: bool = True  # per-IP limits on login/signup/OTP endpoints
    # URL scans: follow redirects and read the final page (read-only, no JavaScript, never local
    # addresses -- see app/services/safe_fetch.py). Set false to never contact scanned sites.
    LIVE_PAGE_CHECKS: bool = True
    # Load every model into memory in the background when the backend starts (no slow first scan).
    WARM_UP_MODELS: bool = True

    # ---- Automatic protection (background watchers, see app/automation/) ----
    AUTOMATION_ENABLED: bool = True        # master switch; each watcher also has an on/off in Settings
    AUTOMATION_USER_EMAIL: str = ""        # CyberGuard account that receives automatic findings (default: first account)
    # Gmail inbox (read-only IMAP). Defaults to the SMTP login used for email alerts.
    IMAP_HOST: str = "imap.gmail.com"
    IMAP_USER: str = ""
    IMAP_PASSWORD: str = ""                # Gmail App Password (16 letters)
    IMAP_FOLDER: str = "INBOX"
    IMAP_SPAM_FOLDER: str = "[Gmail]/Spam"   # also checked (found automatically); "off" = inbox only
    EMAIL_POLL_SECONDS: int = 60
    EMAIL_BACKFILL: int = 5                # on first start, also check this many of the newest emails
    # Downloads folder watcher (files are only read and hashed, never opened or run)
    DOWNLOADS_DIR: str = ""                # default: <your user folder>/Downloads
    DOWNLOADS_POLL_SECONDS: int = 30
    DOWNLOADS_MAX_MB: int = 50
    # Windows sign-in events (needs the backend terminal to run "as Administrator")
    WINDOWS_EVENTS_POLL_SECONDS: int = 300

    # ---- Security switches (all safe by default) ----
    ADMIN_EMAILS: str = ""              # comma-separated admin accounts; empty = the automation owner (see dependencies.py)
    ENABLE_API_DOCS: bool = False       # /docs, /redoc and /openapi.json; turn on only while developing
    DEBUG: bool = False                 # true = show internal error messages in API responses (never in production)
    EXPOSE_DEV_CODES: bool = False      # automated tests ONLY: echo OTP / reset codes in API responses. Never enable.
    MAX_TEXT_CHARS: int = 200_000       # longest pasted text / email accepted by the scan endpoints
    MAX_CHAT_CHARS: int = 4_000         # longest chat message sent to the AI guide

    UPLOAD_DIR: str = "./uploads"
    REPORTS_DIR: str = "./reports"
    MODELS_DIR: str = "./app/ml/models"
    MAX_UPLOAD_MB: int = 15

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def admin_email_list(self) -> List[str]:
        return [e.strip().lower() for e in self.ADMIN_EMAILS.split(",") if e.strip()]

    @property
    def dev_codes_allowed(self) -> bool:
        """Only the test suite turns this on; production can never echo codes."""
        return self.EXPOSE_DEV_CODES and not self.is_production


WEAK_JWT_SECRETS = {"dev-secret-change-me-in-production", "change-me-to-a-long-random-string", "secret", "changeme", ""}


def database_problem(url: str) -> str:
    """'' if url is a PostgreSQL URL, else the reason CyberGuard refuses to start."""
    if not url:
        return ("DATABASE_URL is not set. CyberGuard uses PostgreSQL only: add "
                "DATABASE_URL=postgresql+psycopg2://user:password@localhost:5432/cyberguard to backend/.env")
    if not url.startswith(("postgresql://", "postgresql+psycopg2://", "postgresql+psycopg://")):
        return (f"DATABASE_URL must be a PostgreSQL URL (postgresql+psycopg2://...); got a "
                f"'{url.split(':', 1)[0]}' URL. CyberGuard uses PostgreSQL only.")
    return ""


def security_problems(s: "Settings") -> list[str]:
    """Settings that would make the app unsafe. Production refuses to start with any of them."""
    problems = []
    if s.JWT_SECRET in WEAK_JWT_SECRETS or len(s.JWT_SECRET) < 32:
        problems.append("JWT_SECRET is missing, a known placeholder, or shorter than 32 characters "
                        "(make one with: python -c \"import secrets; print(secrets.token_hex(32))\")")
    if "*" in s.cors_origin_list:
        problems.append("CORS_ORIGINS must list exact origins; '*' cannot be used with login cookies")
    if s.is_production:
        if not s.COOKIE_SECURE:
            problems.append("COOKIE_SECURE must be true in production (HTTPS only)")
        if s.EXPOSE_DEV_CODES:
            problems.append("EXPOSE_DEV_CODES must never be enabled in production")
        if s.DEBUG:
            problems.append("DEBUG must be false in production")
    return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()