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

    # Database — defaults to a local SQLite file so the project runs with
    # zero external setup. Point DATABASE_URL at Postgres for production:
    #   postgresql+psycopg2://user:pass@host:5432/cyberguard
    DATABASE_URL: str = "sqlite:///./cyberguard.db"

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
    ALERT_DEDUP_MINUTES: int = 10     # same threat on the same target is alerted once per window
    APP_BASE_URL: str = "http://localhost:5173"   # used for the "open in CYBERGUARD" link
    # Auto-quarantine: emails scoring this or more are held in quarantine automatically.
    AUTO_QUARANTINE: bool = True
    QUARANTINE_MIN_SCORE: int = 71

    # ---- One-time codes (OTP) for signup and login ----
    OTP_TTL_MINUTES: int = 10        # a code stops working after this
    OTP_MAX_ATTEMPTS: int = 5        # wrong guesses before the code is burned
    OTP_RESEND_SECONDS: int = 60     # wait before "Resend code" works again
    OTP_MAX_RESENDS: int = 5
    RATE_LIMIT_ENABLED: bool = True  # per-IP limits on login/signup/OTP endpoints
    # URL scans: follow redirects and read the final page (read-only, no JavaScript, never local
    # addresses -- see app/services/safe_fetch.py). Set false to never contact scanned sites.
    LIVE_PAGE_CHECKS: bool = True

    # ---- Automatic protection (background watchers, see app/automation/) ----
    AUTOMATION_ENABLED: bool = True        # master switch; each watcher also has an on/off in Settings
    AUTOMATION_USER_EMAIL: str = ""        # CyberGuard account that receives automatic findings (default: first account)
    # Gmail inbox (read-only IMAP). Defaults to the SMTP login used for email alerts.
    IMAP_HOST: str = "imap.gmail.com"
    IMAP_USER: str = ""
    IMAP_PASSWORD: str = ""                # Gmail App Password (16 letters)
    IMAP_FOLDER: str = "INBOX"
    EMAIL_POLL_SECONDS: int = 60
    EMAIL_BACKFILL: int = 5                # on first start, also check this many of the newest emails
    # Downloads folder watcher (files are only read and hashed, never opened or run)
    DOWNLOADS_DIR: str = ""                # default: <your user folder>/Downloads
    DOWNLOADS_POLL_SECONDS: int = 30
    DOWNLOADS_MAX_MB: int = 50
    # Windows sign-in events (needs the backend terminal to run "as Administrator")
    WINDOWS_EVENTS_POLL_SECONDS: int = 300

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


@lru_cache
def get_settings() -> Settings:
    return Settings()