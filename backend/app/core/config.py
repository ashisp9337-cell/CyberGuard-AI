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