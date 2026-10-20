import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    String, Boolean, Integer, Float, Text, DateTime, ForeignKey, JSON, UniqueConstraint
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


def gen_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: gen_id("USR"))
    name: Mapped[str] = mapped_column(String, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    google_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    profile_image: Mapped[str | None] = mapped_column(String, nullable=True)
    role: Mapped[str] = mapped_column(String, default="user")
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    provider: Mapped[str] = mapped_column(String, default="password")  # "password" | "google"
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Bumped on logout and password reset: every session token issued before that stops working.
    session_version: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)

    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    settings = relationship("UserSettings", back_populates="user", uselist=False, cascade="all, delete-orphan")
    known_contacts = relationship("KnownContact", back_populates="user", cascade="all, delete-orphan")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: gen_id("PRT"))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class EmailOTP(Base):
    """A one-time code sent by email: for SIGNUP (prove the email is yours before an
    account exists) or LOGIN (second step after the password). Only a hash of the
    code is stored; the id doubles as the unguessable challenge id the browser holds."""
    __tablename__ = "email_otps"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    purpose: Mapped[str] = mapped_column(String, index=True)          # "signup" | "login"
    email: Mapped[str] = mapped_column(String, index=True)
    user_id: Mapped[str | None] = mapped_column(String, ForeignKey("users.id"), nullable=True, index=True)
    name: Mapped[str | None] = mapped_column(String, nullable=True)  # signup: the name typed in step 1
    code_hash: Mapped[str] = mapped_column(String)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    resends: Mapped[int] = mapped_column(Integer, default=0)
    remember_me: Mapped[bool] = mapped_column(Boolean, default=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)   # code was correct
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)   # finished or cancelled
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: gen_id("SCN"))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), index=True)
    module_id: Mapped[str] = mapped_column(String, index=True)
    subtopic_id: Mapped[str] = mapped_column(String, index=True)
    subtopic_title: Mapped[str] = mapped_column(String)
    input_type: Mapped[str] = mapped_column(String)
    target: Mapped[str] = mapped_column(Text)
    input_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String, default="completed")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    classification: Mapped[str] = mapped_column(String, default="safe")
    severity: Mapped[str] = mapped_column(String, default="info")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    threat_type: Mapped[str] = mapped_column(String, default="")
    analysis_engine: Mapped[str] = mapped_column(String, default="")
    explanation: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="scans")
    indicators = relationship("DetectedIndicatorRow", back_populates="scan", cascade="all, delete-orphan")
    recommendations = relationship("RecommendationRow", back_populates="scan", cascade="all, delete-orphan")


class DetectedIndicatorRow(Base):
    __tablename__ = "detected_indicators"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: gen_id("IND"))
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), index=True)
    label: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text)
    weight: Mapped[float] = mapped_column(Float, default=0.0)
    triggered: Mapped[bool] = mapped_column(Boolean, default=False)

    scan = relationship("Scan", back_populates="indicators")


class RecommendationRow(Base):
    __tablename__ = "recommendations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: gen_id("REC"))
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), index=True)
    recommendation: Mapped[str] = mapped_column(Text)
    priority: Mapped[int] = mapped_column(Integer, default=0)

    scan = relationship("Scan", back_populates="recommendations")


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: gen_id("EVT"))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), index=True)
    event_type: Mapped[str] = mapped_column(String)
    source: Mapped[str] = mapped_column(String, default="system")
    severity: Mapped[str] = mapped_column(String, default="info")
    title: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text, default="")
    event_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String, default="active")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)


class UserSettings(Base):
    __tablename__ = "settings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: gen_id("SET"))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), unique=True, index=True)
    sensitivity: Mapped[str] = mapped_column(String, default="balanced")  # conservative | balanced | aggressive (alert level, see notifier.alert_threshold)
    notifications_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    email_notifications: Mapped[bool] = mapped_column(Boolean, default=True)
    integration_settings: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    user = relationship("User", back_populates="settings")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: gen_id("RPT"))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), index=True)
    title: Mapped[str] = mapped_column(String)
    report_type: Mapped[str] = mapped_column(String, default="scan_summary")
    scan_ids: Mapped[list] = mapped_column(JSON, default=list)
    format: Mapped[str] = mapped_column(String, default="JSON")  # PDF | CSV | JSON
    file_path: Mapped[str] = mapped_column(String, default="")
    size_kb: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)



class KnownContact(Base):
    """
    A user's own personally-trusted contacts (a boss, a professor, a
    relative, their bank), used by the Friend/Relative/Known Contact
    Impersonation detector to check whether a message claiming to be from
    them actually matches what's known about them. This is inherently
    per-user data - one person's "Mom" is meaningless to another user.
    """
    __tablename__ = "known_contacts"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: gen_id("CNT"))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), index=True)
    display_name: Mapped[str] = mapped_column(String)
    role_label: Mapped[str] = mapped_column(String, default="")
    authorized_email: Mapped[str] = mapped_column(String, default="")
    authorized_domain: Mapped[str] = mapped_column(String, default="")
    typical_hours_start: Mapped[int] = mapped_column(Integer, default=0)
    typical_hours_end: Mapped[int] = mapped_column(Integer, default=23)
    high_risk_requests_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    user = relationship("User", back_populates="known_contacts")

# ---------------------------------------------------------------------------
# Email Intelligence Pipeline
# ---------------------------------------------------------------------------
class EmailRecord(Base):
    """One analysed email: who sent it, how it authenticated, and the fused verdict."""
    __tablename__ = "email_records"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: gen_id("EML"))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), index=True)
    scan_id: Mapped[str | None] = mapped_column(String, ForeignKey("scans.id"), nullable=True, index=True)
    message_id: Mapped[str] = mapped_column(String, default="", index=True)
    source: Mapped[str] = mapped_column(String, default="upload")  # upload | paste | imap | gmail | graph
    from_address: Mapped[str] = mapped_column(String, default="", index=True)
    from_domain: Mapped[str] = mapped_column(String, default="", index=True)
    from_display_name: Mapped[str] = mapped_column(String, default="")
    subject: Mapped[str] = mapped_column(Text, default="")
    spf: Mapped[str] = mapped_column(String, default="unknown")
    dkim: Mapped[str] = mapped_column(String, default="unknown")
    dmarc: Mapped[str] = mapped_column(String, default="unknown")
    originating_ip: Mapped[str] = mapped_column(String, default="")
    link_count: Mapped[int] = mapped_column(Integer, default=0)
    attachment_count: Mapped[int] = mapped_column(Integer, default=0)
    category: Mapped[str] = mapped_column(String, default="")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    classification: Mapped[str] = mapped_column(String, default="safe")
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    components: Mapped[list] = mapped_column(JSON, default=list)
    details: Mapped[dict] = mapped_column(JSON, default=dict)   # parsed summary: links, attachments, claims
    action_taken: Mapped[str] = mapped_column(String, default="none")  # none | quarantined | released ...
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)


class SenderHistory(Base):
    """Per-user memory of senders: lets the pipeline spot first-time senders and trust known-good ones."""
    __tablename__ = "sender_history"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: gen_id("SND"))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), index=True)
    sender_address: Mapped[str] = mapped_column(String, index=True)
    sender_domain: Mapped[str] = mapped_column(String, index=True)
    message_count: Mapped[int] = mapped_column(Integer, default=0)
    safe_count: Mapped[int] = mapped_column(Integer, default=0)
    malicious_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class LoginEvent(Base):
    """Every sign-in attempt to CyberGuard itself, so the account-takeover engine can watch them live."""
    __tablename__ = "login_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: gen_id("LGN"))
    email: Mapped[str] = mapped_column(String, index=True)
    user_id: Mapped[str | None] = mapped_column(String, ForeignKey("users.id"), nullable=True, index=True)
    ip: Mapped[str] = mapped_column(String, default="", index=True)
    user_agent: Mapped[str] = mapped_column(Text, default="")
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    stage: Mapped[str] = mapped_column(String, default="password")   # password | otp
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)


class IOC(Base):
    """Indicator of Compromise: a URL, domain, IP, sender address or file hash seen in a risky scan.
    If it shows up again later, the new scan is flagged as "seen before"."""
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("user_id", "ioc_type", "value", name="uq_iocs_user_type_value"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: gen_id("IOC"))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), index=True)
    ioc_type: Mapped[str] = mapped_column(String, index=True)        # url | domain | ip | email | sha256
    value: Mapped[str] = mapped_column(Text, index=True)
    status: Mapped[str] = mapped_column(String, default="active")    # active | allowlisted
    times_seen: Mapped[int] = mapped_column(Integer, default=1)
    max_risk: Mapped[int] = mapped_column(Integer, default=0)
    modules: Mapped[list] = mapped_column(JSON, default=list)        # which modules found it
    first_scan_id: Mapped[str | None] = mapped_column(String, nullable=True)
    last_scan_id: Mapped[str | None] = mapped_column(String, nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)


class AuditLog(Base):
    """Who did what, when and from where (sign-ins, settings, incident and quarantine actions ...)."""
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: gen_id("AUD"))
    user_id: Mapped[str | None] = mapped_column(String, ForeignKey("users.id"), nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String, default="")           # email of who did it (or "system")
    action: Mapped[str] = mapped_column(String, index=True)          # e.g. auth.login, incident.status
    target: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str] = mapped_column(String, default="")
    user_agent: Mapped[str] = mapped_column(Text, default="")
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
