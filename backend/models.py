from datetime import datetime, timezone
from sqlalchemy import String, Text, Integer, Boolean, DateTime, Index, JSON, Float, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base

def now_utc(): return datetime.now(timezone.utc)

class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    agent: Mapped[str] = mapped_column(String(40))
    event_type: Mapped[str] = mapped_column(String(60))
    target: Mapped[str] = mapped_column(String(500))
    decision: Mapped[str] = mapped_column(String(40))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    reasoning: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    data: Mapped[dict] = mapped_column(JSON, default=dict)

class Email(Base):
    __tablename__ = "emails"
    __table_args__ = (Index("uq_email_external", "source", "account_key", "external_message_id", unique=True),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender: Mapped[str] = mapped_column(String(320))
    display_name: Mapped[str] = mapped_column(String(200), default="")
    subject: Mapped[str] = mapped_column(String(500))
    body: Mapped[str] = mapped_column(Text, default="")
    urls: Mapped[list] = mapped_column(JSON, default=list)
    reply_to: Mapped[str] = mapped_column(String(320), default="")
    verdict: Mapped[str] = mapped_column(String(20))
    risk_score: Mapped[int] = mapped_column(Integer)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    folder: Mapped[str] = mapped_column(String(30), default="Inbox")
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    processed: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    ml_analysis: Mapped[dict | None] = mapped_column(JSON(none_as_null=True), nullable=True)
    source: Mapped[str] = mapped_column(String(20), default="simulated", server_default="simulated")
    account_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    external_message_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_label: Mapped[str | None] = mapped_column(String(20), nullable=True)
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    content_limits: Mapped[list | None] = mapped_column(JSON(none_as_null=True), nullable=True)


class GmailSyncState(Base):
    __tablename__ = "gmail_sync"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_key: Mapped[str] = mapped_column(String(64))
    cutoff_ms: Mapped[int] = mapped_column(Integer)
    history_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class LedgerEntry(Base):
    __tablename__ = "ledger"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    agent: Mapped[str] = mapped_column(String(40))
    target: Mapped[str] = mapped_column(String(500))
    decision: Mapped[str] = mapped_column(String(40))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    reasoning: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")
    email_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ml_analysis: Mapped[dict | None] = mapped_column(JSON(none_as_null=True), nullable=True)

class Allowlist(Base):
    __tablename__ = "allowlist"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender: Mapped[str] = mapped_column(String(320), unique=True)

class LinkScan(Base):
    __tablename__ = "link_scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(1000))
    scan_type: Mapped[str] = mapped_column(String(20), default="url")
    verdict: Mapped[str] = mapped_column(String(20))
    risk_score: Mapped[int] = mapped_column(Integer)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    report: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

class EmailLinkScan(Base):
    """Durable automatic scan job, separate from manual Link Lab simulations."""
    __tablename__ = "email_link_scans"
    __table_args__ = (
        UniqueConstraint("email_id", "position"),
        Index("ix_email_link_scan_ready", "state", "lease_until", "id"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"))
    position: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(20), default="queued")
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str | None] = mapped_column(String(10))
    score: Mapped[int | None] = mapped_column(Integer)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    duration_ms: Mapped[float | None] = mapped_column(Float)
    ledger_id: Mapped[int | None] = mapped_column(ForeignKey("ledger.id"), unique=True)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    severity: Mapped[str] = mapped_column(String(20), default="CRITICAL")
    narrative: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")
