"""Data model.

An *Engagement* is what the spec calls a "session": one bounded piece of
authorized work, either in ATTACK or DEFENSE mode. Every offensive action is
tied to an Engagement, which in turn must carry a valid ScopeAuthorization.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Mode(str, enum.Enum):
    attack = "attack"
    defense = "defense"


class RunStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    blocked = "blocked"          # refused by the scope guard
    cancelled = "cancelled"


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    mode: Mapped[Mode] = mapped_column(Enum(Mode))
    operator: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    authorization: Mapped["ScopeAuthorization | None"] = relationship(
        back_populates="engagement", uselist=False, cascade="all, delete-orphan"
    )
    runs: Mapped[list["Run"]] = relationship(back_populates="engagement", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="engagement", cascade="all, delete-orphan")


class ScopeAuthorization(Base):
    """The signed, time-boxed authorized perimeter for an engagement.

    Without a row here flagged ``accepted`` and within its validity window, the
    scope guard refuses every active/offensive plugin for the engagement.
    """
    __tablename__ = "scope_authorizations"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))

    authorization_ref: Mapped[str] = mapped_column(String(300))   # ref. of the written mandate
    authorizing_party: Mapped[str] = mapped_column(String(300))   # who signed off
    # Structured targets. Each entry: {"type": "ip|cidr|host|ssid|url", "value": "..."}
    targets: Mapped[list] = mapped_column(JSON, default=list)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted: Mapped[bool] = mapped_column(Boolean, default=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")

    engagement: Mapped[Engagement] = relationship(back_populates="authorization")


class Run(Base):
    """One execution of one plugin against the engagement."""
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    plugin: Mapped[str] = mapped_column(String(120))               # plugin slug
    target: Mapped[str] = mapped_column(String(400), default="")
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    command: Mapped[str] = mapped_column(Text, default="")          # resolved command line (if any)
    status: Mapped[RunStatus] = mapped_column(Enum(RunStatus), default=RunStatus.pending)
    attack_techniques: Mapped[list] = mapped_column(JSON, default=list)   # ["T1046", ...]
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_output: Mapped[str] = mapped_column(Text, default="")
    parsed: Mapped[dict] = mapped_column(JSON, default=dict)        # structured result
    error: Mapped[str] = mapped_column(Text, default="")

    engagement: Mapped[Engagement] = relationship(back_populates="runs")
    findings: Mapped[list["Finding"]] = relationship(back_populates="run", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    run_id: Mapped[int | None] = mapped_column(ForeignKey("runs.id"), nullable=True)

    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.info)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    asset: Mapped[str] = mapped_column(String(400), default="")
    attack_technique: Mapped[str] = mapped_column(String(40), default="")
    remediation: Mapped[str] = mapped_column(Text, default="")      # defense findings
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped[Engagement] = relationship(back_populates="findings")
    run: Mapped[Run | None] = relationship(back_populates="findings")


class AuditEvent(Base):
    """Append-only, hash-chained audit record.

    Rows are never updated or deleted by the application. Each row stores the
    hash of the previous row, so any tampering breaks the chain and is
    detectable via :func:`app.security.audit.verify_chain`.
    """
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Exact ISO string hashed into the chain (round-trips regardless of DB tz handling).
    ts_iso: Mapped[str] = mapped_column(String(40), default="")
    engagement_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor: Mapped[str] = mapped_column(String(200), default="")
    action: Mapped[str] = mapped_column(String(120))                # e.g. "run.launch"
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    entry_hash: Mapped[str] = mapped_column(String(64), default="", index=True)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    mode: Mapped[Mode] = mapped_column(Enum(Mode))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    html_path: Mapped[str] = mapped_column(String(500), default="")
    pdf_path: Mapped[str] = mapped_column(String(500), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
