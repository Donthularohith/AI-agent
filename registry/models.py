"""
SQLAlchemy Models — Agent, AuditLog, AnomalyEvent

These models map directly to the Agent Identity Schema from Section 3.3 of the
architecture document. The AuditLog table enforces append-only semantics via
PostgreSQL triggers (no UPDATE or DELETE allowed).

Rohith: These models are analogous to the index schema in Splunk — they define
what fields are available for search, correlation, and reporting.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy import (
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    Index,
    Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from registry.database import Base


class AgentStatus(str, enum.Enum):
    """Agent lifecycle states — mirrors CrowdStrike host containment states."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Agent(Base):
    """
    AI Agent Identity Record.

    Every AI agent in the enterprise is registered here with its identity,
    purpose, tool allowlist, and compliance tags. This is the system of record
    for the NHI (Non-Human Identity) inventory.
    """
    __tablename__ = "agents"

    # ── Identity Fields ──────────────────────────────────────────────────
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Unique agent identifier (server-generated UUID)",
    )
    name: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        comment="Human-readable agent name (DNS-safe format)",
    )
    version: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Semantic version (e.g., 1.0.0)",
    )
    owner_email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Email of the human owner responsible for this agent",
    )
    purpose: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Declared purpose — used for compliance audits and transparency",
    )

    # ── Lifecycle Fields ─────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        comment="Registration timestamp",
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Agent expiration — must be set at registration",
    )
    status: Mapped[AgentStatus] = mapped_column(
        SAEnum(AgentStatus, name="agent_status", create_constraint=True),
        default=AgentStatus.ACTIVE,
        nullable=False,
        index=True,
        comment="Current lifecycle status",
    )

    # ── Access Control Fields ────────────────────────────────────────────
    allowed_tools: Mapped[List[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        comment="List of MCP tool URIs this agent may call",
    )
    allowed_resources: Mapped[List[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        comment="List of resource patterns (glob-style) this agent may access",
    )

    # ── Delegation Fields ────────────────────────────────────────────────
    max_delegation_depth: Mapped[int] = mapped_column(
        Integer,
        default=0,
        comment="Maximum child agent delegation depth (0 = cannot delegate)",
    )
    parent_agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.agent_id"),
        nullable=True,
        comment="Parent agent UUID if this is a delegated child agent",
    )

    # ── Credential Fields ────────────────────────────────────────────────
    credential_ttl_seconds: Mapped[int] = mapped_column(
        Integer,
        default=900,
        comment="TTL for issued credentials (default 15 minutes)",
    )

    # ── Monitoring Fields ────────────────────────────────────────────────
    anomaly_threshold: Mapped[float] = mapped_column(
        Float,
        default=-0.3,
        comment="Isolation Forest anomaly score threshold for this agent",
    )

    # ── Compliance Fields ────────────────────────────────────────────────
    compliance_tags: Mapped[List[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        comment="Applicable compliance frameworks: HIPAA, PCI, SOX, etc.",
    )

    # ── Relationships ────────────────────────────────────────────────────
    audit_logs: Mapped[List["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="agent",
        lazy="dynamic",
    )
    anomaly_events: Mapped[List["AnomalyEvent"]] = relationship(
        "AnomalyEvent",
        back_populates="agent",
        lazy="dynamic",
    )
    child_agents: Mapped[List["Agent"]] = relationship(
        "Agent",
        back_populates="parent_agent",
        lazy="dynamic",
    )
    parent_agent: Mapped[Optional["Agent"]] = relationship(
        "Agent",
        back_populates="child_agents",
        remote_side=[agent_id],
    )

    # ── Indexes ──────────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_agents_owner_status", "owner_email", "status"),
        Index("ix_agents_parent", "parent_agent_id"),
        {"comment": "AI Agent Identity Registry — system of record for NHIs"},
    )

    def __repr__(self) -> str:
        return f"<Agent(id={self.agent_id}, name={self.name}, status={self.status})>"


class AuditLog(Base):
    """
    Immutable Audit Log.

    Every agent action, policy decision, and credential event is recorded here.
    A PostgreSQL trigger prevents UPDATE and DELETE operations — this table is
    append-only, ensuring audit trail integrity for HIPAA and compliance.

    Rohith: Think of this as the Splunk index — once an event is written, it
    cannot be modified or deleted. The trigger enforces this at the DB level.
    """
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Sequential audit record ID",
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.agent_id"),
        nullable=False,
        index=True,
        comment="Agent that performed the action",
    )
    action_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Action type: tool_call, credential_issue, credential_rotate, policy_deny, etc.",
    )
    tool_uri: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="MCP tool URI invoked (if applicable)",
    )
    resource: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        comment="Resource accessed (if applicable)",
    )
    outcome: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Outcome: success, denied, error",
    )
    policy_decision: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Full OPA policy decision payload",
    )
    anomaly_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Isolation Forest anomaly score at time of action",
    )
    timestamp_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        comment="UTC timestamp of the action",
    )
    session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="Session/correlation ID for tracing",
    )
    human_owner: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Human owner email at time of action",
    )
    metadata_extra: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Additional metadata (flexible JSONB field)",
    )

    # ── Relationships ────────────────────────────────────────────────────
    agent: Mapped["Agent"] = relationship("Agent", back_populates="audit_logs")
    anomaly_event: Mapped[Optional["AnomalyEvent"]] = relationship(
        "AnomalyEvent",
        back_populates="audit_log_entry",
        uselist=False,
    )

    # ── Indexes ──────────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_audit_agent_timestamp", "agent_id", "timestamp_utc"),
        Index("ix_audit_action_outcome", "action_type", "outcome"),
        {
            "comment": "Append-only audit log — UPDATE/DELETE blocked by trigger"
        },
    )

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, agent={self.agent_id}, action={self.action_type})>"


class AnomalyEvent(Base):
    """
    Anomaly Event Record.

    Stores detailed anomaly information when an agent's behavioral score
    exceeds the threshold. Links back to the audit log entry that triggered
    the anomaly and stores the full 12-feature vector as JSONB.

    Rohith: This is your correlation event — when a Splunk alert fires, this
    record provides the full context for investigation. Each feature in the
    vector maps to a MITRE ATT&CK indicator.
    """
    __tablename__ = "anomaly_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.agent_id"),
        nullable=False,
        index=True,
    )
    audit_log_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("audit_log.id"),
        nullable=True,
    )
    anomaly_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Isolation Forest anomaly score (negative = more anomalous)",
    )
    feature_vector: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment="Full 12-feature behavioral vector at time of anomaly",
    )
    threshold: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Agent's anomaly threshold when this event was generated",
    )
    timestamp_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    resolved: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        comment="Whether this anomaly has been investigated and resolved",
    )
    resolution_notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="SOC analyst notes on resolution",
    )

    # ── Relationships ────────────────────────────────────────────────────
    agent: Mapped["Agent"] = relationship("Agent", back_populates="anomaly_events")
    audit_log_entry: Mapped[Optional["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="anomaly_event",
    )

    __table_args__ = (
        Index("ix_anomaly_agent_timestamp", "agent_id", "timestamp_utc"),
        {"comment": "Behavioral anomaly events with full feature vectors"},
    )

    def __repr__(self) -> str:
        return f"<AnomalyEvent(id={self.id}, agent={self.agent_id}, score={self.anomaly_score})>"
