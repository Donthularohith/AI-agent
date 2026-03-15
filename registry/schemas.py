"""
Pydantic v2 Schemas — Request/Response Models

These schemas validate all API input and serialize all API output.
They enforce the agent identity schema from Section 3.3 at the API boundary.
"""

import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr, field_validator


# ═══════════════════════════════════════════════════════════════
# Agent Schemas
# ═══════════════════════════════════════════════════════════════

class AgentCreate(BaseModel):
    """Request body for POST /agents — register a new AI agent."""
    name: str = Field(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9\-]{2,62}$",
        description="Human-readable agent name, DNS-safe format",
        examples=["emr-patient-reader"],
    )
    version: str = Field(
        ...,
        pattern=r"^\d+\.\d+\.\d+$",
        description="Semantic version",
        examples=["1.0.0"],
    )
    owner_email: str = Field(
        ...,
        description="Email of the human owner",
        examples=["rohith.donthula@cerner.com"],
    )
    purpose: str = Field(
        ...,
        min_length=20,
        max_length=500,
        description="Declared purpose for compliance audits",
        examples=["Read patient demographics and lab results from EMR for clinical decision support"],
    )
    expires_at: datetime = Field(
        ...,
        description="Agent expiration timestamp (ISO 8601)",
    )
    allowed_tools: List[str] = Field(
        ...,
        min_length=1,
        description="List of permitted MCP tool URIs",
        examples=[["mcp://emr/patient/read", "mcp://emr/labs/query"]],
    )
    allowed_resources: List[str] = Field(
        ...,
        min_length=1,
        description="List of allowed resource patterns (glob-style)",
        examples=[["emr:patients:demographics:*", "emr:patients:labs:*"]],
    )
    max_delegation_depth: int = Field(
        default=0,
        ge=0,
        le=5,
        description="Maximum delegation chain depth (0 = no delegation)",
    )
    parent_agent_id: Optional[uuid.UUID] = Field(
        default=None,
        description="Parent agent ID for delegated child agents",
    )
    credential_ttl_seconds: int = Field(
        default=900,
        ge=60,
        le=86400,
        description="Credential TTL in seconds (default 15 minutes)",
    )
    anomaly_threshold: float = Field(
        default=-0.3,
        ge=-1.0,
        le=0.0,
        description="Anomaly score threshold for this agent",
    )
    compliance_tags: List[str] = Field(
        default_factory=list,
        description="Compliance frameworks: HIPAA, PCI, SOX, etc.",
    )

    @field_validator("owner_email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        """Basic email validation."""
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email format")
        return v.lower()

    @field_validator("allowed_tools")
    @classmethod
    def validate_tool_uris(cls, v: List[str]) -> List[str]:
        """Ensure all tool URIs follow the mcp:// scheme."""
        for uri in v:
            if not uri.startswith("mcp://"):
                raise ValueError(f"Tool URI must start with 'mcp://': {uri}")
        return v


class AgentUpdate(BaseModel):
    """Request body for PATCH /agents/{agent_id}."""
    purpose: Optional[str] = Field(None, min_length=20, max_length=500)
    allowed_tools: Optional[List[str]] = None
    allowed_resources: Optional[List[str]] = None
    max_delegation_depth: Optional[int] = Field(None, ge=0, le=5)
    credential_ttl_seconds: Optional[int] = Field(None, ge=60, le=86400)
    anomaly_threshold: Optional[float] = Field(None, ge=-1.0, le=0.0)
    compliance_tags: Optional[List[str]] = None


class AgentResponse(BaseModel):
    """Response body for agent endpoints."""
    agent_id: uuid.UUID
    name: str
    version: str
    owner_email: str
    purpose: str
    created_at: datetime
    expires_at: datetime
    status: str
    allowed_tools: List[str]
    allowed_resources: List[str]
    max_delegation_depth: int
    parent_agent_id: Optional[uuid.UUID] = None
    credential_ttl_seconds: int
    anomaly_threshold: float
    compliance_tags: List[str]

    model_config = {"from_attributes": True}


class AgentListResponse(BaseModel):
    """Paginated list of agents."""
    agents: List[AgentResponse]
    total: int
    page: int
    page_size: int


# ═══════════════════════════════════════════════════════════════
# Credential Schemas
# ═══════════════════════════════════════════════════════════════

class CredentialIssueRequest(BaseModel):
    """Request to issue a new credential for an agent."""
    agent_id: uuid.UUID = Field(..., description="Agent to issue credential for")


class CredentialRotateRequest(BaseModel):
    """Request to rotate an existing agent credential."""
    agent_id: uuid.UUID = Field(..., description="Agent whose credential to rotate")


class CredentialResponse(BaseModel):
    """Credential issuance response — never contains the raw secret."""
    agent_id: uuid.UUID
    credential_id: str
    issued_at: datetime
    expires_at: datetime
    ttl_seconds: int
    status: str = "active"


# ═══════════════════════════════════════════════════════════════
# Policy Schemas
# ═══════════════════════════════════════════════════════════════

class PolicyDecisionRequest(BaseModel):
    """Input for OPA policy decision — matches Section 3.4 schema."""
    agent_id: uuid.UUID
    action: str = Field(..., description="Action type: tool_call, delegate, etc.")
    resource: str = Field(..., description="Resource being accessed")
    tool_uri: Optional[str] = Field(None, description="MCP tool URI being called")
    timestamp: datetime = Field(default_factory=lambda: datetime.now())
    delegation_depth: int = Field(default=0, ge=0)
    parent_agent_id: Optional[uuid.UUID] = None
    session_token_claims: Optional[dict] = None


class PolicyDecisionResponse(BaseModel):
    """OPA policy decision output — matches Section 3.4 output schema."""
    allow: bool
    reason: str
    audit_required: bool = True
    denied_reasons: List[str] = Field(default_factory=list)
    compliance_flags: List[str] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
# Audit Schemas
# ═══════════════════════════════════════════════════════════════

class AuditLogEntry(BaseModel):
    """Single audit log record."""
    id: int
    agent_id: uuid.UUID
    action_type: str
    tool_uri: Optional[str] = None
    resource: Optional[str] = None
    outcome: str
    policy_decision: Optional[dict] = None
    anomaly_score: Optional[float] = None
    timestamp_utc: datetime
    session_id: Optional[uuid.UUID] = None
    human_owner: Optional[str] = None
    metadata_extra: Optional[dict] = None

    model_config = {"from_attributes": True}


class AuditLogResponse(BaseModel):
    """Paginated audit log response."""
    entries: List[AuditLogEntry]
    total: int
    page: int
    page_size: int


class AnomalyEventResponse(BaseModel):
    """Anomaly event record."""
    id: int
    agent_id: uuid.UUID
    anomaly_score: float
    feature_vector: dict
    threshold: float
    timestamp_utc: datetime
    resolved: bool
    resolution_notes: Optional[str] = None

    model_config = {"from_attributes": True}


class AnomalyListResponse(BaseModel):
    """List of anomaly events."""
    events: List[AnomalyEventResponse]
    total: int


# ═══════════════════════════════════════════════════════════════
# Health Schemas
# ═══════════════════════════════════════════════════════════════

class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    database: str = "connected"
    opa: str = "connected"
    vault: str = "connected"
    timestamp: datetime = Field(default_factory=lambda: datetime.now())


class ErrorResponse(BaseModel):
    """Standard error response."""
    detail: str
    error_code: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now())
