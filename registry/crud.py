"""
CRUD Operations — All Database Interactions

Centralized data access layer for agents, audit logs, and anomaly events.
All operations are async and use SQLAlchemy 2.0 async sessions.

Rohith: This is the equivalent of your Splunk search commands — each function
is a specific query pattern that the API and enforcement layers invoke.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple

from sqlalchemy import select, func, and_, or_, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from registry.models import Agent, AuditLog, AnomalyEvent, AgentStatus
from registry.schemas import AgentCreate, AgentUpdate


# ═══════════════════════════════════════════════════════════════
# Agent CRUD
# ═══════════════════════════════════════════════════════════════

async def create_agent(db: AsyncSession, agent_data: AgentCreate) -> Agent:
    """
    Register a new AI agent in the identity registry.
    Generates a server-side UUID and sets status to ACTIVE.
    """
    agent = Agent(
        agent_id=str(uuid.uuid4()),
        name=agent_data.name,
        version=agent_data.version,
        owner_email=agent_data.owner_email,
        purpose=agent_data.purpose,
        expires_at=agent_data.expires_at,
        allowed_tools=agent_data.allowed_tools,
        allowed_resources=agent_data.allowed_resources,
        max_delegation_depth=agent_data.max_delegation_depth,
        parent_agent_id=str(agent_data.parent_agent_id) if agent_data.parent_agent_id else None,
        credential_ttl_seconds=agent_data.credential_ttl_seconds,
        anomaly_threshold=agent_data.anomaly_threshold,
        compliance_tags=agent_data.compliance_tags,
        status=AgentStatus.ACTIVE,
    )
    db.add(agent)
    await db.flush()
    await db.refresh(agent)
    return agent


async def get_agent(db: AsyncSession, agent_id: uuid.UUID) -> Optional[Agent]:
    """Retrieve an agent by ID."""
    result = await db.execute(
        select(Agent).where(Agent.agent_id == str(agent_id))
    )
    return result.scalar_one_or_none()


async def get_agent_by_name(db: AsyncSession, name: str) -> Optional[Agent]:
    """Retrieve an agent by name."""
    result = await db.execute(
        select(Agent).where(Agent.name == name)
    )
    return result.scalar_one_or_none()


async def list_agents(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 50,
    status_filter: Optional[AgentStatus] = None,
    owner_filter: Optional[str] = None,
) -> Tuple[List[Agent], int]:
    """
    List agents with pagination and optional filters.
    Returns (agents, total_count) tuple.
    """
    query = select(Agent)
    count_query = select(func.count(Agent.agent_id))

    if status_filter:
        query = query.where(Agent.status == status_filter)
        count_query = count_query.where(Agent.status == status_filter)

    if owner_filter:
        query = query.where(Agent.owner_email == owner_filter)
        count_query = count_query.where(Agent.owner_email == owner_filter)

    query = query.order_by(Agent.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    agents = list(result.scalars().all())

    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    return agents, total


async def update_agent(
    db: AsyncSession,
    agent_id: uuid.UUID,
    agent_data: AgentUpdate,
) -> Optional[Agent]:
    """Update mutable agent fields. Does not change agent_id, name, or created_at."""
    agent = await get_agent(db, agent_id)
    if not agent:
        return None

    update_data = agent_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(agent, field, value)

    await db.flush()
    await db.refresh(agent)
    return agent


async def suspend_agent(db: AsyncSession, agent_id: uuid.UUID) -> Optional[Agent]:
    """
    Suspend an agent — blocks all credential issuance and tool calls.
    Analogous to CrowdStrike host containment.
    """
    agent = await get_agent(db, agent_id)
    if not agent:
        return None
    if agent.status == AgentStatus.REVOKED:
        return agent  # Revocation is terminal; cannot suspend a revoked agent

    agent.status = AgentStatus.SUSPENDED
    await db.flush()
    await db.refresh(agent)
    return agent


async def revoke_agent(db: AsyncSession, agent_id: uuid.UUID) -> Optional[Agent]:
    """
    Permanently revoke an agent — terminal state.
    Soft delete: record remains for audit trail, but agent can never be reactivated.
    """
    agent = await get_agent(db, agent_id)
    if not agent:
        return None

    agent.status = AgentStatus.REVOKED
    await db.flush()
    await db.refresh(agent)
    return agent


async def reactivate_agent(db: AsyncSession, agent_id: uuid.UUID) -> Optional[Agent]:
    """Reactivate a suspended agent. Cannot reactivate revoked agents."""
    agent = await get_agent(db, agent_id)
    if not agent:
        return None
    if agent.status != AgentStatus.SUSPENDED:
        return None  # Only suspended agents can be reactivated

    agent.status = AgentStatus.ACTIVE
    await db.flush()
    await db.refresh(agent)
    return agent


async def get_child_agents(
    db: AsyncSession,
    parent_agent_id: uuid.UUID,
) -> List[Agent]:
    """Get all direct child agents of a parent."""
    result = await db.execute(
        select(Agent).where(Agent.parent_agent_id == str(parent_agent_id))
    )
    return list(result.scalars().all())


async def get_all_descendants(
    db: AsyncSession,
    agent_id: uuid.UUID,
) -> List[Agent]:
    """
    Recursively get all descendant agents in the delegation chain.
    Used for blast-radius assessment.
    """
    descendants = []
    children = await get_child_agents(db, agent_id)
    for child in children:
        descendants.append(child)
        descendants.extend(await get_all_descendants(db, child.agent_id))
    return descendants


async def cascade_suspend_children(
    db: AsyncSession,
    parent_agent_id: uuid.UUID,
) -> int:
    """
    Suspend all descendant agents when a parent is suspended.
    Returns count of suspended children.
    """
    descendants = await get_all_descendants(db, parent_agent_id)
    count = 0
    for child in descendants:
        if child.status == AgentStatus.ACTIVE:
            child.status = AgentStatus.SUSPENDED
            count += 1
    await db.flush()
    return count


# ═══════════════════════════════════════════════════════════════
# Audit Log CRUD
# ═══════════════════════════════════════════════════════════════

async def create_audit_log(
    db: AsyncSession,
    agent_id: uuid.UUID,
    action_type: str,
    outcome: str,
    tool_uri: Optional[str] = None,
    resource: Optional[str] = None,
    policy_decision: Optional[dict] = None,
    anomaly_score: Optional[float] = None,
    session_id: Optional[uuid.UUID] = None,
    human_owner: Optional[str] = None,
    metadata_extra: Optional[dict] = None,
) -> AuditLog:
    """
    Write an immutable audit log entry.
    This is append-only — the PostgreSQL trigger prevents modification.
    """
    log_entry = AuditLog(
        agent_id=agent_id,
        action_type=action_type,
        tool_uri=tool_uri,
        resource=resource,
        outcome=outcome,
        policy_decision=policy_decision,
        anomaly_score=anomaly_score,
        session_id=str(session_id) if session_id else str(uuid.uuid4()),
        human_owner=human_owner,
        metadata_extra=metadata_extra,
    )
    db.add(log_entry)
    await db.flush()
    await db.refresh(log_entry)
    return log_entry


async def get_audit_logs(
    db: AsyncSession,
    agent_id: uuid.UUID,
    page: int = 1,
    page_size: int = 50,
    action_filter: Optional[str] = None,
    outcome_filter: Optional[str] = None,
    tool_filter: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> Tuple[List[AuditLog], int]:
    """Query audit logs with pagination and filters."""
    query = select(AuditLog).where(AuditLog.agent_id == str(agent_id))
    count_query = select(func.count(AuditLog.id)).where(AuditLog.agent_id == str(agent_id))

    if action_filter:
        query = query.where(AuditLog.action_type == action_filter)
        count_query = count_query.where(AuditLog.action_type == action_filter)

    if outcome_filter:
        query = query.where(AuditLog.outcome == outcome_filter)
        count_query = count_query.where(AuditLog.outcome == outcome_filter)

    if tool_filter:
        query = query.where(AuditLog.tool_uri == tool_filter)
        count_query = count_query.where(AuditLog.tool_uri == tool_filter)

    if start_time:
        query = query.where(AuditLog.timestamp_utc >= start_time)
        count_query = count_query.where(AuditLog.timestamp_utc >= start_time)

    if end_time:
        query = query.where(AuditLog.timestamp_utc <= end_time)
        count_query = count_query.where(AuditLog.timestamp_utc <= end_time)

    query = query.order_by(AuditLog.timestamp_utc.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    logs = list(result.scalars().all())

    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    return logs, total


async def get_recent_actions(
    db: AsyncSession,
    agent_id: uuid.UUID,
    minutes: int = 5,
) -> List[AuditLog]:
    """Get agent actions within the last N minutes — used for behavioral feature extraction."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    result = await db.execute(
        select(AuditLog)
        .where(
            and_(
                AuditLog.agent_id == str(agent_id),
                AuditLog.timestamp_utc >= cutoff,
            )
        )
        .order_by(AuditLog.timestamp_utc.desc())
    )
    return list(result.scalars().all())


async def count_agent_actions(
    db: AsyncSession,
    agent_id: uuid.UUID,
) -> int:
    """Count total actions for an agent — used to trigger baseline retraining."""
    result = await db.execute(
        select(func.count(AuditLog.id)).where(AuditLog.agent_id == str(agent_id))
    )
    return result.scalar() or 0


# ═══════════════════════════════════════════════════════════════
# Anomaly Event CRUD
# ═══════════════════════════════════════════════════════════════

async def create_anomaly_event(
    db: AsyncSession,
    agent_id: uuid.UUID,
    anomaly_score: float,
    feature_vector: dict,
    threshold: float,
    audit_log_id: Optional[int] = None,
) -> AnomalyEvent:
    """Record a new anomaly event with full feature vector."""
    event = AnomalyEvent(
        agent_id=str(agent_id),
        audit_log_id=audit_log_id,
        anomaly_score=anomaly_score,
        feature_vector=feature_vector,
        threshold=threshold,
    )
    db.add(event)
    await db.flush()
    await db.refresh(event)
    return event


async def get_anomaly_events(
    db: AsyncSession,
    agent_id: Optional[uuid.UUID] = None,
    limit: int = 50,
    unresolved_only: bool = False,
) -> List[AnomalyEvent]:
    """Get anomaly events, optionally filtered by agent and resolution status."""
    query = select(AnomalyEvent)

    if agent_id:
        query = query.where(AnomalyEvent.agent_id == str(agent_id))

    if unresolved_only:
        query = query.where(AnomalyEvent.resolved == False)

    query = query.order_by(AnomalyEvent.timestamp_utc.desc()).limit(limit)

    result = await db.execute(query)
    return list(result.scalars().all())


async def count_anomalies_24h(
    db: AsyncSession,
    agent_id: uuid.UUID,
) -> int:
    """Count anomaly events for an agent in the last 24 hours."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    result = await db.execute(
        select(func.count(AnomalyEvent.id)).where(
            and_(
                AnomalyEvent.agent_id == str(agent_id),
                AnomalyEvent.timestamp_utc >= cutoff,
            )
        )
    )
    return result.scalar() or 0


async def resolve_anomaly(
    db: AsyncSession,
    anomaly_id: int,
    resolution_notes: str,
) -> Optional[AnomalyEvent]:
    """Mark an anomaly as resolved with analyst notes."""
    result = await db.execute(
        select(AnomalyEvent).where(AnomalyEvent.id == anomaly_id)
    )
    event = result.scalar_one_or_none()
    if event:
        event.resolved = True
        event.resolution_notes = resolution_notes
        await db.flush()
        await db.refresh(event)
    return event
