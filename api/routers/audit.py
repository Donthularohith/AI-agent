"""
Audit Router — Query Audit Logs & Anomaly Events
"""

import uuid
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from registry.database import get_db
from registry import crud
from registry.schemas import (
    AuditLogResponse,
    AuditLogEntry,
    AnomalyEventResponse,
    AnomalyListResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get(
    "/agents/{agent_id}",
    response_model=AuditLogResponse,
    summary="Get paginated audit log for an agent",
)
async def get_agent_audit_log(
    agent_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: Optional[str] = Query(None, description="Filter by action_type"),
    outcome: Optional[str] = Query(None, description="Filter by outcome"),
    tool: Optional[str] = Query(None, description="Filter by tool_uri"),
    start_time: Optional[datetime] = Query(None, description="Start time filter"),
    end_time: Optional[datetime] = Query(None, description="End time filter"),
    db: AsyncSession = Depends(get_db),
):
    """
    Query the audit log for a specific agent with pagination and filters.

    Rohith: This is your Splunk search in API form:
    index=ai_security agent_id="{agent_id}" action_type="{action}" | ...
    """
    # Verify agent exists
    agent = await crud.get_agent(db, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    logs, total = await crud.get_audit_logs(
        db=db,
        agent_id=agent_id,
        page=page,
        page_size=page_size,
        action_filter=action,
        outcome_filter=outcome,
        tool_filter=tool,
        start_time=start_time,
        end_time=end_time,
    )

    return AuditLogResponse(
        entries=[AuditLogEntry.model_validate(log) for log in logs],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/anomalies",
    response_model=AnomalyListResponse,
    summary="Get recent anomaly events",
)
async def get_anomalies(
    agent_id: Optional[uuid.UUID] = Query(None, description="Filter by agent"),
    limit: int = Query(50, ge=1, le=200),
    unresolved_only: bool = Query(False, description="Show only unresolved anomalies"),
    db: AsyncSession = Depends(get_db),
):
    """Get recent anomaly events across all agents or for a specific agent."""
    events = await crud.get_anomaly_events(
        db=db,
        agent_id=agent_id,
        limit=limit,
        unresolved_only=unresolved_only,
    )

    return AnomalyListResponse(
        events=[AnomalyEventResponse.model_validate(e) for e in events],
        total=len(events),
    )


@router.post(
    "/anomalies/{anomaly_id}/resolve",
    response_model=AnomalyEventResponse,
    summary="Resolve an anomaly event",
)
async def resolve_anomaly(
    anomaly_id: int,
    resolution_notes: str = Query(..., min_length=10, description="Analyst notes"),
    db: AsyncSession = Depends(get_db),
):
    """Mark an anomaly as resolved with analyst investigation notes."""
    event = await crud.resolve_anomaly(db, anomaly_id, resolution_notes)
    if not event:
        raise HTTPException(status_code=404, detail=f"Anomaly {anomaly_id} not found")

    return AnomalyEventResponse.model_validate(event)
