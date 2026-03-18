"""
Agents Router — CRUD Operations for AI Agent Registry

POST /agents — Register new agent
GET  /agents — List all agents
GET  /agents/{agent_id} — Get agent details
POST /agents/{agent_id}/suspend — Suspend agent
POST /agents/{agent_id}/revoke — Revoke agent
POST /agents/{agent_id}/reactivate — Reactivate suspended agent
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from registry.database import get_db
from registry import crud
from registry.schemas import (
    AgentCreate,
    AgentUpdate,
    AgentResponse,
    AgentListResponse,
    ErrorResponse,
)
from registry.models import AgentStatus
from audit.audit_logger import audit_logger
from credentials.token_manager import token_manager
from enforcement.circuit_breaker import circuit_breaker

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "",
    response_model=AgentResponse,
    status_code=201,
    responses={400: {"model": ErrorResponse}},
    summary="Register a new AI agent",
)
async def register_agent(
    agent_data: AgentCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new AI agent in the identity governance platform.

    Requires: name, version, owner_email, purpose, expires_at,
    allowed_tools, allowed_resources.

    Returns the full agent record with server-generated agent_id.
    """
    # Validate parent agent if delegation
    if agent_data.parent_agent_id:
        parent = await crud.get_agent(db, agent_data.parent_agent_id)
        if not parent:
            raise HTTPException(
                status_code=400,
                detail=f"Parent agent {agent_data.parent_agent_id} not found",
            )

        # Validate delegation chain
        from enforcement.delegation_chain import delegation_validator
        parent_dict = {
            "agent_id": str(parent.agent_id),
            "status": parent.status.value,
            "allowed_tools": parent.allowed_tools,
            "allowed_resources": parent.allowed_resources,
            "max_delegation_depth": parent.max_delegation_depth,
            "credential_ttl_seconds": parent.credential_ttl_seconds,
        }
        child_dict = agent_data.model_dump()
        is_valid, violations = delegation_validator.validate_delegation(
            parent_dict, child_dict
        )
        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail=f"Delegation validation failed: {violations}",
            )

    # Check for duplicate name
    existing = await crud.get_agent_by_name(db, agent_data.name)
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Agent with name '{agent_data.name}' already exists",
        )

    # Create agent
    agent = await crud.create_agent(db, agent_data)

    # Log registration to audit trail
    await audit_logger.log_action(
        agent_id=str(agent.agent_id),
        action_type="agent_registered",
        outcome="success",
        human_owner=agent.owner_email,
        metadata_extra={
            "name": agent.name,
            "version": agent.version,
            "compliance_tags": agent.compliance_tags,
        },
        db_session=db,
    )

    logger.info(
        f"Agent registered: {agent.name} (id={agent.agent_id}, "
        f"owner={agent.owner_email})"
    )

    return AgentResponse.model_validate(agent)


@router.get(
    "",
    response_model=AgentListResponse,
    summary="List all registered agents",
)
async def list_agents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    status: str = Query(None, description="Filter by status"),
    owner: str = Query(None, description="Filter by owner email"),
    db: AsyncSession = Depends(get_db),
):
    """List all registered agents with pagination and optional filters."""
    status_filter = None
    if status:
        try:
            status_filter = AgentStatus(status)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status: {status}. Must be: active, suspended, expired, revoked",
            )

    agents, total = await crud.list_agents(
        db, page=page, page_size=page_size,
        status_filter=status_filter, owner_filter=owner,
    )

    return AgentListResponse(
        agents=[AgentResponse.model_validate(a) for a in agents],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{agent_id}",
    response_model=AgentResponse,
    responses={404: {"model": ErrorResponse}},
    summary="Get agent details",
)
async def get_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get the full record for a specific agent."""
    agent = await crud.get_agent(db, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
    return AgentResponse.model_validate(agent)


@router.post(
    "/{agent_id}/suspend",
    response_model=AgentResponse,
    summary="Suspend an agent",
)
async def suspend_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Suspend an agent — blocks all credential issuance and tool calls.
    Also cascades suspension to all child agents in the delegation chain.
    Revokes existing credentials via Vault.
    """
    agent = await crud.suspend_agent(db, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    # Cascade suspension to children (non-fatal)
    suspended_children = 0
    try:
        suspended_children = await crud.cascade_suspend_children(db, agent_id)
    except Exception as e:
        logger.warning(f"Cascade suspend failed (non-fatal): {e}")

    # Revoke credentials (non-fatal — Vault may be offline)
    try:
        await token_manager.revoke_token(str(agent_id))
    except Exception as e:
        logger.warning(f"Failed to revoke credential during suspension: {e}")

    # Reset circuit breaker (non-fatal)
    try:
        circuit_breaker.reset(str(agent_id))
    except Exception as e:
        logger.warning(f"Circuit breaker reset failed: {e}")

    # Log suspension (non-fatal — don't block suspend if audit write fails)
    try:
        await audit_logger.log_action(
            agent_id=str(agent_id),
            action_type="agent_suspended",
            outcome="success",
            human_owner=agent.owner_email,
            metadata_extra={"suspended_children_count": suspended_children},
            db_session=db,
        )
    except Exception as e:
        logger.warning(f"Audit log write failed during suspend: {e}")

    logger.warning(
        f"Agent SUSPENDED: {agent.name} (id={agent_id}), "
        f"{suspended_children} children also suspended"
    )

    return AgentResponse.model_validate(agent)


@router.post(
    "/{agent_id}/revoke",
    response_model=AgentResponse,
    summary="Permanently revoke an agent",
)
async def revoke_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Permanently revoke an agent — terminal state, cannot be reactivated.
    Soft delete: record persists for audit trail.
    """
    agent = await crud.revoke_agent(db, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    try:
        await crud.cascade_suspend_children(db, agent_id)
    except Exception as e:
        logger.warning(f"Cascade failed during revoke: {e}")

    try:
        await token_manager.revoke_token(str(agent_id))
    except Exception as e:
        logger.warning(f"Failed to revoke credential: {e}")

    try:
        await audit_logger.log_action(
            agent_id=str(agent_id),
            action_type="agent_revoked",
            outcome="success",
            human_owner=agent.owner_email,
            db_session=db,
        )
    except Exception as e:
        logger.warning(f"Audit log failed during revoke: {e}")

    logger.warning(f"Agent REVOKED (terminal): {agent.name} (id={agent_id})")

    return AgentResponse.model_validate(agent)


@router.post(
    "/{agent_id}/reactivate",
    response_model=AgentResponse,
    summary="Reactivate a suspended agent",
)
async def reactivate_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Reactivate a suspended agent. Cannot reactivate revoked agents."""
    agent = await crud.reactivate_agent(db, agent_id)
    if not agent:
        raise HTTPException(
            status_code=400,
            detail=f"Agent {agent_id} not found or not in suspended state",
        )

    try:
        circuit_breaker.reset(str(agent_id))
    except Exception as e:
        logger.warning(f"Circuit breaker reset failed: {e}")

    try:
        await audit_logger.log_action(
            agent_id=str(agent_id),
            action_type="agent_reactivated",
            outcome="success",
            human_owner=agent.owner_email,
            db_session=db,
        )
    except Exception as e:
        logger.warning(f"Audit log failed during reactivate: {e}")

    logger.info(f"Agent REACTIVATED: {agent.name} (id={agent_id})")

    return AgentResponse.model_validate(agent)
