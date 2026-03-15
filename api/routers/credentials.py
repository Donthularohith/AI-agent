"""
Credentials Router — Issue, Rotate, Revoke Agent Credentials
"""

import uuid
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from registry.database import get_db
from registry import crud
from registry.schemas import (
    CredentialIssueRequest,
    CredentialRotateRequest,
    CredentialResponse,
    ErrorResponse,
)
from registry.models import AgentStatus
from credentials.token_manager import token_manager
from audit.audit_logger import audit_logger

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/issue",
    response_model=CredentialResponse,
    responses={400: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    summary="Issue a short-lived credential for an agent",
)
async def issue_credential(
    request: CredentialIssueRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Issue a new purpose-bound credential for an agent via Vault.
    Agent must be active and not expired.
    """
    agent = await crud.get_agent(db, request.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {request.agent_id} not found")

    if agent.status != AgentStatus.ACTIVE:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot issue credential — agent status is '{agent.status.value}'",
        )

    if agent.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Cannot issue credential — agent has expired",
        )

    try:
        credential = await token_manager.issue_token(
            agent_id=str(agent.agent_id),
            ttl_seconds=agent.credential_ttl_seconds,
            scoped_resources=agent.allowed_resources,
            purpose=agent.purpose,
        )
    except Exception as e:
        logger.error(f"Credential issuance failed: {e}")
        raise HTTPException(status_code=500, detail=f"Credential issuance failed: {str(e)}")

    # Audit log
    await audit_logger.log_credential_event(
        agent_id=str(agent.agent_id),
        event_type="issue",
        credential_id=credential.get("credential_id"),
        human_owner=agent.owner_email,
        db_session=db,
    )

    return CredentialResponse(
        agent_id=agent.agent_id,
        credential_id=credential["credential_id"],
        issued_at=credential["issued_at"],
        expires_at=credential["expires_at"],
        ttl_seconds=credential["ttl_seconds"],
        status="active",
    )


@router.post(
    "/rotate",
    response_model=CredentialResponse,
    responses={400: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    summary="Rotate an agent's credential",
)
async def rotate_credential(
    request: CredentialRotateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Rotate an agent's credential — zero-downtime rotation.
    New credential is issued before the old one is revoked.
    """
    agent = await crud.get_agent(db, request.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {request.agent_id} not found")

    if agent.status != AgentStatus.ACTIVE:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot rotate — agent status is '{agent.status.value}'",
        )

    try:
        credential = await token_manager.rotate_token(
            agent_id=str(agent.agent_id),
            ttl_seconds=agent.credential_ttl_seconds,
            scoped_resources=agent.allowed_resources,
            purpose=agent.purpose,
        )
    except Exception as e:
        logger.error(f"Credential rotation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Credential rotation failed: {str(e)}")

    # Audit log
    await audit_logger.log_credential_event(
        agent_id=str(agent.agent_id),
        event_type="rotate",
        credential_id=credential.get("credential_id"),
        human_owner=agent.owner_email,
        db_session=db,
    )

    return CredentialResponse(
        agent_id=agent.agent_id,
        credential_id=credential["credential_id"],
        issued_at=credential["issued_at"],
        expires_at=credential["expires_at"],
        ttl_seconds=credential["ttl_seconds"],
        status="active",
    )


@router.post(
    "/revoke/{agent_id}",
    responses={404: {"model": ErrorResponse}},
    summary="Revoke an agent's credential",
)
async def revoke_credential(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Immediately revoke an agent's active credential."""
    agent = await crud.get_agent(db, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    try:
        result = await token_manager.revoke_token(str(agent_id))
    except Exception as e:
        logger.error(f"Credential revocation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Revocation failed: {str(e)}")

    # Audit log
    await audit_logger.log_credential_event(
        agent_id=str(agent_id),
        event_type="revoke",
        human_owner=agent.owner_email,
        db_session=db,
    )

    return {"status": "revoked", "agent_id": str(agent_id)}
