"""
Policy Router — OPA Policy Decision Endpoint & Management
"""

import uuid
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from registry.database import get_db
from registry import crud
from registry.schemas import PolicyDecisionRequest, PolicyDecisionResponse, ErrorResponse
from policy.opa_client import opa_client
from policy.policy_loader import load_all_policies, reload_policy, list_available_policies
from audit.audit_logger import audit_logger

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/decide",
    response_model=PolicyDecisionResponse,
    summary="Evaluate OPA policy for an agent action",
)
async def policy_decide(
    request: PolicyDecisionRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Evaluate authorization policy for an agent action.
    Used by the MCP interceptor to check allow/deny before tool execution.
    """
    # Fetch agent record for policy context
    agent = await crud.get_agent(db, request.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {request.agent_id} not found")

    # Build OPA input
    policy_input = {
        "agent_id": str(request.agent_id),
        "action": request.action,
        "resource": request.resource,
        "tool_uri": request.tool_uri,
        "timestamp": request.timestamp.isoformat() if request.timestamp else datetime.now(timezone.utc).isoformat(),
        "delegation_depth": request.delegation_depth,
        "parent_agent_id": str(request.parent_agent_id) if request.parent_agent_id else None,
        "session_token_claims": request.session_token_claims or {},
        "agent_record": {
            "status": agent.status.value,
            "allowed_tools": agent.allowed_tools,
            "allowed_resources": agent.allowed_resources,
            "max_delegation_depth": agent.max_delegation_depth,
            "compliance_tags": agent.compliance_tags,
        },
    }

    # Evaluate policy
    decision = await opa_client.evaluate_policy(policy_input)

    # Log policy decision to audit
    await audit_logger.log_policy_decision(
        agent_id=str(request.agent_id),
        decision=decision,
        tool_uri=request.tool_uri,
        resource=request.resource,
        db_session=db,
    )

    return PolicyDecisionResponse(**decision)


@router.post(
    "/reload",
    summary="Hot-reload all OPA policies",
)
async def reload_all_policies():
    """Reload all Rego policies into OPA without restarting the service."""
    results = await load_all_policies()
    return {
        "status": "complete",
        "policies": results,
        "loaded": sum(1 for v in results.values() if v),
        "failed": sum(1 for v in results.values() if not v),
    }


@router.post(
    "/reload/{policy_name}",
    summary="Hot-reload a specific OPA policy",
)
async def reload_single_policy(policy_name: str):
    """Reload a specific Rego policy file into OPA."""
    success = await reload_policy(policy_name)
    if not success:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to reload policy '{policy_name}'",
        )
    return {"status": "reloaded", "policy": policy_name}


@router.get(
    "/list",
    summary="List available OPA policies",
)
async def list_policies():
    """List all available policy files."""
    policies = await list_available_policies()
    return {"policies": policies}
