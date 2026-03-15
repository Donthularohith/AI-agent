"""
Health Router — Liveness and Readiness Probes
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter

from registry.schemas import HealthResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Platform health check",
)
async def health_check():
    """
    Check connectivity to all platform dependencies:
    - PostgreSQL database
    - OPA policy engine
    - HashiCorp Vault
    """
    health = HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
    )

    # Check database
    try:
        from registry.database import engine
        from sqlalchemy import text
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        health.database = "connected"
    except Exception as e:
        health.database = f"error: {str(e)[:100]}"
        health.status = "degraded"

    # Check OPA
    try:
        from policy.opa_client import opa_client
        opa_healthy = await opa_client.is_healthy()
        health.opa = "connected" if opa_healthy else "unreachable"
        if not opa_healthy:
            health.status = "degraded"
    except Exception as e:
        health.opa = f"error: {str(e)[:100]}"
        health.status = "degraded"

    # Check Vault
    try:
        from credentials.vault_client import vault_client
        vault_healthy = vault_client.is_healthy()
        health.vault = "connected" if vault_healthy else "unreachable"
        if not vault_healthy:
            health.status = "degraded"
    except Exception as e:
        health.vault = f"error: {str(e)[:100]}"
        health.status = "degraded"

    return health


@router.get("/health/live", summary="Liveness probe")
async def liveness():
    """Kubernetes liveness probe — is the process alive?"""
    return {"status": "alive"}


@router.get("/health/ready", summary="Readiness probe")
async def readiness():
    """Kubernetes readiness probe — can the service accept traffic?"""
    try:
        from registry.database import engine
        from sqlalchemy import text
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception:
        return {"status": "not_ready"}
