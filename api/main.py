"""
FastAPI Application — Main Entry Point

The governance platform API server. Handles startup/shutdown lifecycle,
middleware configuration, and router inclusion.
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

# Configure structured logging
logging.basicConfig(
    level=logging.INFO if os.getenv("API_DEBUG", "false").lower() == "true" else logging.WARNING,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan — initialize and tear down services.
    This runs once on startup and once on shutdown.
    """
    logger.info("=" * 60)
    logger.info("AI Agent Identity Governance Platform — Starting")
    logger.info("=" * 60)

    # Initialize database
    from registry.database import init_db, close_db
    try:
        await init_db()
        logger.info("[OK] Database initialized")
    except Exception as e:
        logger.warning(f"[WARN] Database init: {e} (will retry on first request)")

    # Load OPA policies
    from policy.policy_loader import load_all_policies
    try:
        results = await load_all_policies()
        loaded = sum(1 for v in results.values() if v)
        logger.info(f"[OK] OPA policies loaded: {loaded}/{len(results)}")
    except Exception as e:
        logger.warning(f"[WARN] OPA policy load: {e} (using local fallback)")

    # Start audit logger (includes Splunk HEC)
    from audit.audit_logger import audit_logger
    try:
        await audit_logger.start()
        logger.info("[OK] Audit logger started")
    except Exception as e:
        logger.warning(f"[WARN] Audit logger: {e}")

    logger.info("=" * 60)
    logger.info("Platform ready — all services initialized")
    logger.info("=" * 60)

    yield  # Application runs here

    # Shutdown
    logger.info("Shutting down platform services...")
    try:
        await audit_logger.stop()
    except Exception:
        pass

    from policy.opa_client import opa_client
    try:
        await opa_client.close()
    except Exception:
        pass

    try:
        await close_db()
    except Exception:
        pass

    logger.info("Platform shutdown complete")


# Create FastAPI app
app = FastAPI(
    title=os.getenv("API_TITLE", "AI Agent Identity Governance Platform"),
    description=(
        "Enterprise platform for governing AI agent identities, credentials, "
        "permissions, and behavior. Designed for healthcare environments with "
        "HIPAA, NIST AI RMF, and EU AI Act compliance."
    ),
    version=os.getenv("API_VERSION", "1.0.0"),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware — restrict in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if os.getenv("API_DEBUG") == "true" else ["http://localhost:8501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
from api.routers import agents, credentials, policy, audit, health

app.include_router(agents.router, prefix="/agents", tags=["Agent Registry"])
app.include_router(credentials.router, prefix="/credentials", tags=["Credential Lifecycle"])
app.include_router(policy.router, prefix="/policy", tags=["Policy Engine"])
app.include_router(audit.router, prefix="/audit", tags=["Audit & Compliance"])
app.include_router(health.router, tags=["Health"])


@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint — redirect to docs."""
    return {
        "platform": "AI Agent Identity Governance Platform",
        "version": os.getenv("API_VERSION", "1.0.0"),
        "docs": "/docs",
        "health": "/health",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", "8000")),
        reload=os.getenv("API_DEBUG", "false").lower() == "true",
    )
