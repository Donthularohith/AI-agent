"""
Test Configuration — Pytest Fixtures

Provides test database, mock clients, and async test infrastructure.
"""

import os
import uuid
import asyncio
import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from typing import AsyncGenerator

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

# Set test environment
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///test_governance.db"
os.environ["VAULT_TOKEN"] = "test-vault-token"
os.environ["OPA_URL"] = "http://localhost:8181"
os.environ["SPLUNK_HEC_TOKEN"] = ""
os.environ["API_DEBUG"] = "false"

from registry.database import Base, get_db
from api.main import app


# ── Database Fixtures ─────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="function")
async def test_engine():
    """Create a test database engine."""
    engine = create_async_engine("sqlite+aiosqlite:///test_governance.db", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()
    # Cleanup test DB file
    try:
        os.remove("test_governance.db")
    except FileNotFoundError:
        pass


@pytest_asyncio.fixture(scope="function")
async def test_db(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Provide a test database session."""
    session_factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def client(test_engine) -> AsyncGenerator[AsyncClient, None]:
    """Provide an async HTTP client for API testing."""
    session_factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def override_get_db():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


# ── Mock Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def mock_vault():
    """Mock Vault client for testing."""
    with patch("credentials.vault_client.vault_client") as mock:
        mock.is_healthy.return_value = True
        mock.issue_credential.return_value = {
            "credential_id": f"cred-test-{uuid.uuid4().hex[:8]}",
            "agent_id": "test-agent-id",
            "issued_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(seconds=900),
            "ttl_seconds": 900,
            "status": "active",
        }
        mock.revoke_credential.return_value = True
        yield mock


@pytest.fixture
def mock_opa():
    """Mock OPA client for testing."""
    with patch("policy.opa_client.opa_client") as mock:
        mock.is_healthy = AsyncMock(return_value=True)
        mock.evaluate_policy = AsyncMock(return_value={
            "allow": True,
            "reason": "all_checks_passed",
            "audit_required": True,
            "denied_reasons": [],
            "compliance_flags": [],
        })
        yield mock


# ── Sample Data Fixtures ─────────────────────────────────────────────────

@pytest.fixture
def sample_agent_data():
    """Valid agent registration data."""
    return {
        "name": "emr-patient-reader",
        "version": "1.0.0",
        "owner_email": "rohith.donthula@cerner.com",
        "purpose": "Read patient demographics and lab results from EMR for clinical decision support",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
        "allowed_tools": ["mcp://emr/patient/read", "mcp://emr/labs/query"],
        "allowed_resources": ["emr:patients:demographics:*", "emr:patients:labs:*"],
        "max_delegation_depth": 1,
        "credential_ttl_seconds": 900,
        "anomaly_threshold": -0.3,
        "compliance_tags": ["HIPAA"],
    }


@pytest.fixture
def sample_policy_request():
    """Valid policy decision request."""
    return {
        "agent_id": str(uuid.uuid4()),
        "action": "tool_call",
        "resource": "emr:patients:demographics:12345",
        "tool_uri": "mcp://emr/patient/read",
        "delegation_depth": 0,
    }
