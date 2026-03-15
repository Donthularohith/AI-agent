"""Tests for Credential Management."""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

from credentials.token_manager import TokenManager


@pytest.mark.asyncio
async def test_token_manager_issue(mock_vault):
    """Test token issuance via token manager."""
    manager = TokenManager()
    manager._vault = mock_vault

    credential = await manager.issue_token(
        agent_id="test-agent-123",
        ttl_seconds=900,
        scoped_resources=["emr:patients:*"],
        purpose="Test agent",
    )

    assert "credential_id" in credential
    assert credential["ttl_seconds"] == 900
    assert credential["status"] == "active"
    mock_vault.issue_credential.assert_called_once()


@pytest.mark.asyncio
async def test_token_manager_revoke(mock_vault):
    """Test token revocation."""
    manager = TokenManager()
    manager._vault = mock_vault

    result = await manager.revoke_token("test-agent-123")
    assert result is True
    mock_vault.revoke_credential.assert_called_once_with("test-agent-123")


@pytest.mark.asyncio
async def test_token_expiry_check():
    """Test token expiry detection."""
    manager = TokenManager()

    # Simulate an expired credential
    manager._active_credentials["expired-agent"] = {
        "credential_id": "cred-expired",
        "expires_at": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
        "ttl_seconds": 900,
    }

    status = manager.check_token_expiry("expired-agent")
    assert status is not None
    assert status["status"] == "expired"


@pytest.mark.asyncio
async def test_token_needs_rotation():
    """Test detection of credential needing rotation."""
    manager = TokenManager()

    # Credential with < 30 seconds remaining
    manager._active_credentials["nearly-expired"] = {
        "credential_id": "cred-near",
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=15)).isoformat(),
        "ttl_seconds": 900,
    }

    status = manager.check_token_expiry("nearly-expired")
    assert status is not None
    assert status["status"] == "needs_rotation"
