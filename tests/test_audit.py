"""Tests for Audit Logging — Event recording and Splunk integration."""

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch
from audit.audit_logger import AuditLogger
from audit.splunk_client import SplunkHECClient


@pytest.mark.asyncio
async def test_audit_log_action():
    """Test audit action logging."""
    logger = AuditLogger()
    logger._splunk = AsyncMock()

    record = await logger.log_action(
        agent_id="test-agent-123",
        action_type="tool_call",
        outcome="success",
        tool_uri="mcp://emr/patient/read",
        resource="emr:patients:demographics:456",
        human_owner="rohith@cerner.com",
    )

    assert record["agent_id"] == "test-agent-123"
    assert record["action_type"] == "tool_call"
    assert record["outcome"] == "success"
    assert "timestamp_utc" in record
    assert "session_id" in record


@pytest.mark.asyncio
async def test_audit_credential_event():
    """Test credential lifecycle event logging."""
    logger = AuditLogger()
    logger._splunk = AsyncMock()

    record = await logger.log_credential_event(
        agent_id="test-agent-123",
        event_type="issue",
        credential_id="cred-abc123",
        human_owner="rohith@cerner.com",
    )

    assert record["action_type"] == "credential_issue"
    assert record["outcome"] == "success"


@pytest.mark.asyncio
async def test_audit_anomaly_alert():
    """Test anomaly alert logging includes severity and features."""
    logger = AuditLogger()
    logger._splunk = AsyncMock()

    record = await logger.log_anomaly_alert(
        agent_id="suspicious-agent",
        anomaly_score=-0.65,
        feature_vector={"tool_call_count": 100, "failed_auth_count": 15},
        severity="HIGH",
    )

    assert record["action_type"] == "anomaly_alert"
    assert record["anomaly_score"] == -0.65
    assert record["metadata_extra"]["severity"] == "HIGH"


class TestSplunkHECClient:
    """Tests for Splunk HEC client."""

    @pytest.mark.asyncio
    async def test_event_batching(self):
        """Test events are batched before sending."""
        client = SplunkHECClient()
        client._enabled = True
        client.batch_size = 5

        # Add 3 events (below batch threshold)
        for i in range(3):
            await client.send_event({"test": f"event_{i}"})

        assert len(client._batch) == 3

    @pytest.mark.asyncio
    async def test_disabled_client_ignores_events(self):
        """Test disabled HEC client does not accumulate events."""
        client = SplunkHECClient()
        client._enabled = False

        await client.send_event({"test": "should_be_ignored"})
        assert len(client._batch) == 0

    def test_stats_tracking(self):
        """Test HEC client statistics."""
        client = SplunkHECClient()
        stats = client.get_stats()

        assert "events_sent" in stats
        assert "events_failed" in stats
        assert "pending_events" in stats
        assert stats["pending_events"] == 0
