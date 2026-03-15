"""Tests for OPA Policy Engine."""

import pytest
from unittest.mock import AsyncMock, patch
from policy.opa_client import OPAClient


@pytest.mark.asyncio
async def test_local_fallback_allow():
    """Test local fallback policy allows valid agent action."""
    client = OPAClient()

    input_data = {
        "agent_id": "test-agent",
        "action": "tool_call",
        "resource": "emr:patients:demographics:123",
        "tool_uri": "mcp://emr/patient/read",
        "delegation_depth": 0,
        "session_token_claims": {},
        "agent_record": {
            "status": "active",
            "allowed_tools": ["mcp://emr/patient/read", "mcp://emr/labs/query"],
            "allowed_resources": ["emr:patients:demographics:*"],
            "max_delegation_depth": 1,
            "compliance_tags": ["HIPAA"],
        },
    }

    result = client._evaluate_local_fallback(input_data)
    assert result["allow"] is True
    assert result["reason"] == "all_checks_passed"
    assert "HIPAA" in result["compliance_flags"]


@pytest.mark.asyncio
async def test_local_fallback_deny_inactive_agent():
    """Test local fallback denies inactive agent."""
    client = OPAClient()

    input_data = {
        "agent_id": "test-agent",
        "action": "tool_call",
        "resource": "emr:patients:demographics:123",
        "tool_uri": "mcp://emr/patient/read",
        "delegation_depth": 0,
        "session_token_claims": {},
        "agent_record": {
            "status": "suspended",
            "allowed_tools": ["mcp://emr/patient/read"],
            "allowed_resources": ["emr:patients:*"],
            "max_delegation_depth": 0,
        },
    }

    result = client._evaluate_local_fallback(input_data)
    assert result["allow"] is False
    assert "not active" in result["denied_reasons"][0].lower() or "suspended" in result["denied_reasons"][0].lower()


@pytest.mark.asyncio
async def test_local_fallback_deny_tool_not_in_allowlist():
    """Test local fallback denies tool not in allowlist."""
    client = OPAClient()

    input_data = {
        "agent_id": "test-agent",
        "action": "tool_call",
        "resource": "emr:patients:demographics:123",
        "tool_uri": "mcp://emr/prescriptions/write",
        "delegation_depth": 0,
        "session_token_claims": {},
        "agent_record": {
            "status": "active",
            "allowed_tools": ["mcp://emr/patient/read"],
            "allowed_resources": ["emr:patients:*"],
            "max_delegation_depth": 0,
        },
    }

    result = client._evaluate_local_fallback(input_data)
    assert result["allow"] is False
    assert any("not in" in r.lower() or "allowlist" in r.lower() for r in result["denied_reasons"])


@pytest.mark.asyncio
async def test_resource_pattern_matching():
    """Test glob-style resource pattern matching."""
    client = OPAClient()

    # Wildcard match
    assert client._match_resource_pattern("emr:patients:demographics:123", "emr:patients:*") is True

    # Exact match
    assert client._match_resource_pattern("emr:patients:labs", "emr:patients:labs") is True

    # No match
    assert client._match_resource_pattern("billing:invoices:123", "emr:patients:*") is False

    # Global wildcard
    assert client._match_resource_pattern("anything:goes:here", "*") is True
