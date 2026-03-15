"""Tests for Enforcement — Circuit Breaker, MCP Interceptor, Delegation Chain."""

import pytest
from enforcement.circuit_breaker import CircuitBreaker
from enforcement.delegation_chain import DelegationChainValidator


class TestCircuitBreaker:
    """Tests for the sliding window circuit breaker."""

    def test_initial_state_closed(self):
        """Circuit breaker starts in closed state."""
        cb = CircuitBreaker(threshold=5, window_seconds=60)
        assert cb.is_tripped("test-agent") is False
        assert cb.get_status("test-agent") == "CLOSED"

    def test_trips_at_threshold(self):
        """Circuit breaker trips when threshold is reached."""
        cb = CircuitBreaker(threshold=3, window_seconds=60)

        assert cb.record_denial("agent-1") is False  # 1/3
        assert cb.record_denial("agent-1") is False  # 2/3
        assert cb.record_denial("agent-1") is True   # 3/3 - TRIPPED

        assert cb.is_tripped("agent-1") is True
        assert cb.get_status("agent-1") == "OPEN"

    def test_reset_clears_state(self):
        """Reset clears the circuit breaker."""
        cb = CircuitBreaker(threshold=2, window_seconds=60)

        cb.record_denial("agent-1")
        cb.record_denial("agent-1")

        assert cb.is_tripped("agent-1") is True

        cb.reset("agent-1")
        assert cb.is_tripped("agent-1") is False
        assert cb.get_denial_count("agent-1") == 0

    def test_per_agent_isolation(self):
        """Circuit breaker state is per-agent."""
        cb = CircuitBreaker(threshold=2, window_seconds=60)

        cb.record_denial("agent-1")
        cb.record_denial("agent-1")  # Trips agent-1

        assert cb.is_tripped("agent-1") is True
        assert cb.is_tripped("agent-2") is False  # agent-2 unaffected

    def test_trip_info_includes_details(self):
        """Trip info includes denial count and timeline."""
        cb = CircuitBreaker(threshold=2, window_seconds=60)

        cb.record_denial("agent-1", "tool_not_allowed")
        cb.record_denial("agent-1", "resource_denied")

        trip_info = cb.get_trip_info("agent-1")
        assert trip_info is not None
        assert trip_info["denial_count"] == 2
        assert len(trip_info["recent_denials"]) == 2


class TestDelegationChain:
    """Tests for delegation chain validation."""

    def test_valid_delegation(self):
        """Test valid child agent delegation."""
        validator = DelegationChainValidator()

        parent = {
            "agent_id": "parent-id",
            "status": "active",
            "allowed_tools": ["mcp://emr/patient/read", "mcp://emr/labs/query"],
            "allowed_resources": ["emr:patients:*"],
            "max_delegation_depth": 2,
            "credential_ttl_seconds": 900,
        }

        child = {
            "allowed_tools": ["mcp://emr/patient/read"],  # Subset
            "allowed_resources": ["emr:patients:demographics:*"],  # Narrower scope
            "max_delegation_depth": 1,  # Decremented
            "credential_ttl_seconds": 600,  # Less than parent
        }

        is_valid, violations = validator.validate_delegation(parent, child)
        assert is_valid is True
        assert len(violations) == 0

    def test_reject_scope_escalation(self):
        """Test that scope escalation is rejected."""
        validator = DelegationChainValidator()

        parent = {
            "agent_id": "parent-id",
            "status": "active",
            "allowed_tools": ["mcp://emr/patient/read"],
            "allowed_resources": ["emr:patients:demographics:*"],
            "max_delegation_depth": 2,
            "credential_ttl_seconds": 900,
        }

        child = {
            "allowed_tools": ["mcp://emr/patient/read", "mcp://emr/prescriptions/write"],  # Exceeds parent
            "allowed_resources": ["emr:patients:*"],  # Broader than parent
            "max_delegation_depth": 1,
            "credential_ttl_seconds": 600,
        }

        is_valid, violations = validator.validate_delegation(parent, child)
        assert is_valid is False
        assert len(violations) > 0

    def test_reject_inactive_parent(self):
        """Test that suspended parent cannot delegate."""
        validator = DelegationChainValidator()

        parent = {
            "agent_id": "parent-id",
            "status": "suspended",
            "allowed_tools": ["mcp://emr/patient/read"],
            "allowed_resources": ["emr:patients:*"],
            "max_delegation_depth": 2,
            "credential_ttl_seconds": 900,
        }

        child = {
            "allowed_tools": ["mcp://emr/patient/read"],
            "allowed_resources": ["emr:patients:demographics:*"],
            "max_delegation_depth": 1,
            "credential_ttl_seconds": 600,
        }

        is_valid, violations = validator.validate_delegation(parent, child)
        assert is_valid is False
        assert any("active" in v.lower() for v in violations)

    def test_blast_radius_estimation(self):
        """Test blast radius impact assessment."""
        validator = DelegationChainValidator()

        agent = {
            "agent_id": "compromised-agent",
            "allowed_tools": ["mcp://emr/patient/read", "mcp://emr/admin/write"],
            "allowed_resources": ["emr:patients:demographics:*", "emr:patients:labs:*"],
            "compliance_tags": ["HIPAA"],
            "max_delegation_depth": 2,
        }

        children = [
            {
                "allowed_tools": ["mcp://emr/patient/read"],
                "allowed_resources": ["emr:patients:demographics:*"],
            }
        ]

        blast = validator.estimate_blast_radius(agent, children)
        assert blast["total_accessible_resources"] >= 2
        assert blast["total_accessible_tools"] >= 2
        assert blast["child_agent_count"] == 1
        assert len(blast["hipaa_sensitive_resources"]) > 0
        assert blast["estimated_risk_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
