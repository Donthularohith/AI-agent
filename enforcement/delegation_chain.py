"""
Delegation Chain Validator — Parent→Child Scope Reduction Enforcement

Validates that child agents never inherit more scope than their parent.
Enforces max_delegation_depth limits and ensures scope is strictly reduced
at each delegation level.

Rohith: This prevents the "credential chain explosion" attack where a
compromised agent spawns child agents to amplify its effective scope.
MITRE ATT&CK: T1078 (Valid Accounts) + T1134 (Access Token Manipulation).
"""

import logging
import fnmatch
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DelegationChainValidator:
    """
    Validates delegation chain constraints for child agent creation.

    Rules:
    1. Parent must have delegation rights (max_delegation_depth > 0)
    2. Child's tools must be a strict subset of parent's tools
    3. Child's resources must be within parent's resource scope
    4. Child's max_delegation_depth = parent's - 1
    5. Parent must be active
    """

    def validate_delegation(
        self,
        parent_record: Dict[str, Any],
        child_request: Dict[str, Any],
    ) -> Tuple[bool, List[str]]:
        """
        Validate a delegation (child agent creation) request.

        Args:
            parent_record: Parent agent's full record from registry
            child_request: Requested child agent configuration

        Returns:
            (is_valid, list_of_violation_reasons)
        """
        violations = []

        # Rule 1: Parent must be active
        if parent_record.get("status") != "active":
            violations.append(
                f"Parent agent status is '{parent_record.get('status')}', "
                f"must be 'active' to delegate"
            )

        # Rule 2: Parent must have delegation rights remaining
        parent_max_depth = parent_record.get("max_delegation_depth", 0)
        if parent_max_depth <= 0:
            violations.append(
                "Parent agent has max_delegation_depth=0, cannot create child agents"
            )

        # Rule 3: Child's delegation depth must be decremented
        requested_depth = child_request.get("max_delegation_depth", 0)
        if requested_depth >= parent_max_depth:
            violations.append(
                f"Child max_delegation_depth ({requested_depth}) must be less than "
                f"parent ({parent_max_depth})"
            )

        # Rule 4: Child's tools must be a subset of parent's tools
        parent_tools = set(parent_record.get("allowed_tools", []))
        child_tools = set(child_request.get("allowed_tools", []))
        tool_excess = child_tools - parent_tools
        if tool_excess:
            violations.append(
                f"Child requests tools not in parent's allowlist: {list(tool_excess)}"
            )

        # Rule 5: Child's resources must be within parent's scope
        parent_resources = parent_record.get("allowed_resources", [])
        child_resources = child_request.get("allowed_resources", [])
        resource_violations = self._check_resource_scope(
            parent_resources, child_resources
        )
        violations.extend(resource_violations)

        # Rule 6: Child's credential TTL cannot exceed parent's
        parent_ttl = parent_record.get("credential_ttl_seconds", 900)
        child_ttl = child_request.get("credential_ttl_seconds", 900)
        if child_ttl > parent_ttl:
            violations.append(
                f"Child credential TTL ({child_ttl}s) cannot exceed "
                f"parent TTL ({parent_ttl}s)"
            )

        is_valid = len(violations) == 0

        if not is_valid:
            logger.warning(
                f"Delegation validation failed for parent "
                f"{parent_record.get('agent_id')}: {violations}"
            )
        else:
            logger.info(
                f"Delegation validated: parent {parent_record.get('agent_id')} "
                f"can create child with requested scope"
            )

        return is_valid, violations

    def _check_resource_scope(
        self,
        parent_resources: List[str],
        child_resources: List[str],
    ) -> List[str]:
        """
        Verify each child resource pattern falls within a parent pattern.
        Uses glob-style matching with the ':' delimiter.
        """
        violations = []

        for child_resource in child_resources:
            is_within_scope = False
            for parent_resource in parent_resources:
                if self._resource_within_scope(child_resource, parent_resource):
                    is_within_scope = True
                    break

            if not is_within_scope:
                violations.append(
                    f"Child resource '{child_resource}' exceeds parent scope. "
                    f"Parent resources: {parent_resources}"
                )

        return violations

    def _resource_within_scope(
        self,
        child_pattern: str,
        parent_pattern: str,
    ) -> bool:
        """
        Check if a child resource pattern is within a parent's scope.

        Examples:
            parent="emr:patients:*", child="emr:patients:demographics:*" -> True
            parent="emr:patients:demographics:*", child="emr:patients:*" -> False (broader)
            parent="emr:*", child="emr:patients:labs:*" -> True
            parent="emr:patients:*", child="billing:*" -> False (different scope)
        """
        # Exact match
        if child_pattern == parent_pattern:
            return True

        # Parent is wildcard-all
        if parent_pattern == "*":
            return True

        # Split into segments
        parent_parts = parent_pattern.split(":")
        child_parts = child_pattern.split(":")

        for i, parent_part in enumerate(parent_parts):
            if parent_part == "*":
                # Parent wildcard covers everything beneath
                return True

            if i >= len(child_parts):
                # Child is shorter (broader) — not within scope
                return False

            if parent_part != child_parts[i]:
                return False

        # If we matched all parent parts and child has more specificity, it's within scope
        return len(child_parts) >= len(parent_parts)

    def compute_effective_scope(
        self,
        parent_record: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Compute the maximum scope a child agent can request from this parent.
        Used by the dashboard for blast-radius assessment.
        """
        parent_depth = parent_record.get("max_delegation_depth", 0)

        return {
            "max_child_tools": parent_record.get("allowed_tools", []),
            "max_child_resources": parent_record.get("allowed_resources", []),
            "max_child_delegation_depth": max(0, parent_depth - 1),
            "max_child_credential_ttl": parent_record.get("credential_ttl_seconds", 900),
            "can_delegate": parent_depth > 0,
            "parent_status": parent_record.get("status"),
        }

    def estimate_blast_radius(
        self,
        agent_record: Dict[str, Any],
        child_agents: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Estimate the blast radius if this agent is compromised.
        Used by the SOC dashboard's Blast Radius tab.
        """
        # Collect all accessible resources (agent + children)
        all_resources = set(agent_record.get("allowed_resources", []))
        all_tools = set(agent_record.get("allowed_tools", []))

        for child in child_agents:
            all_resources.update(child.get("allowed_resources", []))
            all_tools.update(child.get("allowed_tools", []))

        # Estimate data exposure based on resource patterns
        hipaa_resources = [r for r in all_resources if "patient" in r.lower() or "emr" in r.lower()]
        pci_resources = [r for r in all_resources if "payment" in r.lower() or "billing" in r.lower()]

        return {
            "agent_id": agent_record.get("agent_id"),
            "total_accessible_resources": len(all_resources),
            "total_accessible_tools": len(all_tools),
            "child_agent_count": len(child_agents),
            "resource_list": list(all_resources),
            "tool_list": list(all_tools),
            "hipaa_sensitive_resources": hipaa_resources,
            "pci_sensitive_resources": pci_resources,
            "estimated_risk_level": self._estimate_risk_level(
                all_resources, all_tools, child_agents
            ),
            "compliance_impact": self._assess_compliance_impact(
                agent_record, hipaa_resources, pci_resources
            ),
        }

    def _estimate_risk_level(
        self,
        resources: set,
        tools: set,
        children: list,
    ) -> str:
        """Estimate overall risk level."""
        score = 0
        score += len(resources) * 2
        score += len(tools) * 3
        score += len(children) * 5

        if any("write" in t or "admin" in t for t in tools):
            score += 20
        if any("patient" in r or "emr" in r for r in resources):
            score += 15

        if score >= 50:
            return "CRITICAL"
        elif score >= 30:
            return "HIGH"
        elif score >= 15:
            return "MEDIUM"
        else:
            return "LOW"

    def _assess_compliance_impact(
        self,
        agent_record: Dict,
        hipaa_resources: list,
        pci_resources: list,
    ) -> List[str]:
        """Assess compliance framework impact."""
        impacts = []
        tags = agent_record.get("compliance_tags", [])

        if "HIPAA" in tags or hipaa_resources:
            impacts.append("HIPAA: PHI exposure risk — breach notification may be required")
        if "PCI" in tags or pci_resources:
            impacts.append("PCI DSS: Cardholder data exposure risk")
        if "SOX" in tags:
            impacts.append("SOX: Financial reporting data integrity risk")

        return impacts


# Module-level singleton
delegation_validator = DelegationChainValidator()
