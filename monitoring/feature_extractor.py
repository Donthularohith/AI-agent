"""
Feature Extractor — Compute 12-Feature Behavioral Vector

Extracts features from an agent's recent actions within a 5-minute
rolling window. These features feed the Isolation Forest anomaly detector.

Rohith: These features map to SIEM correlation logic — each one is an
indicator that, when combined, reveals behavioral patterns. Think of this
as building a Splunk data model for agent behavior analytics.

Feature Vector (Section 3.5):
1.  tool_call_count        — Volume indicator
2.  unique_resource_count  — Breadth of access
3.  out_of_hours_flag      — Temporal anomaly
4.  new_tool_flag          — Tool discovery/probing
5.  resource_entropy       — Access distribution (scanning indicator)
6.  delegation_spawns      — Delegation amplification
7.  failed_auth_count      — Credential stuffing/probing
8.  data_volume_bytes      — Exfiltration indicator
9.  api_error_rate         — Probing/malfunctioning
10. cross_tenant_flag      — Lateral movement
11. privilege_escalation_attempts — Vertical escalation
12. time_since_last_activity     — Dormancy indicator
"""

import math
import logging
from datetime import datetime, timezone, time as dt_time
from typing import List, Dict, Any, Optional, Set
from collections import Counter

logger = logging.getLogger(__name__)

# Business hours definition (Eastern Time — Cerner NJ office)
BUSINESS_HOURS_START = dt_time(9, 0)  # 9 AM
BUSINESS_HOURS_END = dt_time(18, 0)   # 6 PM


class FeatureExtractor:
    """
    Extracts the 12-feature behavioral vector for anomaly detection.

    Each agent maintains a history of known tools, and the extractor
    computes rolling window features from recent audit log entries.
    """

    def __init__(self):
        # Track known tools per agent for new_tool_flag detection
        self._known_tools: Dict[str, Set[str]] = {}
        # Track last activity timestamp per agent
        self._last_activity: Dict[str, datetime] = {}

    def extract_features(
        self,
        agent_id: str,
        recent_actions: List[Dict[str, Any]],
        current_action: Dict[str, Any],
    ) -> Dict[str, float]:
        """
        Compute the 12-feature vector for an agent's current behavioral window.

        Args:
            agent_id: Agent UUID string
            recent_actions: List of audit log entries from the last 5 minutes
            current_action: The current action being evaluated

        Returns:
            Dict with all 12 named features
        """
        all_actions = recent_actions + [current_action]

        features = {
            "tool_call_count": self._compute_tool_call_count(all_actions),
            "unique_resource_count": self._compute_unique_resource_count(all_actions),
            "out_of_hours_flag": self._compute_out_of_hours(current_action),
            "new_tool_flag": self._compute_new_tool_flag(agent_id, current_action),
            "resource_entropy": self._compute_resource_entropy(all_actions),
            "delegation_spawns": self._compute_delegation_spawns(all_actions),
            "failed_auth_count": self._compute_failed_auth_count(all_actions),
            "data_volume_bytes": self._compute_data_volume(all_actions),
            "api_error_rate": self._compute_api_error_rate(all_actions),
            "cross_tenant_flag": self._compute_cross_tenant_flag(all_actions),
            "privilege_escalation_attempts": self._compute_privilege_escalation(all_actions),
            "time_since_last_activity": self._compute_time_since_last(agent_id, current_action),
        }

        # Update tracking state
        self._update_known_tools(agent_id, current_action)
        self._update_last_activity(agent_id, current_action)

        return features

    def _compute_tool_call_count(self, actions: List[Dict]) -> float:
        """Count of tool calls in the window."""
        return float(
            sum(1 for a in actions if a.get("action_type") == "tool_call")
        )

    def _compute_unique_resource_count(self, actions: List[Dict]) -> float:
        """Count of distinct resources accessed."""
        resources = set()
        for action in actions:
            resource = action.get("resource")
            if resource:
                resources.add(resource)
        return float(len(resources))

    def _compute_out_of_hours(self, current_action: Dict) -> float:
        """1.0 if action is outside business hours (9am-6pm ET)."""
        timestamp = current_action.get("timestamp")
        if not timestamp:
            timestamp = datetime.now(timezone.utc)

        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except ValueError:
                return 0.0

        # Simple business hours check (using UTC, adjust for ET offset)
        action_time = timestamp.time()
        # ET is UTC-4 or UTC-5 depending on DST; approximate with UTC-4
        hour_et = (timestamp.hour - 4) % 24

        if hour_et < BUSINESS_HOURS_START.hour or hour_et >= BUSINESS_HOURS_END.hour:
            return 1.0
        return 0.0

    def _compute_new_tool_flag(self, agent_id: str, current_action: Dict) -> float:
        """1.0 if the agent is calling a tool it has never used before."""
        tool_uri = current_action.get("tool_uri")
        if not tool_uri:
            return 0.0

        known = self._known_tools.get(agent_id, set())
        if tool_uri not in known:
            return 1.0
        return 0.0

    def _compute_resource_entropy(self, actions: List[Dict]) -> float:
        """
        Shannon entropy of resource access distribution.
        High entropy = scanning many different resources (potential reconnaissance).
        """
        resources = [a.get("resource", "unknown") for a in actions if a.get("resource")]
        if len(resources) <= 1:
            return 0.0

        counter = Counter(resources)
        total = len(resources)
        entropy = 0.0

        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    def _compute_delegation_spawns(self, actions: List[Dict]) -> float:
        """Count of delegation/spawn events in the window."""
        return float(
            sum(1 for a in actions if a.get("action_type") in ("delegate", "spawn_child"))
        )

    def _compute_failed_auth_count(self, actions: List[Dict]) -> float:
        """Count of authentication/authorization failures."""
        return float(
            sum(
                1 for a in actions
                if a.get("outcome") == "denied" or a.get("action_type") == "auth_failure"
            )
        )

    def _compute_data_volume(self, actions: List[Dict]) -> float:
        """Estimated data volume accessed/transferred in bytes."""
        total_bytes = 0.0
        for action in actions:
            metadata = action.get("metadata_extra", {}) or {}
            total_bytes += metadata.get("data_volume_bytes", 0)
        return total_bytes

    def _compute_api_error_rate(self, actions: List[Dict]) -> float:
        """Ratio of error responses to total calls."""
        if not actions:
            return 0.0

        errors = sum(1 for a in actions if a.get("outcome") == "error")
        return errors / len(actions)

    def _compute_cross_tenant_flag(self, actions: List[Dict]) -> float:
        """1.0 if agent accessed resources in a different tenant/org."""
        tenants = set()
        for action in actions:
            resource = action.get("resource", "")
            if ":" in resource:
                # Extract tenant from resource pattern (first segment)
                tenant = resource.split(":")[0]
                tenants.add(tenant)

        # If more than one unique tenant prefix, flag it
        return 1.0 if len(tenants) > 1 else 0.0

    def _compute_privilege_escalation(self, actions: List[Dict]) -> float:
        """Count of requests for higher-privilege resources or admin tools."""
        escalation_indicators = [
            "admin", "write", "delete", "escalat", "root", "sudo", "privilege"
        ]
        count = 0
        for action in actions:
            resource = (action.get("resource") or "").lower()
            tool_uri = (action.get("tool_uri") or "").lower()
            for indicator in escalation_indicators:
                if indicator in resource or indicator in tool_uri:
                    count += 1
                    break
        return float(count)

    def _compute_time_since_last(self, agent_id: str, current_action: Dict) -> float:
        """Seconds since the agent's previous action."""
        last = self._last_activity.get(agent_id)
        if not last:
            return 0.0

        current_ts = current_action.get("timestamp")
        if not current_ts:
            current_ts = datetime.now(timezone.utc)

        if isinstance(current_ts, str):
            try:
                current_ts = datetime.fromisoformat(current_ts)
            except ValueError:
                return 0.0

        if isinstance(last, str):
            try:
                last = datetime.fromisoformat(last)
            except ValueError:
                return 0.0

        # Ensure both are timezone-aware
        if current_ts.tzinfo is None:
            current_ts = current_ts.replace(tzinfo=timezone.utc)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)

        delta = (current_ts - last).total_seconds()
        return max(0.0, delta)

    def _update_known_tools(self, agent_id: str, action: Dict) -> None:
        """Track tools this agent has used."""
        tool_uri = action.get("tool_uri")
        if tool_uri:
            if agent_id not in self._known_tools:
                self._known_tools[agent_id] = set()
            self._known_tools[agent_id].add(tool_uri)

    def _update_last_activity(self, agent_id: str, action: Dict) -> None:
        """Update last activity timestamp."""
        timestamp = action.get("timestamp")
        if not timestamp:
            timestamp = datetime.now(timezone.utc)
        self._last_activity[agent_id] = timestamp

    def get_feature_names(self) -> List[str]:
        """Return ordered list of feature names for model training."""
        return [
            "tool_call_count",
            "unique_resource_count",
            "out_of_hours_flag",
            "new_tool_flag",
            "resource_entropy",
            "delegation_spawns",
            "failed_auth_count",
            "data_volume_bytes",
            "api_error_rate",
            "cross_tenant_flag",
            "privilege_escalation_attempts",
            "time_since_last_activity",
        ]

    def features_to_vector(self, features: Dict[str, float]) -> List[float]:
        """Convert named feature dict to ordered vector for ML model."""
        return [features[name] for name in self.get_feature_names()]


# Module-level singleton
feature_extractor = FeatureExtractor()
