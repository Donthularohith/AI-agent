"""
Alert Engine — Threshold Evaluation + Alert Generation

Evaluates anomaly scores against thresholds and generates structured
alerts for the SOC dashboard and Splunk integration.

Rohith: These alerts follow the same structure as CrowdStrike detections —
severity, confidence, context, and recommended actions. They're designed
to integrate into your existing SOC workflow.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


class AlertEngine:
    """
    Generates and manages anomaly alerts for the SOC.

    Alerts include severity classification, feature analysis,
    and recommended response actions.
    """

    def __init__(self):
        # In-memory alert store (production would use Redis or Kafka)
        self._alerts: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._max_alerts_per_agent = 100

    async def generate_alert(
        self,
        agent_id: str,
        anomaly_score: float,
        threshold: float,
        feature_vector: Dict[str, float],
        action: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generate a structured anomaly alert.

        Severity classification:
        - CRITICAL: score < -0.7 (extreme deviation from baseline)
        - HIGH: score < -0.5 (significant deviation)
        - MEDIUM: score < -0.3 (moderate deviation)
        - LOW: score < threshold (any deviation)
        """
        severity = self._classify_severity(anomaly_score)
        contributing_features = self._identify_contributing_features(feature_vector)
        recommended_actions = self._generate_recommendations(
            severity, contributing_features, feature_vector
        )

        alert = {
            "alert_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "anomaly_score": anomaly_score,
            "threshold": threshold,
            "severity": severity,
            "contributing_features": contributing_features,
            "feature_vector": feature_vector,
            "action_context": {
                "action_type": action.get("action_type"),
                "tool_uri": action.get("tool_uri"),
                "resource": action.get("resource"),
            },
            "recommended_actions": recommended_actions,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "open",
        }

        # Store alert (FIFO per agent)
        self._alerts[agent_id].append(alert)
        if len(self._alerts[agent_id]) > self._max_alerts_per_agent:
            self._alerts[agent_id] = self._alerts[agent_id][-self._max_alerts_per_agent:]

        logger.warning(
            f"Alert generated for agent {agent_id}: "
            f"severity={severity}, score={anomaly_score:.3f}"
        )

        return alert

    def _classify_severity(self, anomaly_score: float) -> str:
        """Classify alert severity based on anomaly score."""
        if anomaly_score < -0.7:
            return "CRITICAL"
        elif anomaly_score < -0.5:
            return "HIGH"
        elif anomaly_score < -0.3:
            return "MEDIUM"
        else:
            return "LOW"

    def _identify_contributing_features(
        self,
        feature_vector: Dict[str, float],
    ) -> List[Dict[str, Any]]:
        """
        Identify which features contributed most to the anomaly.
        Returns top 3 features by deviation significance.
        """
        # Define normal baseline ranges for each feature
        normal_ranges = {
            "tool_call_count": (0, 30),
            "unique_resource_count": (0, 10),
            "out_of_hours_flag": (0, 0),
            "new_tool_flag": (0, 0),
            "resource_entropy": (0, 2.0),
            "delegation_spawns": (0, 1),
            "failed_auth_count": (0, 1),
            "data_volume_bytes": (0, 10_000_000),
            "api_error_rate": (0, 0.05),
            "cross_tenant_flag": (0, 0),
            "privilege_escalation_attempts": (0, 0),
            "time_since_last_activity": (0, 600),
        }

        deviations = []
        for feature_name, value in feature_vector.items():
            low, high = normal_ranges.get(feature_name, (0, 1))
            range_size = max(high - low, 0.001)

            if value > high:
                deviation = (value - high) / range_size
                deviations.append({
                    "feature": feature_name,
                    "value": value,
                    "normal_range": f"{low}-{high}",
                    "deviation": f"+{deviation:.1f}x above normal",
                    "significance": deviation,
                })
            elif value < low and low > 0:
                deviation = (low - value) / range_size
                deviations.append({
                    "feature": feature_name,
                    "value": value,
                    "normal_range": f"{low}-{high}",
                    "deviation": f"-{deviation:.1f}x below normal",
                    "significance": deviation,
                })
            elif feature_name in ("out_of_hours_flag", "new_tool_flag", "cross_tenant_flag") and value > 0:
                deviations.append({
                    "feature": feature_name,
                    "value": value,
                    "normal_range": "0",
                    "deviation": "Flag triggered",
                    "significance": 2.0,
                })

        # Sort by significance and return top 3
        deviations.sort(key=lambda x: x.get("significance", 0), reverse=True)
        return deviations[:3]

    def _generate_recommendations(
        self,
        severity: str,
        contributing_features: List[Dict],
        feature_vector: Dict[str, float],
    ) -> List[str]:
        """
        Generate actionable recommendations based on alert context.
        Maps to SOC runbook actions.
        """
        recommendations = []

        if severity in ("CRITICAL", "HIGH"):
            recommendations.append(
                "IMMEDIATE: Consider suspending the agent via POST /agents/{id}/suspend"
            )

        for feature_info in contributing_features:
            fname = feature_info.get("feature")
            if fname == "failed_auth_count":
                recommendations.append(
                    "Investigate credential status — possible credential stuffing or expired token"
                )
            elif fname == "out_of_hours_flag":
                recommendations.append(
                    "Agent active outside business hours — verify with owner if expected"
                )
            elif fname == "new_tool_flag":
                recommendations.append(
                    "Agent calling new tool for the first time — verify tool is legitimate"
                )
            elif fname == "cross_tenant_flag":
                recommendations.append(
                    "Cross-tenant access detected — possible lateral movement attempt"
                )
            elif fname == "privilege_escalation_attempts":
                recommendations.append(
                    "Privilege escalation indicators detected — review tool_uri and resource access"
                )
            elif fname == "resource_entropy":
                recommendations.append(
                    "High resource entropy indicates scanning behavior — check for reconnaissance"
                )
            elif fname == "delegation_spawns":
                recommendations.append(
                    "Multiple child agents spawned — check delegation chain for amplification attack"
                )
            elif fname == "data_volume_bytes":
                recommendations.append(
                    "Unusual data volume — potential exfiltration. Check resource access patterns"
                )

        if not recommendations:
            recommendations.append(
                "Review agent audit trail for context and verify behavior with agent owner"
            )

        return recommendations

    def get_recent_alerts(
        self,
        agent_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Get recent alerts, optionally filtered by agent."""
        if agent_id:
            alerts = self._alerts.get(agent_id, [])
            return sorted(alerts, key=lambda a: a["timestamp"], reverse=True)[:limit]

        # All agents
        all_alerts = []
        for agent_alerts in self._alerts.values():
            all_alerts.extend(agent_alerts)
        return sorted(all_alerts, key=lambda a: a["timestamp"], reverse=True)[:limit]

    def get_alert_counts(self) -> Dict[str, int]:
        """Get alert counts per agent — for dashboard display."""
        return {
            agent_id: len(alerts)
            for agent_id, alerts in self._alerts.items()
        }


# Module-level singleton
alert_engine = AlertEngine()
