"""
Behavioral Monitor — Feature Extraction + Isolation Forest Scoring

Orchestrates the full behavioral monitoring pipeline:
1. Extract 12-feature vector from agent action context
2. Score against per-agent Isolation Forest baseline
3. Generate anomaly alerts when score exceeds threshold

Rohith: This is the UEBA (User Entity Behavior Analytics) engine for agents.
Like Splunk UBA baselines user behavior, this baselines each agent's
operational pattern to detect compromised or malfunctioning agents.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from monitoring.feature_extractor import feature_extractor
from monitoring.baseline_trainer import baseline_trainer
from monitoring.alert_engine import alert_engine

logger = logging.getLogger(__name__)


class BehavioralMonitor:
    """
    Central behavioral monitoring service.

    Processes every agent action through the feature extraction and
    anomaly scoring pipeline. Generates alerts for the SOC dashboard
    and Splunk integration.
    """

    def __init__(self):
        self._feature_extractor = feature_extractor
        self._baseline_trainer = baseline_trainer
        self._alert_engine = alert_engine

    async def process_action(
        self,
        agent_id: str,
        action: Dict[str, Any],
        recent_actions: List[Dict[str, Any]],
        anomaly_threshold: float = -0.3,
    ) -> Dict[str, Any]:
        """
        Process an agent action through the behavioral monitoring pipeline.

        Args:
            agent_id: Agent UUID string
            action: Current action being performed
            recent_actions: Recent actions from the last 5 minutes
            anomaly_threshold: Agent-specific anomaly score threshold

        Returns:
            Monitoring result with anomaly score and alert status
        """
        # Step 1: Extract 12-feature behavioral vector
        features = self._feature_extractor.extract_features(
            agent_id=agent_id,
            recent_actions=recent_actions,
            current_action=action,
        )
        feature_vector = self._feature_extractor.features_to_vector(features)

        # Step 2: Score against baseline model
        anomaly_score = self._baseline_trainer.score_action(
            agent_id=agent_id,
            feature_vector=feature_vector,
        )

        # Step 3: Evaluate threshold and generate alert if needed
        is_anomalous = False
        alert_info = None

        if anomaly_score is not None and anomaly_score < anomaly_threshold:
            is_anomalous = True
            alert_info = await self._alert_engine.generate_alert(
                agent_id=agent_id,
                anomaly_score=anomaly_score,
                threshold=anomaly_threshold,
                feature_vector=features,
                action=action,
            )
            logger.warning(
                f"ANOMALY DETECTED — Agent {agent_id}: "
                f"score={anomaly_score:.3f} (threshold={anomaly_threshold})"
            )

        # Build monitoring result
        result = {
            "agent_id": agent_id,
            "anomaly_score": anomaly_score,
            "is_anomalous": is_anomalous,
            "feature_vector": features,
            "threshold": anomaly_threshold,
            "model_status": self._get_model_status(agent_id),
            "alert": alert_info,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.debug(
            f"Behavioral score for agent {agent_id}: "
            f"score={anomaly_score}, anomalous={is_anomalous}"
        )

        return result

    def _get_model_status(self, agent_id: str) -> str:
        """Get the current model status for an agent."""
        if self._baseline_trainer.has_model(agent_id):
            return "trained"
        progress = self._baseline_trainer.get_training_progress(agent_id)
        if progress["buffer_size"] > 0:
            return f"training ({progress['buffer_size']}/{progress['training_threshold']})"
        return "no_data"

    def get_agent_profile(self, agent_id: str) -> Dict[str, Any]:
        """
        Get the complete behavioral profile for an agent.
        Used by the SOC dashboard for agent investigation.
        """
        return {
            "agent_id": agent_id,
            "training_progress": self._baseline_trainer.get_training_progress(agent_id),
            "recent_alerts": self._alert_engine.get_recent_alerts(agent_id),
        }


# Module-level singleton
behavioral_monitor = BehavioralMonitor()
