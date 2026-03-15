"""Tests for Behavioral Monitoring — Feature Extraction & Anomaly Detection."""

import pytest
import numpy as np
from datetime import datetime, timezone

from monitoring.feature_extractor import FeatureExtractor
from monitoring.baseline_trainer import BaselineTrainer


class TestFeatureExtractor:
    """Tests for the 12-feature behavioral vector extractor."""

    def test_extract_all_12_features(self):
        """Test that all 12 features are extracted."""
        extractor = FeatureExtractor()

        recent_actions = [
            {
                "action_type": "tool_call",
                "tool_uri": "mcp://emr/patient/read",
                "resource": "emr:patients:demographics:123",
                "outcome": "success",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ]

        current_action = {
            "action_type": "tool_call",
            "tool_uri": "mcp://emr/patient/read",
            "resource": "emr:patients:demographics:456",
            "outcome": "success",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        features = extractor.extract_features("test-agent", recent_actions, current_action)

        # Verify all 12 features present
        expected_features = extractor.get_feature_names()
        assert len(features) == 12
        for name in expected_features:
            assert name in features

    def test_tool_call_count(self):
        """Test tool_call_count feature."""
        extractor = FeatureExtractor()

        actions = [
            {"action_type": "tool_call", "timestamp": datetime.now(timezone.utc).isoformat()},
            {"action_type": "tool_call", "timestamp": datetime.now(timezone.utc).isoformat()},
            {"action_type": "credential_issue", "timestamp": datetime.now(timezone.utc).isoformat()},
        ]
        current = {"action_type": "tool_call", "timestamp": datetime.now(timezone.utc).isoformat()}

        features = extractor.extract_features("test", actions, current)
        assert features["tool_call_count"] == 3.0  # 2 from recent + 1 current

    def test_failed_auth_detection(self):
        """Test failed_auth_count feature detects denials."""
        extractor = FeatureExtractor()

        actions = [
            {"action_type": "tool_call", "outcome": "denied", "timestamp": datetime.now(timezone.utc).isoformat()},
            {"action_type": "tool_call", "outcome": "denied", "timestamp": datetime.now(timezone.utc).isoformat()},
            {"action_type": "tool_call", "outcome": "success", "timestamp": datetime.now(timezone.utc).isoformat()},
        ]
        current = {"action_type": "tool_call", "outcome": "denied", "timestamp": datetime.now(timezone.utc).isoformat()}

        features = extractor.extract_features("test", actions, current)
        assert features["failed_auth_count"] == 3.0

    def test_resource_entropy_calculation(self):
        """Test Shannon entropy of resource access."""
        extractor = FeatureExtractor()

        # High entropy (many different resources)
        actions = [
            {"resource": f"emr:patients:record:{i}", "timestamp": datetime.now(timezone.utc).isoformat()}
            for i in range(10)
        ]
        current = {"resource": "emr:patients:record:11", "timestamp": datetime.now(timezone.utc).isoformat()}

        features = extractor.extract_features("test", actions, current)
        assert features["resource_entropy"] > 0  # Should have positive entropy


class TestBaselineTrainer:
    """Tests for Isolation Forest baseline training."""

    def test_add_training_samples(self):
        """Test training buffer accumulation."""
        trainer = BaselineTrainer()

        # Add samples below threshold
        for i in range(50):
            vector = [float(i) for _ in range(12)]
            result = trainer.add_training_sample("test-agent", vector)
            assert result is None  # Not enough samples yet

        progress = trainer.get_training_progress("test-agent")
        assert progress["buffer_size"] == 50
        assert progress["has_model"] is False

    def test_model_training_triggers(self):
        """Test that model training triggers at threshold."""
        trainer = BaselineTrainer()

        # Add exactly BASELINE_TRAINING_MIN samples
        for i in range(100):
            vector = [float(np.random.normal(5, 1)) for _ in range(12)]
            result = trainer.add_training_sample("test-agent", vector)

        # Model should be trained after 100 samples
        assert trainer.has_model("test-agent") is True

    def test_anomaly_scoring(self):
        """Test that trained model can score new actions."""
        trainer = BaselineTrainer()

        # Train with normal data
        for _ in range(100):
            vector = [float(np.random.normal(5, 1)) for _ in range(12)]
            trainer.add_training_sample("test-agent", vector)

        # Score a normal action
        normal_vector = [5.0] * 12
        score = trainer.score_action("test-agent", normal_vector)
        assert score is not None

        # Score an anomalous action (extreme values)
        anomalous_vector = [100.0, 50.0, 1.0, 1.0, 5.0, 10.0, 20.0, 99999999.0, 0.9, 1.0, 15.0, 0.0]
        anomaly_score = trainer.score_action("test-agent", anomalous_vector)
        assert anomaly_score is not None
        # Anomalous actions should generally score lower
        assert anomaly_score < score
