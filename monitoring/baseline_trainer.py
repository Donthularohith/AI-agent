"""
Baseline Trainer — Per-Agent Isolation Forest Model Training

Trains and manages per-agent behavioral baselines using scikit-learn
IsolationForest. Each agent gets its own model that learns its normal
operating pattern.

Rohith: This is like building a custom correlation rule per agent in Splunk —
instead of one-size-fits-all thresholds, each agent has its own baseline
that adapts over time.
"""

import os
import logging
import pickle
from pathlib import Path
from typing import Optional, List, Dict

import numpy as np
from sklearn.ensemble import IsolationForest

from monitoring.feature_extractor import feature_extractor

logger = logging.getLogger(__name__)

MODEL_STORAGE_PATH = os.getenv("MODEL_STORAGE_PATH", "/tmp/models")
BASELINE_TRAINING_MIN = int(os.getenv("BASELINE_TRAINING_MIN_ACTIONS", "100"))
RETRAIN_INTERVAL = int(os.getenv("BASELINE_RETRAIN_INTERVAL", "500"))
CONTAMINATION = float(os.getenv("ISOLATION_FOREST_CONTAMINATION", "0.05"))


class BaselineTrainer:
    """
    Manages per-agent Isolation Forest models for behavioral anomaly detection.

    Model lifecycle:
    1. Collect features from first BASELINE_TRAINING_MIN actions (default: 100)
    2. Train initial model
    3. Score all subsequent actions
    4. Retrain every RETRAIN_INTERVAL actions (default: 500)
    """

    def __init__(self):
        self._models_dir = Path(MODEL_STORAGE_PATH)
        self._models_dir.mkdir(parents=True, exist_ok=True)
        # In-memory model cache
        self._models: Dict[str, IsolationForest] = {}
        # Track action counts per agent for retraining
        self._action_counts: Dict[str, int] = {}
        # Buffer training data before initial model fit
        self._training_buffers: Dict[str, List[List[float]]] = {}

    def _model_path(self, agent_id: str) -> Path:
        """Get the file path for an agent's pickled model."""
        return self._models_dir / f"{agent_id}.pkl"

    def load_model(self, agent_id: str) -> Optional[IsolationForest]:
        """Load a trained model from disk or memory cache."""
        if agent_id in self._models:
            return self._models[agent_id]

        model_file = self._model_path(agent_id)
        if model_file.exists():
            try:
                with open(model_file, "rb") as f:
                    model = pickle.load(f)
                self._models[agent_id] = model
                logger.info(f"Loaded model for agent {agent_id} from disk")
                return model
            except Exception as e:
                logger.error(f"Failed to load model for {agent_id}: {e}")
                return None

        return None

    def save_model(self, agent_id: str, model: IsolationForest) -> None:
        """Save a trained model to disk and cache in memory."""
        model_file = self._model_path(agent_id)
        try:
            with open(model_file, "wb") as f:
                pickle.dump(model, f)
            self._models[agent_id] = model
            logger.info(f"Saved model for agent {agent_id}")
        except Exception as e:
            logger.error(f"Failed to save model for {agent_id}: {e}")

    def add_training_sample(
        self,
        agent_id: str,
        feature_vector: List[float],
    ) -> Optional[IsolationForest]:
        """
        Add a feature vector to an agent's training buffer.
        When the buffer reaches BASELINE_TRAINING_MIN, trains the initial model.
        Returns the model if training completed, None otherwise.
        """
        if agent_id not in self._training_buffers:
            self._training_buffers[agent_id] = []

        self._training_buffers[agent_id].append(feature_vector)
        buffer_size = len(self._training_buffers[agent_id])

        if buffer_size >= BASELINE_TRAINING_MIN:
            logger.info(
                f"Training initial baseline for agent {agent_id} "
                f"with {buffer_size} samples"
            )
            model = self._train_model(self._training_buffers[agent_id])
            self.save_model(agent_id, model)
            # Clear buffer after training
            self._training_buffers[agent_id] = []
            self._action_counts[agent_id] = buffer_size
            return model

        return None

    def _train_model(self, training_data: List[List[float]]) -> IsolationForest:
        """
        Train an Isolation Forest model on agent behavioral data.

        Hyperparameters:
        - n_estimators=100: Number of trees (balance accuracy vs speed)
        - contamination=0.05: Expected proportion of anomalies (5%)
        - max_samples="auto": Subsample size (min(256, n_samples))
        - random_state=42: Reproducibility
        """
        X = np.array(training_data)

        model = IsolationForest(
            n_estimators=100,
            contamination=CONTAMINATION,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,  # Use all CPU cores
        )

        model.fit(X)
        logger.info(
            f"Trained IsolationForest on {X.shape[0]} samples, "
            f"{X.shape[1]} features"
        )
        return model

    def score_action(
        self,
        agent_id: str,
        feature_vector: List[float],
    ) -> Optional[float]:
        """
        Score a single action against the agent's baseline model.

        Returns:
            Anomaly score (float): negative = more anomalous
            - Score near 1.0: normal behavior
            - Score near 0.0: uncertain
            - Score below -0.3: anomalous (default threshold)
            - Score near -1.0: highly anomalous
            - None if no model exists yet
        """
        model = self.load_model(agent_id)
        if model is None:
            # No model yet — buffer and return None
            self.add_training_sample(agent_id, feature_vector)
            return None

        try:
            X = np.array([feature_vector])
            # score_samples returns raw anomaly scores
            score = model.score_samples(X)[0]

            # Track action count for retraining
            self._action_counts[agent_id] = self._action_counts.get(agent_id, 0) + 1

            # Check if retraining is needed
            if self._action_counts[agent_id] % RETRAIN_INTERVAL == 0:
                logger.info(
                    f"Retraining trigger for agent {agent_id} "
                    f"at action count {self._action_counts[agent_id]}"
                )
                # Add to buffer for retraining
                if agent_id not in self._training_buffers:
                    self._training_buffers[agent_id] = []
                self._training_buffers[agent_id].append(feature_vector)

            return float(score)

        except Exception as e:
            logger.error(f"Error scoring action for agent {agent_id}: {e}")
            return None

    def retrain_model(
        self,
        agent_id: str,
        training_data: List[List[float]],
    ) -> IsolationForest:
        """
        Retrain an agent's model with new data.
        Called when action count reaches RETRAIN_INTERVAL.
        """
        model = self._train_model(training_data)
        self.save_model(agent_id, model)
        self._action_counts[agent_id] = 0
        logger.info(f"Retrained model for agent {agent_id}")
        return model

    def has_model(self, agent_id: str) -> bool:
        """Check if an agent has a trained baseline model."""
        if agent_id in self._models:
            return True
        return self._model_path(agent_id).exists()

    def get_training_progress(self, agent_id: str) -> Dict:
        """Get the training progress for an agent."""
        buffer_size = len(self._training_buffers.get(agent_id, []))
        has_model = self.has_model(agent_id)
        action_count = self._action_counts.get(agent_id, 0)

        return {
            "has_model": has_model,
            "buffer_size": buffer_size,
            "training_threshold": BASELINE_TRAINING_MIN,
            "total_actions_scored": action_count,
            "next_retrain_at": (
                (action_count // RETRAIN_INTERVAL + 1) * RETRAIN_INTERVAL
                if has_model
                else BASELINE_TRAINING_MIN
            ),
        }

    def delete_model(self, agent_id: str) -> bool:
        """Delete an agent's model (used when agent is revoked)."""
        self._models.pop(agent_id, None)
        self._training_buffers.pop(agent_id, None)
        self._action_counts.pop(agent_id, None)

        model_file = self._model_path(agent_id)
        if model_file.exists():
            model_file.unlink()
            logger.info(f"Deleted model for agent {agent_id}")
            return True
        return False


# Module-level singleton
baseline_trainer = BaselineTrainer()
