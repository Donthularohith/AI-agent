"""
Circuit Breaker — Per-Agent Rate Limiting + Kill Switch

Implements a sliding window counter that auto-suspends agents exceeding
a configurable denial threshold. This prevents compromised agents from
repeatedly probing for allowed actions.

Rohith: This is the automated containment action — like CrowdStrike's
network containment feature, but for AI agents. When an agent trips the
circuit breaker, it's automatically suspended pending SOC review.
"""

import os
import time
import logging
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

THRESHOLD = int(os.getenv("CIRCUIT_BREAKER_THRESHOLD", "5"))
WINDOW_SECONDS = int(os.getenv("CIRCUIT_BREAKER_WINDOW_SECONDS", "60"))


class CircuitBreaker:
    """
    Per-agent sliding window circuit breaker.

    Tracks policy denial events per agent. When denials exceed
    the threshold within the time window, the circuit breaker
    trips and the agent should be suspended.

    States:
    - CLOSED: Normal operation, counting denials
    - OPEN: Tripped — agent should be suspended
    - HALF_OPEN: Reset after cooldown (not auto-implemented; requires manual reactivation)
    """

    def __init__(
        self,
        threshold: int = THRESHOLD,
        window_seconds: int = WINDOW_SECONDS,
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # Sliding window: agent_id -> list of (timestamp, event_type) tuples
        self._denial_windows: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        # Track tripped breakers
        self._tripped: Dict[str, Dict] = {}

    def record_denial(
        self,
        agent_id: str,
        denial_reason: str = "policy_denial",
    ) -> bool:
        """
        Record a policy denial event for an agent.

        Returns True if the circuit breaker trips (threshold exceeded),
        False if still within limits.
        """
        now = time.time()

        # Add denial to sliding window
        self._denial_windows[agent_id].append((now, denial_reason))

        # Prune old events outside the window
        window_start = now - self.window_seconds
        self._denial_windows[agent_id] = [
            (ts, reason)
            for ts, reason in self._denial_windows[agent_id]
            if ts >= window_start
        ]

        # Check if threshold exceeded
        current_count = len(self._denial_windows[agent_id])

        if current_count >= self.threshold:
            self._trip_breaker(agent_id, current_count)
            return True

        logger.debug(
            f"Circuit breaker for agent {agent_id}: "
            f"{current_count}/{self.threshold} denials in window"
        )
        return False

    def _trip_breaker(self, agent_id: str, denial_count: int) -> None:
        """Trip the circuit breaker — mark agent for suspension."""
        trip_info = {
            "agent_id": agent_id,
            "tripped_at": datetime.now(timezone.utc).isoformat(),
            "denial_count": denial_count,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "recent_denials": [
                {"timestamp": ts, "reason": reason}
                for ts, reason in self._denial_windows[agent_id][-10:]
            ],
        }

        self._tripped[agent_id] = trip_info

        logger.critical(
            f"CIRCUIT BREAKER TRIPPED — Agent {agent_id}: "
            f"{denial_count} denials in {self.window_seconds}s "
            f"(threshold: {self.threshold})"
        )

    def is_tripped(self, agent_id: str) -> bool:
        """Check if an agent's circuit breaker has tripped."""
        return agent_id in self._tripped

    def get_trip_info(self, agent_id: str) -> Optional[Dict]:
        """Get trip details for a tripped circuit breaker."""
        return self._tripped.get(agent_id)

    def reset(self, agent_id: str) -> None:
        """
        Reset the circuit breaker for an agent.
        Called when an agent is manually reactivated by SOC.
        """
        self._denial_windows.pop(agent_id, None)
        self._tripped.pop(agent_id, None)
        logger.info(f"Circuit breaker reset for agent {agent_id}")

    def get_denial_count(self, agent_id: str) -> int:
        """Get current denial count within the sliding window."""
        now = time.time()
        window_start = now - self.window_seconds

        # Prune and count
        valid_denials = [
            (ts, reason)
            for ts, reason in self._denial_windows.get(agent_id, [])
            if ts >= window_start
        ]
        self._denial_windows[agent_id] = valid_denials
        return len(valid_denials)

    def get_all_tripped(self) -> Dict[str, Dict]:
        """Get all currently tripped circuit breakers."""
        return dict(self._tripped)

    def get_status(self, agent_id: str) -> str:
        """Get circuit breaker state for an agent."""
        if self.is_tripped(agent_id):
            return "OPEN"
        elif self.get_denial_count(agent_id) > 0:
            return "CLOSED (counting)"
        else:
            return "CLOSED"


# Module-level singleton
circuit_breaker = CircuitBreaker()
