"""
Token Manager — Purpose-Bound Token Creation, Rotation & Revocation

Orchestrates the credential lifecycle by coordinating between the Vault client
and the agent registry. Handles TTL enforcement and auto-rotation scheduling.
"""

import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

from credentials.vault_client import vault_client

logger = logging.getLogger(__name__)


class TokenManager:
    """
    Manages purpose-bound tokens for AI agents.

    Each token is scoped to the agent's declared resources and has a TTL
    from the agent's credential_ttl_seconds field. Tokens auto-expire
    and can be rotated with zero downtime.
    """

    def __init__(self):
        self._vault = vault_client
        # Track active credential metadata (in-memory for fast lookups)
        self._active_credentials: Dict[str, Dict[str, Any]] = {}

    async def issue_token(
        self,
        agent_id: str,
        ttl_seconds: int,
        scoped_resources: list,
        purpose: str,
    ) -> Dict[str, Any]:
        """
        Issue a new purpose-bound token for an agent.

        Args:
            agent_id: UUID of the agent requesting a credential
            ttl_seconds: Token lifetime in seconds
            scoped_resources: List of resource patterns this token is valid for
            purpose: Agent's declared purpose (for audit trail)

        Returns:
            Credential metadata (never raw secret)
        """
        try:
            credential = self._vault.issue_credential(
                agent_id=agent_id,
                ttl_seconds=ttl_seconds,
                scoped_resources=scoped_resources,
                purpose=purpose,
            )

            # Track the credential in memory for quick expiry checks
            self._active_credentials[agent_id] = credential

            logger.info(
                f"Token issued for agent {agent_id}: "
                f"credential_id={credential['credential_id']}, "
                f"ttl={ttl_seconds}s"
            )
            return credential

        except Exception as e:
            logger.error(f"Failed to issue token for agent {agent_id}: {e}")
            raise

    async def rotate_token(
        self,
        agent_id: str,
        ttl_seconds: int,
        scoped_resources: list,
        purpose: str,
    ) -> Dict[str, Any]:
        """
        Rotate an agent's token — creates new credential before revoking old.
        Zero-downtime rotation ensures the agent is never without a valid credential.
        """
        try:
            new_credential = self._vault.rotate_credential(
                agent_id=agent_id,
                ttl_seconds=ttl_seconds,
                scoped_resources=scoped_resources,
                purpose=purpose,
            )

            # Update in-memory tracking
            self._active_credentials[agent_id] = new_credential

            logger.info(
                f"Token rotated for agent {agent_id}: "
                f"new credential_id={new_credential['credential_id']}"
            )
            return new_credential

        except Exception as e:
            logger.error(f"Failed to rotate token for agent {agent_id}: {e}")
            raise

    async def revoke_token(self, agent_id: str) -> bool:
        """
        Revoke an agent's token immediately.
        Called on agent suspension or revocation.
        """
        try:
            result = self._vault.revoke_credential(agent_id)

            # Remove from in-memory tracking
            self._active_credentials.pop(agent_id, None)

            logger.info(f"Token revoked for agent {agent_id}")
            return result

        except Exception as e:
            logger.error(f"Failed to revoke token for agent {agent_id}: {e}")
            return False

    def check_token_expiry(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Check if an agent's token needs rotation.
        Returns renewal info if TTL has > 30 seconds remaining, None otherwise.
        """
        cred = self._active_credentials.get(agent_id)
        if not cred:
            # Try to fetch from Vault
            cred = self._vault.get_credential_status(agent_id)
            if cred:
                self._active_credentials[agent_id] = cred

        if not cred:
            return None

        expires_at_str = cred.get("expires_at")
        if not expires_at_str:
            return None

        if isinstance(expires_at_str, str):
            expires_at = datetime.fromisoformat(expires_at_str)
        else:
            expires_at = expires_at_str

        # Ensure timezone-aware
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        remaining = (expires_at - now).total_seconds()

        if remaining <= 0:
            return {"status": "expired", "remaining_seconds": 0}
        elif remaining <= 30:
            return {"status": "needs_rotation", "remaining_seconds": remaining}
        else:
            return {"status": "active", "remaining_seconds": remaining}

    def get_active_credential(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get the active credential metadata for an agent."""
        if agent_id in self._active_credentials:
            return self._active_credentials[agent_id]
        return self._vault.get_credential_status(agent_id)


# Module-level singleton
token_manager = TokenManager()
