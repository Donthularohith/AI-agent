"""
HashiCorp Vault Client — AppRole Auth + Dynamic Secret Management

Uses hvac to interact with Vault. In dev mode, uses root token directly;
in production, uses AppRole auth (role_id + secret_id from environment).

Rohith: This follows the same Vault patterns you'd use in infrastructure
pipelines — AppRole for machine-to-machine auth, KV v2 for secret storage.
"""

import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

import hvac
from hvac.exceptions import VaultError, InvalidPath
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class VaultClient:
    """
    Manages HashiCorp Vault interactions for agent credential lifecycle.

    Supports two auth modes:
    1. Dev mode: Uses VAULT_TOKEN (root token) directly
    2. Production mode: Uses AppRole (VAULT_ROLE_ID + VAULT_SECRET_ID)
    """

    def __init__(self):
        self.vault_addr = os.getenv("VAULT_ADDR", "http://localhost:8200")
        self.role_id = os.getenv("VAULT_ROLE_ID")
        self.secret_id = os.getenv("VAULT_SECRET_ID")
        self.dev_token = os.getenv("VAULT_TOKEN")
        self._client: Optional[hvac.Client] = None
        self._token_expiry: Optional[datetime] = None

    def _get_client(self) -> hvac.Client:
        """Get or create an authenticated Vault client."""
        if self._client and self._client.is_authenticated():
            return self._client

        self._client = hvac.Client(url=self.vault_addr)

        if self.dev_token:
            # Dev mode — use root token directly
            self._client.token = self.dev_token
            logger.info("Vault authenticated with dev token")
        elif self.role_id and self.secret_id:
            # Production mode — AppRole auth
            try:
                result = self._client.auth.approle.login(
                    role_id=self.role_id,
                    secret_id=self.secret_id,
                )
                self._client.token = result["auth"]["client_token"]
                lease_duration = result["auth"]["lease_duration"]
                self._token_expiry = datetime.now(timezone.utc) + timedelta(
                    seconds=lease_duration
                )
                logger.info(
                    f"Vault authenticated via AppRole, token expires in {lease_duration}s"
                )
            except VaultError as e:
                logger.error(f"Vault AppRole login failed: {e}")
                raise
        else:
            raise ValueError(
                "No Vault authentication configured. Set VAULT_TOKEN or "
                "VAULT_ROLE_ID + VAULT_SECRET_ID"
            )

        return self._client

    @property
    def client(self) -> hvac.Client:
        """Property that returns an authenticated client, re-authenticating if needed."""
        if (
            self._token_expiry
            and datetime.now(timezone.utc) >= self._token_expiry - timedelta(seconds=30)
        ):
            logger.info("Vault token nearing expiry, re-authenticating...")
            self._client = None

        return self._get_client()

    def _ensure_kv_engine(self) -> None:
        """Ensure KV v2 secret engine is mounted at 'secret/'."""
        try:
            client = self.client
            mounts = client.sys.list_mounted_secrets_engines()
            if "secret/" not in mounts:
                client.sys.enable_secrets_engine(
                    backend_type="kv",
                    path="secret",
                    options={"version": "2"},
                )
                logger.info("Enabled KV v2 secrets engine at secret/")
        except VaultError as e:
            logger.warning(f"Could not verify KV engine mount: {e}")

    def issue_credential(
        self,
        agent_id: str,
        ttl_seconds: int,
        scoped_resources: list,
        purpose: str,
    ) -> Dict[str, Any]:
        """
        Issue a new purpose-bound credential for an agent.
        Stores the credential in Vault KV at secret/data/agents/{agent_id}/current.

        Returns the credential metadata (never the raw secret in logs).
        """
        import secrets

        client = self.client
        self._ensure_kv_engine()

        # Generate a cryptographically secure credential
        credential_token = secrets.token_urlsafe(48)
        credential_id = f"cred-{agent_id[:8]}-{secrets.token_hex(4)}"
        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + timedelta(seconds=ttl_seconds)

        secret_data = {
            "credential_id": credential_id,
            "agent_id": agent_id,
            "token": credential_token,
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "ttl_seconds": ttl_seconds,
            "scoped_resources": scoped_resources,
            "purpose": purpose,
            "status": "active",
        }

        try:
            # Write to Vault KV v2
            path = f"agents/{agent_id}/current"
            client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=secret_data,
                mount_point="secret",
            )
            logger.info(
                f"Issued credential {credential_id} for agent {agent_id}, "
                f"TTL={ttl_seconds}s"
            )
        except VaultError as e:
            logger.error(f"Failed to issue credential for agent {agent_id}: {e}")
            raise

        # Return metadata only — never the raw token
        return {
            "credential_id": credential_id,
            "agent_id": agent_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "ttl_seconds": ttl_seconds,
            "status": "active",
        }

    def rotate_credential(
        self,
        agent_id: str,
        ttl_seconds: int,
        scoped_resources: list,
        purpose: str,
    ) -> Dict[str, Any]:
        """
        Rotate an agent's credential — issues a new one and revokes the old.
        Zero-downtime rotation: new credential is written before old is revoked.
        """
        # Issue new credential first (zero-downtime)
        new_cred = self.issue_credential(agent_id, ttl_seconds, scoped_resources, purpose)
        logger.info(
            f"Rotated credential for agent {agent_id}: "
            f"new credential_id={new_cred['credential_id']}"
        )
        return new_cred

    def revoke_credential(self, agent_id: str) -> bool:
        """
        Revoke an agent's credential — immediate invalidation.
        Called when an agent is suspended or revoked.
        """
        client = self.client
        try:
            path = f"agents/{agent_id}/current"
            # Read current secret to mark as revoked
            try:
                current = client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point="secret",
                )
                secret_data = current["data"]["data"]
                secret_data["status"] = "revoked"
                secret_data["revoked_at"] = datetime.now(timezone.utc).isoformat()

                # Update with revoked status
                client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret=secret_data,
                    mount_point="secret",
                )
            except InvalidPath:
                logger.warning(
                    f"No credential found at path {path} for agent {agent_id}"
                )
                return False

            logger.info(f"Revoked credential for agent {agent_id}")
            return True

        except VaultError as e:
            logger.error(f"Failed to revoke credential for agent {agent_id}: {e}")
            raise

    def get_credential_status(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Check the current credential status for an agent."""
        client = self.client
        try:
            path = f"agents/{agent_id}/current"
            result = client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point="secret",
            )
            data = result["data"]["data"]
            # Never return the raw token — only metadata
            return {
                "credential_id": data.get("credential_id"),
                "agent_id": data.get("agent_id"),
                "issued_at": data.get("issued_at"),
                "expires_at": data.get("expires_at"),
                "ttl_seconds": data.get("ttl_seconds"),
                "status": data.get("status"),
            }
        except InvalidPath:
            return None
        except VaultError as e:
            logger.error(f"Failed to get credential status for agent {agent_id}: {e}")
            return None

    def is_healthy(self) -> bool:
        """Health check — verify Vault is reachable and authenticated."""
        try:
            client = self.client
            return client.is_authenticated()
        except Exception:
            return False


# Module-level singleton
vault_client = VaultClient()
