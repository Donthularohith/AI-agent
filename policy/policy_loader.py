"""
Policy Loader — Load and Push Rego Policies to OPA at Startup

Reads all .rego files from the policies/ directory and pushes them
to the OPA server via REST API.
"""

import os
import logging
from pathlib import Path

from policy.opa_client import opa_client

logger = logging.getLogger(__name__)

POLICIES_DIR = Path(__file__).parent / "policies"


async def load_all_policies() -> dict:
    """
    Load all Rego policies from disk and push them to OPA.
    Returns a dict of {policy_name: success_bool}.
    """
    results = {}

    if not POLICIES_DIR.exists():
        logger.warning(f"Policies directory not found: {POLICIES_DIR}")
        return results

    for policy_file in POLICIES_DIR.glob("*.rego"):
        policy_name = policy_file.stem  # e.g., "agent_authz"
        policy_content = policy_file.read_text()

        success = await opa_client.load_policy(policy_name, policy_content)
        results[policy_name] = success

        if success:
            logger.info(f"Loaded policy: {policy_name}")
        else:
            logger.error(f"Failed to load policy: {policy_name}")

    return results


async def reload_policy(policy_name: str) -> bool:
    """
    Hot-reload a specific policy file into OPA.
    Supports FR-019: policy hot-reload without service restart.
    """
    policy_file = POLICIES_DIR / f"{policy_name}.rego"

    if not policy_file.exists():
        logger.error(f"Policy file not found: {policy_file}")
        return False

    policy_content = policy_file.read_text()
    success = await opa_client.load_policy(policy_name, policy_content)

    if success:
        logger.info(f"Hot-reloaded policy: {policy_name}")
    else:
        logger.error(f"Failed to hot-reload policy: {policy_name}")

    return success


async def list_available_policies() -> list:
    """List all available policy files."""
    if not POLICIES_DIR.exists():
        return []
    return [f.stem for f in POLICIES_DIR.glob("*.rego")]
