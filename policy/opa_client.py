"""
OPA Client — Async REST Client for Policy Decisions

Communicates with OPA server via REST API for authorization decisions.
Uses aiohttp for non-blocking HTTP calls to meet the <50ms p99 target.

Rohith: OPA is your policy enforcement point (PEP) — similar to how
Splunk Enterprise Security uses correlation searches to make decisions,
OPA evaluates Rego policies against agent action context.
"""

import os
import logging
import time
from typing import Dict, Any, Optional

import aiohttp
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class OPAClient:
    """
    Async client for Open Policy Agent REST API.

    Sends policy decision requests to OPA and returns structured
    allow/deny decisions. Handles connection pooling and timeouts
    to maintain <50ms p99 latency.
    """

    def __init__(self):
        self.opa_url = os.getenv("OPA_URL", "http://localhost:8181")
        self.policy_path = os.getenv("OPA_POLICY_PATH", "/v1/data/authz")
        self._session: Optional[aiohttp.ClientSession] = None
        # Fallback to local evaluation if OPA is unavailable
        self._fallback_enabled = True

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session with connection pooling."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=5, connect=1)
            connector = aiohttp.TCPConnector(
                limit=50,           # Max 50 concurrent connections to OPA
                keepalive_timeout=30, # Keep connections alive for 30s
            )
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
            )
        return self._session

    async def evaluate_policy(
        self,
        input_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Send a policy decision request to OPA.

        Args:
            input_data: The policy input matching Section 3.4 schema:
                {agent_id, action, resource, tool_uri, timestamp,
                 delegation_depth, parent_agent_id, session_token_claims,
                 agent_record}

        Returns:
            Policy decision: {allow, reason, audit_required, denied_reasons, compliance_flags}
        """
        start_time = time.monotonic()

        try:
            session = await self._get_session()

            # POST to OPA's data API
            url = f"{self.opa_url}{self.policy_path}"
            payload = {"input": input_data}

            async with session.post(url, json=payload) as response:
                elapsed_ms = (time.monotonic() - start_time) * 1000

                if response.status == 200:
                    result = await response.json()
                    decision = result.get("result", {})

                    logger.debug(
                        f"OPA decision in {elapsed_ms:.1f}ms: "
                        f"allow={decision.get('allow', False)}, "
                        f"agent={input_data.get('agent_id')}"
                    )

                    return {
                        "allow": decision.get("allow", False),
                        "reason": decision.get("reason", "policy_evaluation_complete"),
                        "audit_required": decision.get("audit_required", True),
                        "denied_reasons": decision.get("denied_reasons", []),
                        "compliance_flags": decision.get("compliance_flags", []),
                    }
                else:
                    error_text = await response.text()
                    logger.error(
                        f"OPA returned status {response.status}: {error_text}"
                    )
                    # Fail closed — deny on OPA error
                    return self._fail_closed("opa_error", f"OPA returned {response.status}")

        except aiohttp.ClientError as e:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            logger.error(f"OPA connection error after {elapsed_ms:.1f}ms: {e}")

            if self._fallback_enabled:
                return self._evaluate_local_fallback(input_data)
            return self._fail_closed("opa_unreachable", str(e))

        except Exception as e:
            logger.error(f"Unexpected OPA error: {e}")
            return self._fail_closed("opa_internal_error", str(e))

    def _evaluate_local_fallback(
        self,
        input_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Local fallback policy evaluation when OPA is unavailable.
        Implements basic checks matching the Rego policies.

        This is a safety net — not a replacement for OPA.
        """
        logger.warning("Using local fallback policy evaluation (OPA unavailable)")

        denied_reasons = []
        agent_record = input_data.get("agent_record", {})

        # Check 1: Agent must be active
        if agent_record.get("status") != "active":
            denied_reasons.append(
                f"Agent status is '{agent_record.get('status')}', must be 'active'"
            )

        # Check 2: Tool must be in allowlist
        tool_uri = input_data.get("tool_uri")
        allowed_tools = agent_record.get("allowed_tools", [])
        if tool_uri and tool_uri not in allowed_tools:
            denied_reasons.append(
                f"Tool '{tool_uri}' not in agent's allowed_tools list"
            )

        # Check 3: Resource must match an allowed pattern
        resource = input_data.get("resource", "")
        allowed_resources = agent_record.get("allowed_resources", [])
        resource_match = False
        for pattern in allowed_resources:
            if self._match_resource_pattern(resource, pattern):
                resource_match = True
                break
        if resource and not resource_match:
            denied_reasons.append(
                f"Resource '{resource}' does not match any allowed pattern"
            )

        # Check 4: Delegation depth check
        delegation_depth = input_data.get("delegation_depth", 0)
        max_depth = agent_record.get("max_delegation_depth", 0)
        if delegation_depth > max_depth:
            denied_reasons.append(
                f"Delegation depth {delegation_depth} exceeds max {max_depth}"
            )

        # Check 5: Token expiry
        claims = input_data.get("session_token_claims", {})
        if claims.get("expires_at"):
            from datetime import datetime
            try:
                expires = datetime.fromisoformat(str(claims["expires_at"]))
                if expires < datetime.now(expires.tzinfo):
                    denied_reasons.append("Session token has expired")
            except (ValueError, TypeError):
                pass

        allow = len(denied_reasons) == 0
        compliance_flags = agent_record.get("compliance_tags", [])

        return {
            "allow": allow,
            "reason": "all_checks_passed" if allow else denied_reasons[0],
            "audit_required": True,
            "denied_reasons": denied_reasons,
            "compliance_flags": compliance_flags,
        }

    def _match_resource_pattern(self, resource: str, pattern: str) -> bool:
        """
        Match a resource string against a glob-like pattern.
        Supports * as wildcard.
        """
        if pattern == "*":
            return True

        pattern_parts = pattern.split(":")
        resource_parts = resource.split(":")

        for i, p_part in enumerate(pattern_parts):
            if p_part == "*":
                return True  # Wildcard matches everything after
            if i >= len(resource_parts):
                return False
            if p_part != resource_parts[i]:
                return False

        return len(resource_parts) == len(pattern_parts)

    @staticmethod
    def _fail_closed(reason: str, detail: str) -> Dict[str, Any]:
        """Fail closed — deny access when OPA is unavailable or erroring."""
        return {
            "allow": False,
            "reason": reason,
            "audit_required": True,
            "denied_reasons": [f"Policy engine error: {detail}"],
            "compliance_flags": [],
        }

    async def load_policy(self, policy_name: str, policy_content: str) -> bool:
        """Push a Rego policy to OPA."""
        try:
            session = await self._get_session()
            url = f"{self.opa_url}/v1/policies/{policy_name}"
            headers = {"Content-Type": "text/plain"}

            async with session.put(url, data=policy_content, headers=headers) as response:
                if response.status == 200:
                    logger.info(f"Policy '{policy_name}' loaded into OPA")
                    return True
                else:
                    error = await response.text()
                    logger.error(
                        f"Failed to load policy '{policy_name}': {response.status} - {error}"
                    )
                    return False
        except Exception as e:
            logger.error(f"Error loading policy '{policy_name}': {e}")
            return False

    async def push_data(self, data_path: str, data: Dict[str, Any]) -> bool:
        """Push data to OPA's data store."""
        try:
            session = await self._get_session()
            url = f"{self.opa_url}/v1/data/{data_path}"

            async with session.put(url, json=data) as response:
                if response.status == 204 or response.status == 200:
                    logger.info(f"Data pushed to OPA at path '{data_path}'")
                    return True
                else:
                    error = await response.text()
                    logger.error(
                        f"Failed to push data to '{data_path}': {response.status} - {error}"
                    )
                    return False
        except Exception as e:
            logger.error(f"Error pushing data to OPA: {e}")
            return False

    async def is_healthy(self) -> bool:
        """Health check — verify OPA is reachable."""
        try:
            session = await self._get_session()
            url = f"{self.opa_url}/health"

            async with session.get(url) as response:
                return response.status == 200
        except Exception:
            return False

    async def close(self) -> None:
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()


# Module-level singleton
opa_client = OPAClient()
