"""
MCP Interceptor — Intercept + Allow/Deny MCP Tool Calls

Wraps MCP tool calls with governance enforcement. Before any tool
executes, the interceptor checks OPA policy and behavioral scoring.

Rohith: This is the inline enforcement point — like a web application
firewall (WAF) inspects HTTP requests, this inspects every MCP tool
call before it reaches the backend.
"""

import logging
import uuid
import functools
import asyncio
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, List

from policy.opa_client import opa_client
from enforcement.circuit_breaker import circuit_breaker
from monitoring.behavioral_monitor import behavioral_monitor

logger = logging.getLogger(__name__)


class MCPInterceptor:
    """
    MCP Tool Call Interceptor.

    Wraps tool callables with governance checks:
    1. Check circuit breaker status
    2. Evaluate OPA policy
    3. Score behavioral anomaly
    4. Allow or deny execution
    5. Log everything to audit trail
    """

    def __init__(
        self,
        agent_id: str,
        agent_record: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
    ):
        self.agent_id = agent_id
        self.agent_record = agent_record or {}
        self.session_id = session_id or str(uuid.uuid4())
        self._audit_callback: Optional[Callable] = None
        self._recent_actions: List[Dict[str, Any]] = []

    def set_audit_callback(self, callback: Callable) -> None:
        """Set a callback function for audit logging."""
        self._audit_callback = callback

    def set_agent_record(self, record: Dict[str, Any]) -> None:
        """Update the agent record (refreshed from registry)."""
        self.agent_record = record

    def governed_tool(self, func: Callable = None, *, tool_uri: str = None, resource: str = None):
        """
        Decorator to wrap a tool function with governance enforcement.

        Usage:
            @interceptor.governed_tool
            def my_tool(arg1, arg2):
                ...

            @interceptor.governed_tool(tool_uri="mcp://emr/patient/read")
            def read_patient(patient_id):
                ...
        """
        def decorator(fn: Callable) -> Callable:
            # Derive tool_uri from function name if not specified
            actual_tool_uri = tool_uri or f"mcp://tools/{fn.__name__}"

            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                actual_resource = resource or kwargs.get("resource", "")
                return await self._execute_governed(
                    fn, actual_tool_uri, actual_resource, *args, **kwargs
                )

            @functools.wraps(fn)
            def sync_wrapper(*args, **kwargs):
                actual_resource = resource or kwargs.get("resource", "")
                return asyncio.get_event_loop().run_until_complete(
                    self._execute_governed(
                        fn, actual_tool_uri, actual_resource, *args, **kwargs
                    )
                )

            if asyncio.iscoroutinefunction(fn):
                return async_wrapper
            return sync_wrapper

        if func is not None:
            return decorator(func)
        return decorator

    async def intercept(
        self,
        tool_uri: str,
        resource: str,
        tool_callable: Callable,
        *args,
        **kwargs,
    ) -> Any:
        """
        Intercept and govern a tool call programmatically.

        Args:
            tool_uri: MCP tool URI being called
            resource: Resource being accessed
            tool_callable: The actual tool function to call
            *args, **kwargs: Arguments for the tool function

        Returns:
            Tool result if allowed

        Raises:
            PermissionError: If the tool call is denied
        """
        return await self._execute_governed(
            tool_callable, tool_uri, resource, *args, **kwargs
        )

    async def _execute_governed(
        self,
        func: Callable,
        tool_uri: str,
        resource: str,
        *args,
        **kwargs,
    ) -> Any:
        """Core governance execution pipeline."""
        action_context = {
            "agent_id": self.agent_id,
            "action_type": "tool_call",
            "tool_uri": tool_uri,
            "resource": resource,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
        }

        # ── Step 1: Check Circuit Breaker ────────────────────────────────
        if circuit_breaker.is_tripped(self.agent_id):
            trip_info = circuit_breaker.get_trip_info(self.agent_id)
            await self._log_action(
                action_context, "denied", "circuit_breaker_tripped",
                {"trip_info": trip_info}
            )
            raise PermissionError(
                f"Agent {self.agent_id} circuit breaker is OPEN — "
                f"agent suspended after {trip_info.get('denial_count', '?')} "
                f"denials in {trip_info.get('window_seconds', '?')}s"
            )

        # ── Step 2: Evaluate OPA Policy ──────────────────────────────────
        policy_input = {
            "agent_id": self.agent_id,
            "action": "tool_call",
            "resource": resource,
            "tool_uri": tool_uri,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "delegation_depth": self.agent_record.get("delegation_depth", 0),
            "parent_agent_id": self.agent_record.get("parent_agent_id"),
            "session_token_claims": self.agent_record.get("session_token_claims", {}),
            "agent_record": {
                "status": self.agent_record.get("status", "active"),
                "allowed_tools": self.agent_record.get("allowed_tools", []),
                "allowed_resources": self.agent_record.get("allowed_resources", []),
                "max_delegation_depth": self.agent_record.get("max_delegation_depth", 0),
                "compliance_tags": self.agent_record.get("compliance_tags", []),
            },
        }

        policy_decision = await opa_client.evaluate_policy(policy_input)

        if not policy_decision.get("allow", False):
            # Record denial in circuit breaker
            tripped = circuit_breaker.record_denial(
                self.agent_id,
                policy_decision.get("reason", "policy_denial"),
            )

            await self._log_action(
                action_context, "denied",
                policy_decision.get("reason", "policy_denial"),
                {"policy_decision": policy_decision, "circuit_breaker_tripped": tripped}
            )

            raise PermissionError(
                f"Access denied for agent {self.agent_id}: "
                f"{policy_decision.get('reason')}. "
                f"Details: {policy_decision.get('denied_reasons', [])}"
            )

        # ── Step 3: Behavioral Scoring ───────────────────────────────────
        monitoring_result = await behavioral_monitor.process_action(
            agent_id=self.agent_id,
            action=action_context,
            recent_actions=self._recent_actions,
            anomaly_threshold=self.agent_record.get("anomaly_threshold", -0.3),
        )

        anomaly_score = monitoring_result.get("anomaly_score")

        # ── Step 4: Execute Tool ─────────────────────────────────────────
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            # Log successful execution
            await self._log_action(
                action_context, "success", "allowed",
                {
                    "policy_decision": policy_decision,
                    "anomaly_score": anomaly_score,
                    "is_anomalous": monitoring_result.get("is_anomalous", False),
                }
            )

            # Track for sliding window
            self._recent_actions.append(action_context)
            # Keep only last 100 actions in memory
            if len(self._recent_actions) > 100:
                self._recent_actions = self._recent_actions[-100:]

            return result

        except PermissionError:
            raise  # Re-raise our own PermissionErrors
        except Exception as e:
            # Log tool execution error
            action_context["error"] = str(e)
            await self._log_action(
                action_context, "error", "tool_execution_error",
                {"error": str(e), "anomaly_score": anomaly_score}
            )
            raise

    async def _log_action(
        self,
        action_context: Dict,
        outcome: str,
        reason: str,
        extra: Optional[Dict] = None,
    ) -> None:
        """Log action through the audit callback if configured."""
        log_entry = {
            **action_context,
            "outcome": outcome,
            "reason": reason,
            "metadata_extra": extra or {},
        }

        if self._audit_callback:
            try:
                await self._audit_callback(log_entry)
            except Exception as e:
                logger.error(f"Audit callback failed: {e}")

        logger.info(
            f"MCP Intercept: agent={self.agent_id}, "
            f"tool={action_context.get('tool_uri')}, "
            f"outcome={outcome}, reason={reason}"
        )
