"""
Audit Logger — Append-Only Audit Writes + Splunk HEC Forwarding

Coordinates audit log writes to PostgreSQL and Splunk HEC forwarding.
Every agent action, policy decision, and credential event routes through here.

Rohith: This is the central log pipeline — like your Splunk forwarder,
it receives events from all platform components and writes them to both
the local audit store (PostgreSQL) and the SIEM (Splunk HEC).
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from audit.splunk_client import splunk_client

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Centralized audit logging service.

    Writes to:
    1. PostgreSQL (append-only, synchronous) — primary audit store
    2. Splunk HEC (async batch) — SIEM integration

    Every record includes: agent_id, action_type, tool_uri, resource,
    outcome, policy_decision, anomaly_score, timestamp_utc, session_id,
    human_owner.
    """

    def __init__(self):
        self._splunk = splunk_client

    async def log_action(
        self,
        agent_id: str,
        action_type: str,
        outcome: str,
        tool_uri: Optional[str] = None,
        resource: Optional[str] = None,
        policy_decision: Optional[Dict[str, Any]] = None,
        anomaly_score: Optional[float] = None,
        session_id: Optional[str] = None,
        human_owner: Optional[str] = None,
        metadata_extra: Optional[Dict[str, Any]] = None,
        db_session=None,
    ) -> Dict[str, Any]:
        """
        Log an action to both PostgreSQL and Splunk HEC.

        This is the single entry point for all audit logging.
        Database write is synchronous (within the transaction);
        Splunk forwarding is async (batched).
        """
        timestamp = datetime.now(timezone.utc)
        session_uuid = session_id or str(uuid.uuid4())

        # Build the audit record
        audit_record = {
            "agent_id": str(agent_id),
            "action_type": action_type,
            "tool_uri": tool_uri,
            "resource": resource,
            "outcome": outcome,
            "policy_decision": policy_decision,
            "anomaly_score": anomaly_score,
            "timestamp_utc": timestamp.isoformat(),
            "session_id": session_uuid,
            "human_owner": human_owner,
            "metadata_extra": metadata_extra or {},
        }

        # Step 1: Write to PostgreSQL (if session provided)
        db_record = None
        if db_session:
            try:
                from registry.crud import create_audit_log
                db_record = await create_audit_log(
                    db=db_session,
                    agent_id=uuid.UUID(str(agent_id)),
                    action_type=action_type,
                    outcome=outcome,
                    tool_uri=tool_uri,
                    resource=resource,
                    policy_decision=policy_decision,
                    anomaly_score=anomaly_score,
                    session_id=uuid.UUID(session_uuid) if session_uuid else None,
                    human_owner=human_owner,
                    metadata_extra=metadata_extra,
                )
                audit_record["db_id"] = db_record.id if db_record else None
            except Exception as e:
                logger.error(f"Failed to write audit log to DB: {e}")
                # Don't fail the action — log the error and continue
                audit_record["db_write_error"] = str(e)

        # Step 2: Forward to Splunk HEC (async batch)
        try:
            await self._splunk.send_event(audit_record)
        except Exception as e:
            logger.error(f"Failed to send audit event to Splunk: {e}")
            # Don't fail the action for Splunk errors

        logger.info(
            f"Audit: agent={agent_id}, action={action_type}, "
            f"outcome={outcome}, tool={tool_uri}"
        )

        return audit_record

    async def log_credential_event(
        self,
        agent_id: str,
        event_type: str,
        credential_id: Optional[str] = None,
        human_owner: Optional[str] = None,
        db_session=None,
    ) -> Dict[str, Any]:
        """Log a credential lifecycle event (issue, rotate, revoke)."""
        return await self.log_action(
            agent_id=agent_id,
            action_type=f"credential_{event_type}",
            outcome="success",
            metadata_extra={"credential_id": credential_id},
            human_owner=human_owner,
            db_session=db_session,
        )

    async def log_policy_decision(
        self,
        agent_id: str,
        decision: Dict[str, Any],
        tool_uri: Optional[str] = None,
        resource: Optional[str] = None,
        db_session=None,
    ) -> Dict[str, Any]:
        """Log an OPA policy decision."""
        outcome = "allowed" if decision.get("allow") else "denied"
        return await self.log_action(
            agent_id=agent_id,
            action_type="policy_decision",
            outcome=outcome,
            tool_uri=tool_uri,
            resource=resource,
            policy_decision=decision,
            db_session=db_session,
        )

    async def log_anomaly_alert(
        self,
        agent_id: str,
        anomaly_score: float,
        feature_vector: Dict[str, float],
        severity: str,
        human_owner: Optional[str] = None,
        db_session=None,
    ) -> Dict[str, Any]:
        """Log a behavioral anomaly alert."""
        return await self.log_action(
            agent_id=agent_id,
            action_type="anomaly_alert",
            outcome="alert_generated",
            anomaly_score=anomaly_score,
            human_owner=human_owner,
            metadata_extra={
                "severity": severity,
                "feature_vector": feature_vector,
            },
            db_session=db_session,
        )

    async def log_circuit_breaker_trip(
        self,
        agent_id: str,
        trip_info: Dict[str, Any],
        db_session=None,
    ) -> Dict[str, Any]:
        """Log a circuit breaker trip event."""
        return await self.log_action(
            agent_id=agent_id,
            action_type="circuit_breaker_trip",
            outcome="agent_suspended",
            metadata_extra=trip_info,
            db_session=db_session,
        )

    async def start(self) -> None:
        """Start the audit logger and Splunk HEC client."""
        await self._splunk.start()
        logger.info("Audit logger started")

    async def stop(self) -> None:
        """Stop the audit logger and flush remaining events."""
        await self._splunk.stop()
        logger.info("Audit logger stopped")


# Module-level singleton
audit_logger = AuditLogger()
