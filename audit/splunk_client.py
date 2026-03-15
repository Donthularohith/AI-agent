"""
Splunk HEC Client — Async Batch Event Forwarding

Forwards audit events to Splunk via HTTP Event Collector (HEC).
Implements async batch sending: flush every 5 seconds or 100 events.

Rohith: This follows the exact same HEC pattern you configure in
Splunk Enterprise. The sourcetype, index, and event format are designed
to integrate with standard Splunk search patterns.
"""

import os
import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import aiohttp
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class SplunkHECClient:
    """
    Async Splunk HTTP Event Collector client.

    Batches events and flushes either:
    - When batch reaches BATCH_SIZE (default: 100 events)
    - When FLUSH_INTERVAL seconds have elapsed (default: 5 seconds)
    - Whichever comes first

    Sourcetype: ai:agent:governance
    Index: ai_security
    """

    def __init__(self):
        self.hec_url = os.getenv("SPLUNK_HEC_URL", "http://localhost:8088/services/collector")
        self.hec_token = os.getenv("SPLUNK_HEC_TOKEN", "")
        self.index = os.getenv("SPLUNK_INDEX", "ai_security")
        self.sourcetype = os.getenv("SPLUNK_SOURCETYPE", "ai:agent:governance")
        self.batch_size = int(os.getenv("SPLUNK_HEC_BATCH_SIZE", "100"))
        self.flush_interval = int(os.getenv("SPLUNK_HEC_FLUSH_INTERVAL_SECONDS", "5"))

        self._batch: List[Dict[str, Any]] = []
        self._last_flush: float = time.time()
        self._session: Optional[aiohttp.ClientSession] = None
        self._flush_task: Optional[asyncio.Task] = None
        self._enabled = bool(self.hec_token)
        self._stats = {
            "events_sent": 0,
            "events_failed": 0,
            "batches_sent": 0,
            "last_send_time": None,
        }

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=10)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def start(self) -> None:
        """Start the background flush task."""
        if not self._enabled:
            logger.warning("Splunk HEC disabled — no SPLUNK_HEC_TOKEN configured")
            return

        self._flush_task = asyncio.create_task(self._periodic_flush())
        logger.info(
            f"Splunk HEC client started — "
            f"URL: {self.hec_url}, index: {self.index}, "
            f"batch_size: {self.batch_size}, flush_interval: {self.flush_interval}s"
        )

    async def stop(self) -> None:
        """Stop the flush task and send remaining events."""
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        # Final flush
        if self._batch:
            await self._flush_batch()

        if self._session and not self._session.closed:
            await self._session.close()

        logger.info(
            f"Splunk HEC client stopped — "
            f"total events sent: {self._stats['events_sent']}, "
            f"failed: {self._stats['events_failed']}"
        )

    async def send_event(self, event_data: Dict[str, Any]) -> None:
        """
        Add an event to the batch. Flush if batch is full.

        Event format matches Splunk HEC JSON format:
        {
            "time": epoch_timestamp,
            "host": "ai-governance-platform",
            "source": "governance-api",
            "sourcetype": "ai:agent:governance",
            "index": "ai_security",
            "event": { ... actual event data ... }
        }
        """
        if not self._enabled:
            return

        hec_event = {
            "time": time.time(),
            "host": "ai-governance-platform",
            "source": "governance-api",
            "sourcetype": self.sourcetype,
            "index": self.index,
            "event": event_data,
        }

        self._batch.append(hec_event)

        # Flush if batch is full
        if len(self._batch) >= self.batch_size:
            await self._flush_batch()

    async def _periodic_flush(self) -> None:
        """Background task that flushes the batch every flush_interval seconds."""
        while True:
            try:
                await asyncio.sleep(self.flush_interval)
                if self._batch:
                    await self._flush_batch()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Splunk HEC periodic flush error: {e}")

    async def _flush_batch(self) -> None:
        """Send the current batch to Splunk HEC."""
        if not self._batch:
            return

        batch_to_send = self._batch.copy()
        self._batch = []
        self._last_flush = time.time()

        try:
            session = await self._get_session()
            headers = {
                "Authorization": f"Splunk {self.hec_token}",
                "Content-Type": "application/json",
            }

            # Splunk HEC accepts batch events as newline-delimited JSON
            import json
            payload = "\n".join(json.dumps(event) for event in batch_to_send)

            async with session.post(
                self.hec_url,
                data=payload,
                headers=headers,
            ) as response:
                if response.status == 200:
                    self._stats["events_sent"] += len(batch_to_send)
                    self._stats["batches_sent"] += 1
                    self._stats["last_send_time"] = datetime.now(timezone.utc).isoformat()

                    logger.debug(
                        f"Splunk HEC batch sent: {len(batch_to_send)} events "
                        f"(total: {self._stats['events_sent']})"
                    )
                else:
                    error_text = await response.text()
                    self._stats["events_failed"] += len(batch_to_send)
                    logger.error(
                        f"Splunk HEC send failed ({response.status}): {error_text}"
                    )
                    # Re-queue failed events (up to batch_size limit)
                    self._batch = batch_to_send[:self.batch_size] + self._batch

        except aiohttp.ClientError as e:
            self._stats["events_failed"] += len(batch_to_send)
            logger.error(f"Splunk HEC connection error: {e}")
            # Re-queue for retry
            self._batch = batch_to_send[:self.batch_size] + self._batch

        except Exception as e:
            self._stats["events_failed"] += len(batch_to_send)
            logger.error(f"Splunk HEC unexpected error: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get HEC client statistics."""
        return {
            **self._stats,
            "pending_events": len(self._batch),
            "enabled": self._enabled,
            "hec_url": self.hec_url,
            "index": self.index,
            "sourcetype": self.sourcetype,
        }

    async def is_healthy(self) -> bool:
        """Health check — verify Splunk HEC is reachable."""
        if not self._enabled:
            return True  # Not configured, not a failure

        try:
            session = await self._get_session()
            headers = {"Authorization": f"Splunk {self.hec_token}"}

            async with session.get(
                self.hec_url.replace("/services/collector", "/services/collector/health"),
                headers=headers,
            ) as response:
                return response.status == 200
        except Exception:
            return False


# Module-level singleton
splunk_client = SplunkHECClient()
