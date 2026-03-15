"""
Rate Limiting Middleware — Per-Client Request Throttling
"""

import os
import time
import logging
from collections import defaultdict
from typing import Dict, Tuple

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

RATE_LIMIT = int(os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "120"))


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple in-memory rate limiter using sliding window counters.
    Limits requests per client IP.

    For production, replace with Redis-backed rate limiting.
    """

    def __init__(self, app, requests_per_minute: int = RATE_LIMIT):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.window_seconds = 60
        # client_ip -> [(timestamp, ...)]
        self._requests: Dict[str, list] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health checks
        if request.url.path.startswith("/health"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - self.window_seconds

        # Prune old requests
        self._requests[client_ip] = [
            ts for ts in self._requests[client_ip] if ts >= window_start
        ]

        # Check limit
        if len(self._requests[client_ip]) >= self.requests_per_minute:
            logger.warning(
                f"Rate limit exceeded for {client_ip}: "
                f"{len(self._requests[client_ip])}/{self.requests_per_minute} "
                f"requests in {self.window_seconds}s"
            )
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Max {self.requests_per_minute} requests per minute.",
            )

        # Record request
        self._requests[client_ip].append(now)

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        remaining = self.requests_per_minute - len(self._requests[client_ip])
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"] = str(int(window_start + self.window_seconds))

        return response
