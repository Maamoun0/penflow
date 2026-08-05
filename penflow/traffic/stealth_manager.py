"""
Intelligent Traffic Governor & Adaptive Rate Limiter for PenFlow.

Provides enterprise-grade network traffic governance:
  - Token-bucket rate limiting with configurable burst capacity
  - Randomized delay jitter to prevent predictable request fingerprints
  - Adaptive backoff upon detecting server pressure (HTTP 429 / 503)
  - Automatic rate restoration on healthy response streaks
"""
import time
import random
import asyncio
from typing import Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.traffic.stealth_manager")


class AdaptiveRateLimiter:
    """
    Token-bucket rate limiter with jitter and concurrency control.
    """

    def __init__(self, target_rps: float = 10.0, burst: int = 5, jitter_ratio: float = 0.2):
        self.target_rps = target_rps
        self.burst = burst
        self.jitter_ratio = jitter_ratio
        self.tokens = float(burst)
        self.last_refill = time.time()
        self._lock = asyncio.Lock() if asyncio.get_event_loop().is_running() else None

    def _refill(self):
        now = time.time()
        delta = now - self.last_refill
        self.tokens = min(float(self.burst), self.tokens + delta * self.target_rps)
        self.last_refill = now

    def acquire_sync(self) -> float:
        """Synchronously acquire a token, returning the sleep duration applied."""
        self._refill()
        sleep_needed = 0.0

        if self.tokens < 1.0:
            sleep_needed = (1.0 - self.tokens) / max(0.1, self.target_rps)
            # Apply random jitter
            jitter = sleep_needed * random.uniform(-self.jitter_ratio, self.jitter_ratio)
            sleep_needed = max(0.001, sleep_needed + jitter)
            time.sleep(sleep_needed)
            self._refill()

        self.tokens -= 1.0
        return sleep_needed

    async def acquire_async(self) -> float:
        """Asynchronously acquire a token."""
        self._refill()
        sleep_needed = 0.0

        if self.tokens < 1.0:
            sleep_needed = (1.0 - self.tokens) / max(0.1, self.target_rps)
            jitter = sleep_needed * random.uniform(-self.jitter_ratio, self.jitter_ratio)
            sleep_needed = max(0.001, sleep_needed + jitter)
            await asyncio.sleep(sleep_needed)
            self._refill()

        self.tokens -= 1.0
        return sleep_needed


class TrafficGovernor:
    """
    Monitors target health and dynamically modulates scanning pace.
    """

    def __init__(self, base_rps: float = 10.0, min_rps: float = 1.0, max_rps: float = 50.0):
        self.base_rps = base_rps
        self.min_rps = min_rps
        self.max_rps = max_rps
        self.current_rps = base_rps
        self.limiter = AdaptiveRateLimiter(target_rps=base_rps)
        self.consecutive_successes = 0
        self.consecutive_throttles = 0
        self.total_requests = 0
        self.throttle_events = 0

    def record_response(self, status_code: int):
        """Adjusts rate dynamically based on response codes."""
        self.total_requests += 1

        if status_code in (429, 503):
            self.consecutive_throttles += 1
            self.consecutive_successes = 0
            self.throttle_events += 1

            # Exponential backoff on rate
            self.current_rps = max(self.min_rps, self.current_rps * 0.5)
            self.limiter.target_rps = self.current_rps
            logger.warning(
                f"[TrafficGovernor] Server returned {status_code}. Backing off pace to {self.current_rps:.1f} RPS."
            )

        elif 200 <= status_code < 400:
            self.consecutive_successes += 1
            self.consecutive_throttles = 0

            # Gradual recovery after 10 clean responses
            if self.consecutive_successes >= 10 and self.current_rps < self.base_rps:
                self.current_rps = min(self.base_rps, self.current_rps * 1.2)
                self.limiter.target_rps = self.current_rps
                self.consecutive_successes = 0
                logger.info(f"[TrafficGovernor] Connection stable. Restoring pace to {self.current_rps:.1f} RPS.")

    async def throttle(self) -> float:
        """Call before sending an HTTP request."""
        return await self.limiter.acquire_async()

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "throttle_events": self.throttle_events,
            "current_rps": round(self.current_rps, 2),
            "base_rps": self.base_rps
        }
