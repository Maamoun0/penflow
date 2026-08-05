import asyncio
import time
from typing import Dict

from penflow.config import Config
from penflow.utils.logger import get_logger

logger = get_logger("penflow.network.rate_limiter")

class DomainRateLimiter:
    def __init__(self, requests_per_second: float):
        self.rate = requests_per_second
        self.capacity = max(1.0, requests_per_second)
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self.lock = asyncio.Lock()
        
        # Adaptive backoff state
        self.consecutive_429s = 0
        self.consecutive_200s = 0
        self.current_multiplier = 1.0

    async def acquire(self):
        """Wait until a token is available."""
        async with self.lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_update
                
                # Replenish tokens based on rate and backoff multiplier
                effective_rate = self.rate / self.current_multiplier
                self.tokens = min(self.capacity, self.tokens + elapsed * effective_rate)
                self.last_update = now
                
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                
                # Wait for enough time to get 1 token
                wait_time = (1.0 - self.tokens) / effective_rate
                await asyncio.sleep(wait_time)

    def record_response(self, status_code: int, config: Config):
        """Update adaptive limits based on response status."""
        if not config.get("rate_limiter.backoff_on_429", True):
            return
            
        if status_code in (429, 503, 504):
            self.consecutive_429s += 1
            self.consecutive_200s = 0
            
            multiplier = config.get("rate_limiter.backoff_multiplier", 2.0)
            max_backoff = config.get("rate_limiter.max_backoff_seconds", 60)
            
            # Increase backoff, max delay is bounded by max_backoff
            new_multiplier = min(self.current_multiplier * multiplier, max_backoff * self.rate)
            
            if new_multiplier > self.current_multiplier:
                logger.warning(f"Rate limit hit ({status_code}). Increasing backoff multiplier to {new_multiplier:.2f}")
                self.current_multiplier = new_multiplier
                
        elif status_code < 400 or status_code == 404:
            self.consecutive_200s += 1
            if self.consecutive_200s >= config.get("rate_limiter.recovery_threshold", 5):
                if self.current_multiplier > 1.0:
                    self.current_multiplier = max(1.0, self.current_multiplier / 1.5)
                    self.consecutive_200s = 0
                    logger.debug(f"Stability recovered. Decreasing backoff multiplier to {self.current_multiplier:.2f}")

class AdaptiveRateLimiter:
    def __init__(self):
        self.config = Config.load()
        profile = self.config.get_active_profile()
        self.default_rate = profile.get("requests_per_second", 3.0)
        self.domain_limiters: Dict[str, DomainRateLimiter] = {}
        self._lock = asyncio.Lock()

    async def get_limiter(self, domain: str) -> DomainRateLimiter:
        async with self._lock:
            if domain not in self.domain_limiters:
                self.domain_limiters[domain] = DomainRateLimiter(self.default_rate)
            return self.domain_limiters[domain]

    async def acquire(self, domain: str):
        """Acquire a token for the specified domain."""
        limiter = await self.get_limiter(domain)
        await limiter.acquire()

    async def record_response(self, domain: str, status_code: int):
        """Record response to adapt rate limits."""
        limiter = await self.get_limiter(domain)
        limiter.record_response(status_code, self.config)
