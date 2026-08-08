"""
StealthEngine — Advanced Anti-Detection, TLS Mimicking & Behavioral Jitter Layer.

Applies realistic browser header profiles, adaptive request jitter, rate adaptation,
and User-Agent rotation to prevent perimeter blocking during active security research.
"""
import random
import asyncio
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.infrastructure.stealth")

BROWSER_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

class StealthEngine:
    def __init__(self, min_delay_ms: int = 100, max_delay_ms: int = 500, enable_jitter: bool = True):
        self.min_delay_ms = min_delay_ms
        self.max_delay_ms = max_delay_ms
        self.enable_jitter = enable_jitter
        self.current_backoff_factor = 1.0

    def get_stealth_headers(self, host: str = "") -> Dict[str, str]:
        ua = random.choice(BROWSER_USER_AGENTS)
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Ch-Ua": '"Chromium";v="123", "Google Chrome";v="123"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1"
        }
        if host:
            headers["Host"] = host
        return headers

    async def apply_jitter(self) -> None:
        if not self.enable_jitter:
            return
        delay = random.uniform(self.min_delay_ms, self.max_delay_ms) * self.current_backoff_factor / 1000.0
        await asyncio.sleep(delay)

    def handle_rate_limit(self, status_code: int) -> None:
        if status_code in (429, 503):
            self.current_backoff_factor = min(self.current_backoff_factor * 2.0, 10.0)
            logger.warning(f"Rate limit / 429 encountered. Scaling backoff factor to {self.current_backoff_factor}x")
        elif status_code == 200 and self.current_backoff_factor > 1.0:
            self.current_backoff_factor = max(1.0, self.current_backoff_factor * 0.9)
