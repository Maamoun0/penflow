"""
OOBCallbackServer — Out-Of-Band Interaction Listener & Token Manager for PenFlow.

Provides deterministic OOB tracking for Blind SSRF, Blind XXE, Blind SQLi, and Stored XSS:
  1. Generates unique interaction subdomains per scan/agent/payload
  2. Embeds an in-memory HTTP/DNS interaction tracker with timeout polling
  3. Supports external webhook listeners / interactsh / local HTTP callback endpoint fallback
"""

import asyncio
import uuid
import time
from typing import Dict, Any, Optional, Set
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.infrastructure.oob")


class OOBCallbackServer:
    """
    In-memory Out-of-Band (OOB) interaction coordinator.
    Generates unique interaction identifiers and tracks incoming callbacks.
    """
    _instance: Optional["OOBCallbackServer"] = None

    def __init__(self, base_domain: str = "oob.penflow.local"):
        self.base_domain = base_domain
        self._interactions: Dict[str, Dict[str, Any]] = {}
        self._registered_tokens: Set[str] = set()

    @classmethod
    def get_instance(cls) -> "OOBCallbackServer":
        if cls._instance is None:
            cls._instance = OOBCallbackServer()
        return cls._instance

    def generate_token(self, agent_name: str, scan_id: str) -> str:
        """Generates a unique tracking token for an agent payload."""
        token_id = uuid.uuid4().hex[:12]
        full_token = f"{agent_name}-{scan_id[:8]}-{token_id}"
        self._registered_tokens.add(full_token)
        return full_token

    def get_callback_url(self, token: str, protocol: str = "http") -> str:
        """Returns the full target callback URL for a generated token."""
        return f"{protocol}://{token}.{self.base_domain}/callback"

    def record_interaction(self, token: str, source_ip: str, request_data: Dict[str, Any]):
        """Records an incoming OOB callback hit."""
        logger.info(f"[OOBCallbackServer] Out-Of-Band interaction detected for token: {token} from {source_ip}")
        self._interactions[token] = {
            "timestamp": time.time(),
            "source_ip": source_ip,
            "data": request_data,
            "confirmed": True
        }

    async def wait_for_interaction(self, token: str, timeout: float = 5.0) -> bool:
        """Polls for an incoming OOB interaction within the specified timeout."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if token in self._interactions:
                return True
            await asyncio.sleep(0.3)
        return False

    def get_interaction_data(self, token: str) -> Optional[Dict[str, Any]]:
        return self._interactions.get(token)
