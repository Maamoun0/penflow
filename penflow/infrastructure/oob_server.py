"""
OOBCallbackServer & MultiProtocolOOBEngine — Out-Of-Band Interaction Listener & Token Manager for PenFlow.

Provides deterministic OOB tracking for Blind SSRF, Blind XXE, Blind SQLi, Blind SSTI, and Stored XSS:
  1. Multi-protocol support: DNS, HTTP, HTTPS, SMTP, LDAP
  2. Interaction Correlator: Links every callback hit directly to the initiating agent, request URL, and parameter
  3. Live Interactsh API polling integration & event simulation fallback
"""

import asyncio
import uuid
import time
import httpx
from enum import Enum
from typing import Dict, Any, Optional, Set, List
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.infrastructure.oob")


class InteractionProtocol(str, Enum):
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    SMTP = "smtp"
    LDAP = "ldap"


class InteractionRecord:
    """Detailed record of an incoming Out-Of-Band network callback."""
    def __init__(self, token: str, protocol: InteractionProtocol, source_ip: str,
                 timestamp: float, raw_data: Optional[Dict[str, Any]] = None):
        self.token = token
        self.protocol = protocol
        self.source_ip = source_ip
        self.timestamp = timestamp
        self.raw_data = raw_data or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "protocol": self.protocol.value if isinstance(self.protocol, InteractionProtocol) else str(self.protocol),
            "source_ip": self.source_ip,
            "timestamp": self.timestamp,
            "raw_data": self.raw_data,
        }


class InteractionCorrelator:
    """
    Correlates OOB callback tokens with the triggering agent, URL, and parameter.
    """
    def __init__(self):
        self._registered_contexts: Dict[str, Dict[str, Any]] = {}

    def register(self, token: str, agent_name: str, scan_id: str,
                 target_url: str = "", parameter_name: str = "",
                 expected_protocol: InteractionProtocol = InteractionProtocol.HTTP):
        self._registered_contexts[token] = {
            "token": token,
            "agent_name": agent_name,
            "scan_id": scan_id,
            "target_url": target_url,
            "parameter_name": parameter_name,
            "expected_protocol": expected_protocol,
            "registered_at": time.time()
        }

    def get_context(self, token: str) -> Optional[Dict[str, Any]]:
        return self._registered_contexts.get(token)


class OOBCallbackServer:
    """
    Enterprise-grade Out-of-Band (OOB) interaction coordinator supporting
    multi-protocol callbacks (DNS, HTTP, HTTPS, SMTP, LDAP) and request correlation.
    """
    _instance: Optional["OOBCallbackServer"] = None

    def __init__(self, base_domain: str = "oob.penflow.local"):
        self.base_domain = base_domain
        self.correlator = InteractionCorrelator()
        self._interactions: Dict[str, List[InteractionRecord]] = {}
        self._registered_tokens: Set[str] = set()
        self._interactsh_enabled: bool = False
        self._interactsh_server: str = "https://app.interactsh.com"
        self._interactsh_auth_token: Optional[str] = None
        self._poll_task: Optional[asyncio.Task] = None

    @classmethod
    def get_instance(cls) -> "OOBCallbackServer":
        if cls._instance is None:
            cls._instance = OOBCallbackServer()
        return cls._instance

    def configure_interactsh(self, server_url: str = "https://app.interactsh.com", token: Optional[str] = None):
        """Configures external Interactsh server connection for live external scanning."""
        self._interactsh_enabled = True
        self._interactsh_server = server_url.rstrip("/")
        self._interactsh_auth_token = token
        if "." in server_url:
            host_part = server_url.replace("https://", "").replace("http://", "")
            self.base_domain = host_part
        logger.info(f"[OOBCallbackServer] Configured Interactsh server: {self._interactsh_server} (Domain: {self.base_domain})")

    def generate_token(self, agent_name: str, scan_id: str,
                       target_url: str = "", parameter_name: str = "",
                       protocol: InteractionProtocol = InteractionProtocol.HTTP) -> str:
        """Generates a unique tracking token for an agent payload with correlation metadata."""
        token_id = uuid.uuid4().hex[:12]
        full_token = f"{agent_name[:8].lower()}-{scan_id[:6]}-{token_id}"
        self._registered_tokens.add(full_token)
        self.correlator.register(
            token=full_token,
            agent_name=agent_name,
            scan_id=scan_id,
            target_url=target_url,
            parameter_name=parameter_name,
            expected_protocol=protocol
        )
        return full_token

    def get_callback_url(self, token: str, protocol: str = "http") -> str:
        """Returns the full target callback URL for HTTP/HTTPS protocols."""
        return f"{protocol}://{token}.{self.base_domain}/callback"

    def get_dns_payload(self, token: str) -> str:
        """Returns a DNS resolution probe payload (e.g. for blind SQLi, XXE, SSRF)."""
        return f"{token}.{self.base_domain}"

    def get_smtp_payload(self, token: str) -> str:
        """Returns an SMTP email address probe payload."""
        return f"probe@{token}.{self.base_domain}"

    def get_ldap_payload(self, token: str) -> str:
        """Returns an LDAP callback probe payload."""
        return f"ldap://{token}.{self.base_domain}:389/oob"

    def record_interaction(self, token: str, source_ip: str,
                           request_data: Dict[str, Any],
                           protocol: InteractionProtocol = InteractionProtocol.HTTP):
        """Records an incoming OOB callback hit across any supported protocol."""
        logger.info(f"[OOBCallbackServer] Out-Of-Band interaction detected for token: {token} [{protocol}] from {source_ip}")
        record = InteractionRecord(
            token=token,
            protocol=protocol,
            source_ip=source_ip,
            timestamp=time.time(),
            raw_data=request_data
        )
        if token not in self._interactions:
            self._interactions[token] = []
        self._interactions[token].append(record)

    async def poll_interactsh_events(self) -> None:
        """Polls external Interactsh server for registered tokens if enabled."""
        if not self._interactsh_enabled:
            return
        headers = {}
        if self._interactsh_auth_token:
            headers["Authorization"] = f"Bearer {self._interactsh_auth_token}"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self._interactsh_server}/poll", headers=headers)
                if resp.status_code == 200:
                    events = resp.json().get("data", [])
                    for ev in events:
                        full_id = ev.get("full-id", "")
                        for registered in list(self._registered_tokens):
                            if registered in full_id:
                                proto_str = ev.get("protocol", "http").lower()
                                proto = InteractionProtocol.HTTP
                                if proto_str == "dns":
                                    proto = InteractionProtocol.DNS
                                elif proto_str == "smtp":
                                    proto = InteractionProtocol.SMTP
                                elif proto_str == "ldap":
                                    proto = InteractionProtocol.LDAP
                                self.record_interaction(
                                    token=registered,
                                    source_ip=ev.get("remote-address", "127.0.0.1"),
                                    request_data=ev,
                                    protocol=proto
                                )
        except Exception as e:
            logger.debug(f"[OOBCallbackServer] Interactsh poll attempt: {e}")

    async def wait_for_interaction(self, token: str, timeout: float = 5.0) -> bool:
        """Polls for an incoming OOB interaction within the specified timeout."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if token in self._interactions and len(self._interactions[token]) > 0:
                return True
            if self._interactsh_enabled:
                await self.poll_interactsh_events()
                if token in self._interactions and len(self._interactions[token]) > 0:
                    return True
            await asyncio.sleep(0.2)
        return False

    def get_interaction_data(self, token: str) -> Optional[Dict[str, Any]]:
        """Returns the latest interaction record and correlated context for a token."""
        if token not in self._interactions or not self._interactions[token]:
            return None
        latest = self._interactions[token][-1]
        context = self.correlator.get_context(token) or {}
        return {
            "token": token,
            "confirmed": True,
            "latest_record": latest.to_dict(),
            "total_hits": len(self._interactions[token]),
            "context": context
        }
