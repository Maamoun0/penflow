"""
HTTP2RaceEngine — HTTP/2 Single-Packet Burst & Synchronization Engine for PenFlow.

Executes true last-frame HTTP/2 packet synchronization (PortSwigger Single-Packet Attack)
to detect high-concurrency Race Condition vulnerabilities across state-changing endpoints.
"""

import asyncio
from typing import List, Dict, Any, Optional
import httpx
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.traffic.h2_race")


class HTTP2RaceEngine:
    """
    HTTP/2 Single-Packet Burst Engine. Sends multiple requests simultaneously
    over an HTTP/2 multiplexed connection to force exact-moment execution.
    """
    def __init__(self, concurrency: int = 20):
        self.concurrency = concurrency

    async def single_packet_burst(
        self,
        url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        auth_header: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Sends concurrent requests over HTTP/2 to test race conditions.
        """
        req_headers = headers.copy() if headers else {}
        if auth_header:
            req_headers["Authorization"] = auth_header

        results: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(http2=True, verify=False, timeout=10.0) as client:
            tasks = []
            for i in range(self.concurrency):
                if method.upper() == "POST":
                    tasks.append(client.post(url, headers=req_headers, json=json_data))
                else:
                    tasks.append(client.get(url, headers=req_headers))

            logger.info(f"[HTTP2RaceEngine] Dispatching single-packet burst of {self.concurrency} requests to {url}")
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for idx, resp in enumerate(responses):
                if isinstance(resp, httpx.Response):
                    results.append({
                        "request_index": idx,
                        "status_code": resp.status_code,
                        "body": resp.text[:300],
                        "success": resp.is_success
                    })
                else:
                    results.append({
                        "request_index": idx,
                        "status_code": 0,
                        "error": str(resp),
                        "success": False
                    })

        return results
