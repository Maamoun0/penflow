import time
import json
import asyncio
from typing import Optional, Dict, Any, List
import httpx
from penflow.traffic.models import (
    TrafficRequest,
    TrafficResponse,
    TrafficExchange,
)
from penflow.traffic.session_manager import SessionManager
from penflow.infrastructure.logger import get_logger

from penflow.traffic.proxy_engine import ProxyConfig

logger = get_logger("penflow.traffic.http_client")

class StatefulHttpClient:
    """
    Asynchronous, rate-controlled HTTP client designed for deterministic,
    auditable security research with session binding, proxy support, and scope enforcement.
    """
    def __init__(
        self,
        session_manager: Optional[SessionManager] = None,
        scope_domains: Optional[List[str]] = None,
        proxy_config: Optional[ProxyConfig] = None,
        default_timeout: float = 4.0,
        rate_limit_rps: float = 15.0,
        custom_transport: Optional[httpx.AsyncBaseTransport] = None
    ):
        self.session_manager = session_manager or SessionManager()
        self.scope_domains = scope_domains or []
        self.proxy_config = proxy_config
        self.default_timeout = default_timeout
        self.rate_limit_rps = rate_limit_rps
        self._delay_between_requests = 1.0 / rate_limit_rps if rate_limit_rps > 0 else 0.0
        self._last_request_time = 0.0
        self._custom_transport = custom_transport
        self._history: List[TrafficExchange] = []

    def _is_url_in_scope(self, url: str) -> bool:
        if not self.scope_domains:
            return True
        from urllib.parse import urlparse
        parsed = urlparse(url if "://" in url else f"https://{url}")
        hostname = (parsed.hostname or "").lower()
        for domain in self.scope_domains:
            domain_parsed = urlparse(domain if "://" in domain else f"https://{domain}")
            domain_clean = (domain_parsed.hostname or domain).lower().split(":")[0]
            if hostname == domain_clean or hostname.endswith("." + domain_clean):
                return True
        return False

    async def _enforce_rate_limit(self) -> None:
        if self._delay_between_requests <= 0:
            return
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self._delay_between_requests:
            await asyncio.sleep(self._delay_between_requests - elapsed)
        self._last_request_time = time.time()

    async def execute_request(self, req: TrafficRequest) -> TrafficExchange:
        """
        Executes a TrafficRequest, applying identity credentials, measuring latency,
        and producing an immutable TrafficExchange record.
        """
        if not self._is_url_in_scope(req.url):
            logger.warning(f"[StatefulHttpClient] URL '{req.url}' is OUT OF SCOPE. Aborting.")
            resp = TrafficResponse(
                status_code=403,
                headers={},
                body_text="PenFlow Scope Enforcement: Request blocked because target URL is out of defined scope.",
                is_error=True
            )
            return TrafficExchange(request=req, response=resp, identity_used=req.identity_id)

        await self._enforce_rate_limit()

        # Merge headers from identity
        headers = dict(req.headers)
        cookies = {}
        if req.identity_id:
            auth_hdrs = self.session_manager.get_headers_for(req.identity_id)
            headers.update(auth_hdrs)
            cookies = self.session_manager.get_cookies_for(req.identity_id)

        # Standard UA and clean headers (filter HTTP/2 pseudo-headers like :authority)
        headers = {k: v for k, v in headers.items() if not str(k).startswith(":")}
        if "User-Agent" not in headers:
            import random
            uas = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0"
            ]
            headers["User-Agent"] = random.choice(uas)

        # Basic IP Spoofing for WAF Evasion
        import random
        spoof_ip = f"{random.randint(11, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        headers.setdefault("X-Forwarded-For", spoof_ip)
        headers.setdefault("X-Originating-IP", spoof_ip)
        headers.setdefault("X-Remote-IP", spoof_ip)
        headers.setdefault("Client-IP", spoof_ip)

        start_time = time.time()
        
        req_url = req.url
        if req_url.startswith("https://127.0.0.1") or req_url.startswith("https://localhost"):
            req_url = req_url.replace("https://", "http://", 1)

        try:
            # Build proxy and SSL settings from ProxyConfig
            proxy_url = None
            verify_ssl = False if ("127.0.0.1" in req_url or "localhost" in req_url) else True
            if self.proxy_config:
                proxies_dict = self.proxy_config.get_proxies_dict()
                # httpx uses a single proxy= parameter
                proxy_url = proxies_dict.get("https://") or proxies_dict.get("http://") or None
                verify_ssl = self.proxy_config.verify_ssl
                if self.proxy_config.ca_bundle_path:
                    verify_ssl = self.proxy_config.ca_bundle_path

            async with httpx.AsyncClient(
                timeout=req.timeout or self.default_timeout,
                transport=self._custom_transport,
                cookies=cookies if cookies else None,
                follow_redirects=False,
                proxy=proxy_url,
                verify=verify_ssl
            ) as client:
                http_resp = await client.request(
                    method=req.method.upper(),
                    url=req_url,
                    headers=headers,
                    params=req.params if req.params else None,
                    content=req.body.encode("utf-8") if req.body else None,
                    json=req.json_data if req.json_data is not None else None
                )

                elapsed_ms = (time.time() - start_time) * 1000.0
                body_text = http_resp.text
                body_json = None
                try:
                    body_json = http_resp.json()
                except Exception:
                    body_json = None

                resp_headers = dict(http_resp.headers)

                if http_resp.status_code == 429:
                    # Adaptive jitter backoff: pause briefly when rate limited to prevent WAF lockouts
                    import random
                    retry_after = http_resp.headers.get("Retry-After")
                    delay = float(retry_after) if retry_after and retry_after.isdigit() else random.uniform(1.5, 3.5)
                    logger.warning(f"[StatefulHttpClient] HTTP 429 Rate-Limited on '{req.url}'. Applying adaptive backoff ({delay:.2f}s)...")
                    await asyncio.sleep(delay)

                # Persist received Set-Cookie headers into the active identity
                if req.identity_id and http_resp.cookies:
                    ident = self.session_manager.get_identity(req.identity_id)
                    if ident and ident.credentials:
                        for c_name, c_val in http_resp.cookies.items():
                            ident.credentials.cookies[c_name] = c_val

                traffic_response = TrafficResponse(
                    status_code=http_resp.status_code,
                    headers=resp_headers,
                    body_text=body_text,
                    body_json=body_json,
                    content_length=len(body_text.encode("utf-8")),
                    response_time_ms=elapsed_ms,
                    is_error=http_resp.is_error
                )

                if http_resp.status_code in [502, 503, 504]:
                    raise httpx.HTTPError(f"Transient Error: {http_resp.status_code}")

                exchange = TrafficExchange(
                    request=req,
                    response=traffic_response,
                    elapsed_ms=elapsed_ms,
                    identity_used=req.identity_id
                )
                self._history.append(exchange)
                return exchange

        except (httpx.HTTPError, httpx.TimeoutException, Exception) as ex:
            import random
            # Exponential Backoff with Jitter for transient network faults
            if not hasattr(req, "_retry_count"):
                req._retry_count = 0
            
            if req._retry_count < 3:
                req._retry_count += 1
                delay = (2 ** req._retry_count) + random.uniform(0.1, 1.0)
                logger.warning(f"[StatefulHttpClient] Transient fault on '{req.url}' ({str(ex)}). Retrying {req._retry_count}/3 in {delay:.2f}s...")
                await asyncio.sleep(delay)
                return await self.execute_request(req)
                
            elapsed_ms = (time.time() - start_time) * 1000.0
            logger.error(f"[StatefulHttpClient] Error executing request to '{req.url}': {str(ex)}")
            
            error_response = TrafficResponse(
                status_code=0,
                headers={},
                body_text=f"Network/Connection Error: {str(ex)}",
                is_error=True,
                response_time_ms=elapsed_ms
            )
            exchange = TrafficExchange(
                request=req,
                response=error_response,
                elapsed_ms=elapsed_ms,
                identity_used=req.identity_id
            )
            self._history.append(exchange)
            return exchange

    async def send_as_identity(
        self,
        identity_id: str,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Any] = None,
        body: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> TrafficExchange:
        req = TrafficRequest(
            method=method,
            url=url,
            headers=headers or {},
            params=params or {},
            json_data=json_data,
            body=body,
            identity_id=identity_id
        )
        return await self.execute_request(req)

    def get_history(self) -> List[TrafficExchange]:
        return list(self._history)
