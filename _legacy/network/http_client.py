import asyncio
import httpx
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional

from penflow.config import Config
from penflow.utils.logger import get_logger
from penflow.utils.url_utils import extract_domain, normalize_url
from penflow.utils.hash_utils import fingerprint_request, fingerprint_response
from penflow.network.rate_limiter import AdaptiveRateLimiter
from penflow.network.circuit_breaker import CircuitBreaker
from penflow.network.cache_manager import CacheManager

logger = get_logger("penflow.network.http_client")

@dataclass
class HttpResponse:
    status: int
    headers: Dict[str, str]
    body: str
    elapsed_ms: int
    fingerprint: str
    from_cache: bool
    url: str

class HttpClient:
    def __init__(self):
        self.config = Config.load()
        self.profile = self.config.get_active_profile()
        
        self.rate_limiter = AdaptiveRateLimiter()
        self.circuit_breaker = CircuitBreaker()
        self.cache = CacheManager()
        
        # Setup httpx client
        limits = httpx.Limits(
            max_connections=self.profile.get("max_concurrency", 10) * 2,
            max_keepalive_connections=self.profile.get("max_concurrency", 10)
        )
        
        timeout = httpx.Timeout(self.profile.get("timeout_seconds", 15.0))
        
        proxy_config = self.config.get("network.proxy", {})
        proxies = None
        if proxy_config.get("enabled", False):
            proxy_url = proxy_config.get("url")
            proxies = {"http://": proxy_url, "https://": proxy_url}
            
        verify_ssl = self.config.get("network.verify_ssl", False)
        
        # Common headers
        self.default_headers = {
            "User-Agent": self.profile.get("user_agent", "PenFlow/1.0"),
            "Accept": "*/*",
            "Connection": "keep-alive"
        }
        
        self.client = httpx.AsyncClient(
            limits=limits,
            timeout=timeout,
            proxy=proxy_url if proxy_config.get("enabled", False) else None,
            verify=verify_ssl,
            follow_redirects=self.config.get("network.follow_redirects", True),
            max_redirects=self.config.get("network.max_redirects", 5)
        )

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def request(self, method: str, url: str, **kwargs) -> Optional[HttpResponse]:
        """Execute HTTP request with caching, rate limiting, and circuit breaking."""
        normalized_url = normalize_url(url)
        domain = extract_domain(normalized_url)
        
        if not domain:
            logger.error(f"Invalid URL: {url}")
            return None

        # Check circuit breaker
        if not await self.circuit_breaker.can_execute(domain):
            logger.warning(f"Circuit broken for {domain}. Skipping request.")
            return None

        # Prepare request params for fingerprinting
        params = kwargs.get("params", {})
        req_fingerprint = fingerprint_request(method, normalized_url, params)

        # Check Cache
        skip_cache = kwargs.pop("skip_cache", False)
        if not skip_cache and method.upper() in ("GET", "HEAD"):
            cached = self.cache.get(domain, req_fingerprint)
            if cached:
                return HttpResponse(
                    status=cached.status,
                    headers=cached.headers,
                    body=cached.body,
                    elapsed_ms=cached.elapsed_ms,
                    fingerprint=cached.fingerprint,
                    from_cache=True,
                    url=normalized_url
                )

        # Prepare Headers
        headers = self.default_headers.copy()
        if "headers" in kwargs:
            headers.update(kwargs["headers"])
        kwargs["headers"] = headers

        # Retry logic
        max_retries = 0 if kwargs.pop("skip_retries", False) else self.profile.get("retry_count", 3)
        for attempt in range(max_retries + 1):
            # Apply rate limiting
            await self.rate_limiter.acquire(domain)
            
            start_time = time.monotonic()
            try:
                response = await self.client.request(method, normalized_url, **kwargs)
                elapsed_ms = int((time.monotonic() - start_time) * 1000)
                
                status = response.status_code
                
                # Record response for adaptive components
                await self.rate_limiter.record_response(domain, status)
                
                if status < 500:
                    await self.circuit_breaker.record_success(domain)
                else:
                    await self.circuit_breaker.record_failure(domain)
                    if attempt < max_retries:
                        await asyncio.sleep(0.5 ** attempt)  # Reduced delay
                        continue
 
                # Process successful response
                resp_headers = dict(response.headers)
                body_text = response.text
                
                res_fingerprint = fingerprint_response(status, resp_headers, body_text)
                
                # Cache successful GET/HEAD requests
                if method.upper() in ("GET", "HEAD") and status < 400:
                    self.cache.put(
                        domain, req_fingerprint, status, 
                        resp_headers, body_text, elapsed_ms, res_fingerprint
                    )
                
                return HttpResponse(
                    status=status,
                    headers=resp_headers,
                    body=body_text,
                    elapsed_ms=elapsed_ms,
                    fingerprint=res_fingerprint,
                    from_cache=False,
                    url=str(response.url)
                )
                
            except (httpx.RequestError, httpx.TimeoutException) as e:
                logger.error(f"Request failed: {method} {normalized_url} - {str(e)}")
                await self.circuit_breaker.record_failure(domain)
                if attempt < max_retries:
                    await asyncio.sleep(0.5 ** attempt)
                else:
                    return None
 
        return None

    # Convenience methods
    async def get(self, url: str, **kwargs) -> Optional[HttpResponse]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Optional[HttpResponse]:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs) -> Optional[HttpResponse]:
        return await self.request("HEAD", url, **kwargs)
