"""
Playwright Browser Engine — Phase 3: Headless Browser & SPA Renderer for PenFlow.

Provides full headless Chromium browser support to render modern Single Page Applications (React, Vue, Angular, UMI).
Extracts dynamic XHR/Fetch API endpoints, intercepts network traffic, and handles JavaScript-rendered content.
"""
import asyncio
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.browser.playwright_agent")

try:
    from playwright.async_api import async_playwright, Browser, Page, Response
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("[PlaywrightAgent] playwright package is not installed. Run: pip install playwright && playwright install chromium")


class PlaywrightBrowserAgent:
    """
    Phase 3: Headless Browser Automation & Traffic Interceptor.
    Renders SPA applications, intercepts all client-side network calls (Fetch/XHR),
    and discovers hidden dynamic API endpoints.
    """

    def __init__(self, headless: bool = True, timeout: float = 30000.0):
        self.headless = headless
        self.timeout = timeout
        self.intercepted_endpoints: Set[str] = set()
        self.captured_headers: Dict[str, str] = {}
        self.captured_tokens: Set[str] = set()

    async def render_and_harvest(
        self,
        url: str,
        wait_until: str = "networkidle",
        auth_cookies: Optional[Dict[str, str]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Navigates to URL, waits for JS rendering, and harvests all intercepted API endpoints & tokens.
        """
        if not PLAYWRIGHT_AVAILABLE:
            return {
                "error": "Playwright is not installed. Install via: pip install playwright && playwright install chromium",
                "endpoints": [],
                "success": False
            }

        discovered_apis: Set[str] = set()
        captured_requests: List[Dict[str, Any]] = []

        async with async_playwright() as p:
            try:
                browser: Browser = await p.chromium.launch(headless=self.headless)
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )

                # Set cookies if provided
                if auth_cookies:
                    domain = urlparse(url).netloc
                    cookie_list = [
                        {"name": k, "value": v, "domain": domain, "path": "/"}
                        for k, v in auth_cookies.items()
                    ]
                    await context.add_cookies(cookie_list)

                # Set extra headers if provided
                if auth_headers:
                    await context.set_extra_http_headers(auth_headers)

                page: Page = await context.new_page()

                # Event listener: Intercept network requests
                def handle_request(request):
                    req_url = request.url
                    resource_type = request.resource_type
                    # Capture Fetch, XHR, and API requests
                    if resource_type in ["fetch", "xhr"] or "/api/" in req_url or "/rest/" in req_url or "/graphql" in req_url:
                        discovered_apis.add(req_url)
                        captured_requests.append({
                            "url": req_url,
                            "method": request.method,
                            "resource_type": resource_type,
                            "headers": request.headers
                        })
                        # Check for Authorization token in headers
                        auth_header = request.headers.get("authorization", "")
                        if auth_header:
                            self.captured_tokens.add(auth_header)

                page.on("request", handle_request)

                logger.info(f"[PlaywrightAgent] Navigating to '{url}' for full JS rendering...")
                await page.goto(url, wait_until=wait_until, timeout=self.timeout)

                # Small delay for dynamic AJAX calls after page load
                await page.wait_for_timeout(3000)

                # Extract title and HTML snapshot
                page_title = await page.title()
                content = await page.content()

                await browser.close()

                logger.info(f"[PlaywrightAgent] Harvested {len(discovered_apis)} API endpoints from '{url}'")

                return {
                    "success": True,
                    "url": url,
                    "title": page_title,
                    "endpoints": list(discovered_apis),
                    "captured_requests": captured_requests,
                    "captured_tokens": list(self.captured_tokens),
                    "html_length": len(content)
                }

            except Exception as e:
                logger.error(f"[PlaywrightAgent] Failed rendering '{url}': {e}")
                return {
                    "success": False,
                    "error": str(e),
                    "endpoints": list(discovered_apis),
                }
