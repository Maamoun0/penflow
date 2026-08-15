"""
SmartCrawler — Elite Deep Web Crawler & Attack Surface Extractor for PenFlow.

Capabilities:
  - Full HTML attribute extraction: href, action, src, srcset, data-url, data-src,
    data-href, data-endpoint, content (meta refresh), formaction
  - JavaScript bundle mining: fetch(), axios, XMLHttpRequest, apiUrl, baseURL,
    React Router, Angular, Vue Router path extraction
  - Query parameter extraction and cataloguing for injection testing
  - WebSocket URL detection (ws://, wss://)
  - Form analysis with field-level parameter extraction
  - Depth-controlled BFS crawling with configurable page budget
  - Parallel JS file mining (all files in deep mode)
"""
import httpx
import re
from urllib.parse import urlparse, urljoin, parse_qs
from typing import Set, Dict, List, Any, Optional, Tuple
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.smart_crawler")


# ─────────────────────────────────────────────────────────
# Regex Patterns for JS Mining
# ─────────────────────────────────────────────────────────

# Classic API path patterns (quoted strings beginning with / followed by api/v1/etc.)
JS_API_PATH_PATTERN = re.compile(
    r'["\']'
    r'(/(?:api|v\d|auth|users|user|admin|graphql|oauth|token|webhook|service|'
    r'internal|private|account|accounts|profile|settings|config|management|'
    r'billing|subscription|search|data|export|import|report|upload|download|'
    r'file|files|media|assets)[a-zA-Z0-9_\-./{}:?=&%+]*)'
    r'["\']',
    re.IGNORECASE
)

# fetch() / axios / XMLHttpRequest URL patterns
JS_FETCH_PATTERN = re.compile(
    r'(?:fetch|axios\.get|axios\.post|axios\.put|axios\.delete|axios\.patch|'
    r'\.get|\.post|\.put|\.delete)\s*\(\s*["\']'
    r'(/[a-zA-Z0-9_\-./{}:?=&%+]+)'
    r'["\']',
    re.IGNORECASE
)

# baseURL / apiUrl / endpoint constant assignments
JS_BASE_URL_PATTERN = re.compile(
    r'(?:baseURL|baseUrl|apiUrl|API_URL|apiEndpoint|BASE_URL|endpoint|'
    r'API_BASE|apiBase|serviceUrl|SERVICE_URL)\s*[=:]\s*["\']'
    r'([^"\']+)'
    r'["\']',
    re.IGNORECASE
)

# React Router / Angular / Vue router path definitions
JS_ROUTER_PATTERN = re.compile(
    r'(?:path|route|component)\s*[:=]\s*["\']'
    r'(/[a-zA-Z0-9_\-./{}:?=&%+]*)'
    r'["\']',
    re.IGNORECASE
)

# WebSocket URL detection
JS_WEBSOCKET_PATTERN = re.compile(
    r'new\s+WebSocket\s*\(\s*["\']'
    r'(wss?://[^"\']+)'
    r'["\']',
    re.IGNORECASE
)

# Template literal API calls: `${baseUrl}/api/v1/users`
JS_TEMPLATE_LITERAL_PATTERN = re.compile(
    r'`\$\{[^}]+\}(/(?:api|v\d|auth|user|admin)[a-zA-Z0-9_\-./{}:?=&%]*)`',
    re.IGNORECASE
)

# HTML attribute patterns
HTML_SRC_PATTERN = re.compile(
    r'(?:src|href|action|srcset|data-url|data-src|data-href|data-endpoint|formaction)\s*=\s*(?:["\']([^"\']+)["\']|([^\s>"\']+))',
    re.IGNORECASE
)
HTML_META_REFRESH_PATTERN = re.compile(
    r'<meta[^>]+content\s*=\s*(?:["\'][^"\']*url\s*=\s*([^"\']+)["\']|[^>]*url\s*=\s*([^\s>"\']+))',
    re.IGNORECASE
)
HTML_SCRIPT_SRC_PATTERN = re.compile(
    r'<script[^>]*\ssrc\s*=\s*(?:["\']([^"\']+\.js[^"\']*)["\']|([^\s>"\']+\.js[^\s>"\']*))',
    re.IGNORECASE
)
HTML_FORM_PATTERN = re.compile(
    r'<form[^>]*>(.*?)</form>',
    re.IGNORECASE | re.DOTALL
)
HTML_INPUT_PATTERN = re.compile(
    r'<(?:input|select|textarea|button)\b[^>]*\bname\s*=\s*(?:["\']([^"\']+)["\']|([^\s>"\']+))',
    re.IGNORECASE
)
HTML_LINK_PATTERN = re.compile(
    r'href\s*=\s*(?:["\']([^"\']+)["\']|([^\s>"\']+))',
    re.IGNORECASE
)

# Static file extensions to skip crawling
STATIC_EXTENSIONS = frozenset([
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
    ".pdf", ".zip", ".tar", ".gz", ".map", ".webp", ".avif",
])


class SmartCrawler:
    """
    Elite asynchronous, structure-aware web crawler that exhaustively discovers
    endpoints, forms, query parameters, JS API routes, and WebSocket URLs.
    Serves as the primary attack surface enumerator for all downstream agents.
    """

    def __init__(self, max_depth: int = 2, max_pages: int = 25, timeout: float = 10.0):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited_urls: Set[str] = set()

    async def crawl(self, start_url: str) -> Dict[str, Any]:
        if not start_url.startswith("http://") and not start_url.startswith("https://"):
            start_url = f"https://{start_url}"

        parsed_start = urlparse(start_url)
        target_domain = parsed_start.netloc.lower()

        root_status_code: int = 0
        discovered_endpoints: List[Dict[str, Any]] = []
        discovered_forms: List[Dict[str, Any]] = []
        discovered_js: List[str] = []
        all_parameters: Dict[str, Set[str]] = {}  # url -> set of param names
        websocket_urls: List[str] = []

        queue: List[Tuple[str, int]] = [(start_url, 0)]
        self.visited_urls.add(start_url)

        DEFAULT_BROWSER_HEADERS = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers=DEFAULT_BROWSER_HEADERS
        ) as client:
            while queue and len(self.visited_urls) <= self.max_pages:
                curr_url, depth = queue.pop(0)

                try:
                    resp = await client.get(curr_url)
                    status_code = resp.status_code
                    if curr_url == start_url or root_status_code == 0:
                        root_status_code = status_code

                    # Check for dead/expired lab containers (HTTP 504 Gateway Timeout)
                    if curr_url == start_url and (status_code in (502, 503, 504) or "gateway timeout" in resp.text.lower()):
                        logger.warning(f"[SmartCrawler] Target '{target_domain}' returned HTTP {status_code} (Gateway Timeout / Offline Container).")
                        return {
                            "domain": target_domain,
                            "status_code": status_code,
                            "is_reachable": False,
                            "is_expired": True,
                            "error": f"Target server returned HTTP {status_code} Gateway Timeout. Target container is expired or offline.",
                            "endpoints": [],
                            "discovered_urls": [],
                            "forms": [],
                            "js_files": [],
                            "mined_js_routes": [],
                            "websocket_urls": [],
                        }

                    content_type = resp.headers.get("content-type", "")

                    # Extract any query parameters from this URL
                    parsed_curr = urlparse(curr_url)
                    q_params = parse_qs(parsed_curr.query)
                    if q_params:
                        if curr_url not in all_parameters:
                            all_parameters[curr_url] = set()
                        all_parameters[curr_url].update(q_params.keys())

                    discovered_endpoints.append({
                        "url": curr_url,
                        "status": status_code,
                        "content_type": content_type,
                        "depth": depth,
                        "parameters": list(q_params.keys()),
                    })

                    if "text/html" in content_type and depth < self.max_depth:
                        html_text = resp.text

                        # Extract all HTML attributes with URLs (quoted or unquoted)
                        attr_links_raw = HTML_SRC_PATTERN.findall(html_text)
                        for m in attr_links_raw:
                            raw_link = m[0] if (isinstance(m, tuple) and m[0]) else (m[1] if isinstance(m, tuple) else m)
                            if not raw_link:
                                continue
                            link = raw_link.strip().split(" ")[0]  # handle srcset multiple
                            if link.startswith(("javascript:", "data:", "#", "mailto:")):
                                continue
                            abs_link = urljoin(curr_url, link)
                            parsed_link = urlparse(abs_link)
                            link_netloc = parsed_link.netloc.lower()

                            # Match exact target_domain OR any subdomain of target_domain
                            is_in_scope = (
                                link_netloc == target_domain or
                                link_netloc.endswith("." + target_domain) or
                                (target_domain.startswith("www.") and link_netloc.endswith("." + target_domain[4:]))
                            )

                            if is_in_scope and abs_link not in self.visited_urls:
                                path_lower = parsed_link.path.lower()
                                if not any(path_lower.endswith(ext) for ext in STATIC_EXTENSIONS):
                                    self.visited_urls.add(abs_link)
                                    queue.append((abs_link, depth + 1))

                        # Extract meta refresh redirects
                        for m in HTML_META_REFRESH_PATTERN.findall(html_text):
                            raw_meta = m[0] if (isinstance(m, tuple) and m[0]) else (m[1] if isinstance(m, tuple) else m)
                            if not raw_meta:
                                continue
                            abs_link = urljoin(curr_url, raw_meta.strip())
                            link_netloc = urlparse(abs_link).netloc.lower()
                            is_in_scope = (
                                link_netloc == target_domain or
                                link_netloc.endswith("." + target_domain) or
                                (target_domain.startswith("www.") and link_netloc.endswith("." + target_domain[4:]))
                            )
                            if is_in_scope and abs_link not in self.visited_urls:
                                self.visited_urls.add(abs_link)
                                queue.append((abs_link, depth + 1))

                        # Extract JS script src files
                        for m in HTML_SCRIPT_SRC_PATTERN.findall(html_text):
                            raw_js = m[0] if (isinstance(m, tuple) and m[0]) else (m[1] if isinstance(m, tuple) else m)
                            if not raw_js:
                                continue
                            abs_js = urljoin(curr_url, raw_js.strip())
                            if abs_js not in discovered_js:
                                discovered_js.append(abs_js)

                        # Extract forms and their input parameters (quoted or unquoted)
                        for form_html in HTML_FORM_PATTERN.findall(html_text):
                            action_match = re.search(r'\baction\s*=\s*(?:["\']([^"\']*)["\']|([^\s>"\']+))', form_html, re.IGNORECASE)
                            method_match = re.search(r'\bmethod\s*=\s*(?:["\']([^"\']*)["\']|([^\s>"\']+))', form_html, re.IGNORECASE)
                            raw_action = (action_match.group(1) or action_match.group(2)) if action_match else ""
                            raw_method = (method_match.group(1) or method_match.group(2)) if method_match else "GET"
                            action = urljoin(curr_url, raw_action) if raw_action else curr_url
                            method = raw_method.upper() if raw_method else "GET"

                            input_matches = HTML_INPUT_PATTERN.findall(form_html)
                            all_inputs = list(set([
                                (im[0] or im[1]).strip()
                                for im in input_matches
                                if (im[0] or im[1])
                            ]))
                            discovered_forms.append({
                                "action": action,
                                "method": method,
                                "parameters": all_inputs,
                            })
                            discovered_endpoints.append({
                                "url": action,
                                "status": 200,
                                "content_type": "application/x-www-form-urlencoded",
                                "depth": depth,
                                "method": method,
                                "parameters": all_inputs,
                            })

                except Exception as e:
                    logger.warning(f"[SmartCrawler] Error crawling '{curr_url}': {type(e).__name__}: {str(e)}")

        # ── JS Mining Phase ──────────────────────────────────────────────────────
        mined_js_endpoints: List[str] = []
        mined_js_params: List[str] = []
        js_to_mine = discovered_js  # mine ALL in deep mode; caller sets max_pages accordingly

        if js_to_mine:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
                headers=DEFAULT_BROWSER_HEADERS
            ) as js_client:
                for js_url in js_to_mine:
                    try:
                        js_resp = await js_client.get(js_url)
                        if js_resp.status_code != 200:
                            continue
                        js_text = js_resp.text

                        # 1. Classic API path patterns
                        for route in JS_API_PATH_PATTERN.findall(js_text):
                            full_url = urljoin(start_url, route)
                            if full_url not in mined_js_endpoints:
                                mined_js_endpoints.append(full_url)

                        # 2. fetch/axios patterns
                        for route in JS_FETCH_PATTERN.findall(js_text):
                            full_url = urljoin(start_url, route)
                            if full_url not in mined_js_endpoints:
                                mined_js_endpoints.append(full_url)

                        # 3. baseURL / apiUrl constants
                        for base in JS_BASE_URL_PATTERN.findall(js_text):
                            if base.startswith("/") or "://" in base:
                                full = urljoin(start_url, base) if base.startswith("/") else base
                                if full not in mined_js_endpoints:
                                    mined_js_endpoints.append(full)

                        # 4. Router path definitions
                        for path in JS_ROUTER_PATTERN.findall(js_text):
                            full_url = urljoin(start_url, path)
                            if full_url not in mined_js_endpoints:
                                mined_js_endpoints.append(full_url)

                        # 5. WebSocket URLs
                        for ws_url in JS_WEBSOCKET_PATTERN.findall(js_text):
                            if ws_url not in websocket_urls:
                                websocket_urls.append(ws_url)

                        # 6. Template literal paths
                        for path in JS_TEMPLATE_LITERAL_PATTERN.findall(js_text):
                            full_url = urljoin(start_url, path)
                            if full_url not in mined_js_endpoints:
                                mined_js_endpoints.append(full_url)

                        # 7. Extract probable param names from JS variable assignments
                        param_matches = re.findall(
                            r'(?:params|data|payload|body|query)\s*[=:]\s*\{([^}]{0,500})\}',
                            js_text, re.IGNORECASE
                        )
                        for match in param_matches:
                            keys = re.findall(r'["\']?(\w+)["\']?\s*:', match)
                            mined_js_params.extend(keys)

                    except Exception as e:
                        logger.debug(f"[SmartCrawler] Failed to mine JS '{js_url}': {str(e)}")

        # Add mined JS endpoints to discovered list
        for full_url in mined_js_endpoints:
            discovered_endpoints.append({
                "url": full_url,
                "status": 200,
                "content_type": "mined_js_route",
                "depth": 99,
                "parameters": [],
            })

        logger.info(
            f"[SmartCrawler] Crawling finished for '{target_domain}': "
            f"Discovered {len(discovered_endpoints)} endpoints, {len(discovered_forms)} forms, "
            f"{len(discovered_js)} JS files, {len(mined_js_endpoints)} JS-mined routes, "
            f"{len(websocket_urls)} WebSocket URLs."
        )

        return {
            "domain": target_domain,
            "status_code": root_status_code,
            "is_reachable": bool(discovered_endpoints or root_status_code > 0),
            "endpoints": discovered_endpoints,
            "discovered_urls": [ep["url"] for ep in discovered_endpoints],
            "forms": discovered_forms,
            "js_files": discovered_js,
            "mined_js_routes": mined_js_endpoints,
            "websocket_urls": websocket_urls,
            "all_parameters": {url: list(params) for url, params in all_parameters.items()},
            "mined_js_params": list(set(mined_js_params)),
        }
