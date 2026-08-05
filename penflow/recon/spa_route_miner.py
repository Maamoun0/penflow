"""
SPA Dynamic Route Miner & Webpack Chunk Analyzer for PenFlow.

Extracts dynamic routes and hidden API endpoints from modern SPA frameworks:
  - Next.js Build Manifests (_buildManifest.js, _ssgManifest.js)
  - React Router definitions (path: "/admin/dashboard", element: ...)
  - Vue Router routes (path: '/users/:id', component: ...)
  - Angular RouterModule definitions ({ path: 'profile', ... })
  - Webpack Dynamic Chunk Maps (u=function(e){...})
"""
import re
import httpx
from typing import List, Dict, Any, Set, Optional
from urllib.parse import urljoin
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.spa_route_miner")

NEXT_MANIFEST_PATTERN = re.compile(r'["\'](/_next/static/[^"\']+/_buildManifest\.js)["\']', re.IGNORECASE)
NEXT_ROUTE_PATTERN = re.compile(r'["\'](/[a-zA-Z0-9_\-./\[\]{}]+)["\']\s*:\s*\[', re.IGNORECASE)
REACT_ROUTER_PATTERN = re.compile(r'path\s*:\s*["\'](/[a-zA-Z0-9_\-./:]+)["\']', re.IGNORECASE)
VUE_ROUTER_PATTERN = re.compile(r'path\s*:\s*["\'](/[a-zA-Z0-9_\-./:]+)["\']', re.IGNORECASE)
ANGULAR_ROUTE_PATTERN = re.compile(r'path\s*:\s*["\']([a-zA-Z0-9_\-./:]+)["\']', re.IGNORECASE)
WEBPACK_CHUNK_PATTERN = re.compile(r'["\']static/chunks/([^"\']+\.js)["\']', re.IGNORECASE)


class SPARouteMiner:
    """
    Mines Single Page Application JavaScript bundles for hidden dynamic routes and endpoints.
    """

    def extract_routes_from_js(self, js_code: str) -> Dict[str, List[str]]:
        """Parses JavaScript code string and returns classified route lists."""
        routes: Set[str] = set()
        endpoints: Set[str] = set()

        # 1. Next.js manifest routes
        for match in NEXT_ROUTE_PATTERN.finditer(js_code):
            routes.add(match.group(1))

        # 2. React Router paths
        for match in REACT_ROUTER_PATTERN.finditer(js_code):
            routes.add(match.group(1))

        # 3. Vue Router paths
        for match in VUE_ROUTER_PATTERN.finditer(js_code):
            routes.add(match.group(1))

        # 4. Angular Router paths
        for match in ANGULAR_ROUTE_PATTERN.finditer(js_code):
            p = match.group(1)
            routes.add(f"/{p}" if not p.startswith("/") else p)

        # 5. Extract API endpoints
        api_pattern = re.compile(r'["\'](/(?:api|v\d|auth|users|admin|graphql)[a-zA-Z0-9_\-./:?=&%]+)["\']', re.IGNORECASE)
        for match in api_pattern.finditer(js_code):
            endpoints.add(match.group(1))

        # Filter out static file extensions
        clean_routes = [r for r in sorted(list(routes)) if not any(r.endswith(ext) for ext in (".png", ".jpg", ".css", ".js", ".svg"))]
        clean_endpoints = [e for e in sorted(list(endpoints)) if not any(e.endswith(ext) for ext in (".png", ".jpg", ".css", ".js", ".svg"))]

        logger.info(f"[SPARouteMiner] Extracted {len(clean_routes)} SPA routes and {len(clean_endpoints)} API endpoints.")
        return {
            "routes": clean_routes,
            "api_endpoints": clean_endpoints
        }

    async def fetch_and_mine_url(self, target_url: str) -> Dict[str, Any]:
        """Fetches main HTML page, discovers script bundles, downloads and mines them."""
        all_routes: Set[str] = set()
        all_endpoints: Set[str] = set()
        scripts_mined = 0

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(target_url)
                if resp.status_code == 200:
                    html_text = resp.text

                    # Extract inline JS routes
                    res_inline = self.extract_routes_from_js(html_text)
                    all_routes.update(res_inline["routes"])
                    all_endpoints.update(res_inline["api_endpoints"])

                    # Extract script URLs
                    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_text, re.IGNORECASE)
                    for src in script_srcs[:10]:  # Cap at top 10 scripts
                        full_script_url = urljoin(target_url, src)
                        try:
                            s_resp = await client.get(full_script_url)
                            if s_resp.status_code == 200:
                                s_res = self.extract_routes_from_js(s_resp.text)
                                all_routes.update(s_res["routes"])
                                all_endpoints.update(s_res["api_endpoints"])
                                scripts_mined += 1
                        except Exception as e:
                            logger.debug(f"[SPARouteMiner] Could not fetch script '{full_script_url}': {e}")
        except Exception as e:
            logger.error(f"[SPARouteMiner] Error mining SPA target '{target_url}': {e}")

        return {
            "target_url": target_url,
            "scripts_mined": scripts_mined,
            "total_routes": len(all_routes),
            "total_api_endpoints": len(all_endpoints),
            "routes": sorted(list(all_routes)),
            "api_endpoints": sorted(list(all_endpoints))
        }
