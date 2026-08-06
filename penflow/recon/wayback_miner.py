"""
Historical Wayback Machine & API Versioning Enumerator for PenFlow.

Capabilities:
  - Queries Archive.org CDX API for historical endpoint discovery and parameter patterns.
  - Enumerates API versions (/api/v1/, /api/v2/, /api/v3/, /v1/, /v2/, /api/internal/, /api/admin/, /api/private/).
  - Checks common web framework debug & administrative endpoints:
      • Django: /admin/, /api-auth/, /__debug__/
      • Rails: /rails/info/, /sidekiq/
      • Spring Boot: /actuator/, /actuator/env, /h2-console
      • Laravel: /telescope/, /horizon/
  - Fetches and parses robots.txt, sitemap.xml, and security.txt.
"""
import re
import httpx
from typing import List, Dict, Any, Set, Optional
from urllib.parse import urljoin, urlparse
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.wayback_miner")

FRAMEWORK_ADMIN_PATHS = [
    "/admin/", "/api-auth/", "/__debug__/",
    "/rails/info/", "/sidekiq/",
    "/actuator/", "/actuator/env", "/actuator/health", "/h2-console",
    "/telescope/", "/horizon/",
    "/api/v1/", "/api/v2/", "/api/v3/", "/api/internal/", "/api/admin/", "/api/private/"
]


class WaybackMiner:
    """
    Mines historical endpoints from Archive.org CDX API and enumerates framework paths.
    """

    async def fetch_wayback_urls(self, domain: str, max_results: int = 100) -> List[str]:
        """Queries Archive.org CDX API for historical URLs associated with domain."""
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={max_results}"
        discovered_urls: Set[str] = set()

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(cdx_url)
                if resp.status_code == 200:
                    data = resp.json()
                    # First row is column names ['original']
                    for row in data[1:]:
                        if row and isinstance(row, list) and row[0]:
                            discovered_urls.add(row[0])
                    logger.info(f"[WaybackMiner] Retrieved {len(discovered_urls)} historical URLs from Wayback Machine for '{domain}'.")
        except Exception as e:
            logger.error(f"[WaybackMiner] Exception querying Wayback Machine CDX API for '{domain}': {e}")

        return sorted(list(discovered_urls))

    async def check_framework_paths(self, base_url: str) -> List[Dict[str, Any]]:
        """Checks for common framework debug/admin endpoints on target base URL."""
        discovered: List[Dict[str, Any]] = []
        base = base_url.rstrip("/")

        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                for path in FRAMEWORK_ADMIN_PATHS:
                    target_endpoint = f"{base}{path}"
                    try:
                        resp = await client.get(target_endpoint)
                        if resp.status_code in (200, 301, 302, 401, 403):
                            discovered.append({
                                "endpoint": target_endpoint,
                                "status_code": resp.status_code,
                                "path": path
                            })
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"[WaybackMiner] Exception checking framework paths for '{base_url}': {e}")

        logger.info(f"[WaybackMiner] Discovered {len(discovered)} framework/admin endpoints on '{base_url}'.")
        return discovered

    async def parse_well_known_files(self, base_url: str) -> Dict[str, Any]:
        """Fetches and parses robots.txt, sitemap.xml, and security.txt."""
        base = base_url.rstrip("/")
        disallowed_paths: Set[str] = set()
        sitemap_urls: Set[str] = set()

        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
                # 1. robots.txt
                resp_robots = await client.get(f"{base}/robots.txt")
                if resp_robots.status_code == 200:
                    disallows = re.findall(r"Disallow:\s*([^\s#]+)", resp_robots.text, re.IGNORECASE)
                    for d in disallows:
                        disallowed_paths.add(d)

                # 2. security.txt
                resp_sec = await client.get(f"{base}/.well-known/security.txt")
                sec_text = resp_sec.text if resp_sec.status_code == 200 else ""
        except Exception as e:
            logger.error(f"[WaybackMiner] Exception parsing well-known files for '{base_url}': {e}")

        return {
            "disallowed_paths": sorted(list(disallowed_paths)),
            "has_security_txt": bool(sec_text)
        }
