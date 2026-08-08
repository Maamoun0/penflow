"""
FileContentFuzzer — Deep File, Path & Sensitive Document Enumerator for PenFlow.

Brute-forces high-risk paths, configuration files, source code leaks, backups,
and hidden endpoints across target URLs.

Phase 1 Enhancement: Integrates SmartHttpVerifier for 3-layer False Positive
elimination before recording any finding.
"""
import httpx
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.file_content_fuzzer")

# High-density wordlist for sensitive file & directory fuzzing
SENSITIVE_FILE_WORDLIST = [
    # Environment & Config
    "/.env", "/.env.local", "/.env.production", "/.env.staging", "/.env.backup", "/.env.bak", "/.env.old",
    "/config.json", "/config.yml", "/config.yaml", "/config.php", "/wp-config.php", "/settings.py",
    "/application.yml", "/application.properties", "/database.yml", "/database.php",
    # Source Code Leaks
    "/.git/HEAD", "/.git/config", "/.git/index", "/.svn/entries", "/.svn/wc.db", "/.hg/hgrc",
    # Backup & Database Dumps
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql", "/dump.sql", "/data.sql", "/site.sql",
    "/database.sql", "/db_backup.sql", "/archive.zip", "/www.zip", "/site.zip",
    # Packages & Locks
    "/package.json", "/package-lock.json", "/composer.json", "/composer.lock", "/yarn.lock",
    "/Gemfile", "/Gemfile.lock", "/requirements.txt", "/Pipfile", "/Dockerfile", "/docker-compose.yml",
    # Logs & Server Config
    "/access.log", "/error.log", "/app.log", "/debug.log", "/server-status", "/server-info",
    "/.htaccess", "/.htpasswd", "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml",
    # Admin & Management
    "/admin", "/admin/", "/admin/login", "/dashboard", "/manage", "/console", "/panel", "/phpmyadmin/",
]

# SPA/catch-all response indicators — pages that return HTTP 200 for every route
HTML_CATCHALL_MARKERS = [
    "<!doctype html", "<html", "loading...", "__next", "umi.", "react", "vue", "angular",
    "document management", "root</div>", "id=\"app\"", "id=\"root\"",
]


class FileContentFuzzer:
    """
    Asynchronous Sensitive File & Directory Content Fuzzer.
    Identifies exposed backups, environment variables, source code control files,
    and sensitive management interfaces.

    Phase 1: Now includes SmartHttpVerifier integration to eliminate False Positives
    by running 3-layer verification on every potential finding:
      1. Baseline fingerprint comparison (detect SPA soft-404)
      2. Content-type and length differential analysis
      3. File-type specific content signature matching
    """

    def __init__(self, concurrency: int = 15, timeout: float = 4.0):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = timeout

    async def _establish_baseline(self, client: httpx.AsyncClient, base_url: str) -> Dict[str, Any]:
        """Get a baseline 404 fingerprint for this server."""
        try:
            r = await client.get(f"{base_url}/__penflow_probe_xyzabc8f7a__")
            return {
                "status": r.status_code,
                "length": len(r.content),
                "is_html": "text/html" in r.headers.get("content-type", ""),
                "body_snippet": r.text[:512].lower(),
            }
        except Exception:
            return {"status": 404, "length": 0, "is_html": False, "body_snippet": ""}

    def _is_soft_404(self, resp: httpx.Response, baseline: Dict[str, Any]) -> bool:
        """Detect if a 200 response is actually a SPA catch-all page."""
        if resp.status_code != 200:
            return False
        ct = resp.headers.get("content-type", "")
        if "text/html" not in ct:
            return False
        # Compare length with baseline (within 10% = same page)
        if baseline["status"] == 200 and baseline["length"] > 0:
            diff_ratio = abs(len(resp.content) - baseline["length"]) / baseline["length"]
            if diff_ratio < 0.10:
                return True
        # Check for SPA shell markers
        body_lower = resp.text[:1500].lower()
        hits = sum(1 for m in HTML_CATCHALL_MARKERS if m in body_lower)
        return hits >= 2

    def _has_real_content(self, path: str, resp: httpx.Response) -> bool:
        """
        Validate the response body matches the expected content type for this path.
        This is the core False Positive filter for sensitive files.
        """
        import re
        ct = resp.headers.get("content-type", "")
        body = resp.text
        body_bytes = resp.content

        # .env files must contain KEY=VALUE pairs
        if ".env" in path:
            if re.search(r'[A-Z_]{3,}=[^\n]{2,}', body[:2000]):
                return True
            return False

        # .git files must have binary or git-specific headers
        if ".git/" in path:
            if body_bytes[:4] == b'DIRC' or b'ref: refs/' in body_bytes[:100] or b'[core]' in body_bytes[:200]:
                return True
            return False

        # SQL files must have SQL statements
        if any(x in path for x in [".sql", "/dump", "/backup"]):
            if re.search(r'(CREATE TABLE|INSERT INTO|-- MySQL|-- PostgreSQL)', body[:3000], re.I):
                return True
            return False

        # JSON/YAML config must have actual key-value structure
        if path.endswith((".json", ".yaml", ".yml")):
            if body.strip().startswith(("{", "[")):
                return True
            return False

        # Dependency files: check for known markers
        if path in ["/package.json", "/package-lock.json", "/yarn.lock", "/Pipfile", "/requirements.txt"]:
            if '"name"' in body or '"version"' in body or "[[package]]" in body or "==" in body:
                return True
            return False

        # Apache server-status: must contain specific text
        if "server-status" in path:
            return "Apache Server Status" in body or "Server Version" in body

        # Admin/login: 200 or redirect is sufficient for these
        if any(x in path for x in ["/admin", "/login", "/dashboard", "/console"]):
            return True

        # For other paths: accept non-HTML 200 responses
        if resp.status_code == 200 and "text/html" not in ct:
            return True

        return False

    async def fuzz_files(
        self,
        target_url: str,
        custom_paths: Optional[List[str]] = None,
        deep_mode: bool = False
    ) -> List[Dict[str, Any]]:
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        paths = list(set(SENSITIVE_FILE_WORDLIST + (custom_paths or [])))
        discovered_files: List[Dict[str, Any]] = []
        eliminated_fps: int = 0

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (PenFlow/22.0 Content Discovery)"}
        ) as client:

            # Phase 1: Establish baseline FIRST
            baseline = await self._establish_baseline(client, target_url)
            logger.debug(f"[FileContentFuzzer] Baseline for {target_url}: status={baseline['status']}, len={baseline['length']}")

            async def probe_path(path: str):
                nonlocal eliminated_fps
                full_url = urljoin(target_url, path)
                async with self.semaphore:
                    try:
                        resp = await client.get(full_url)
                        status = resp.status_code

                        if status not in (200, 206, 401, 403):
                            return

                        content_len = len(resp.content)
                        content_type = resp.headers.get("content-type", "")

                        # --- Phase 1: Soft-404 / SPA catch-all detection ---
                        if self._is_soft_404(resp, baseline):
                            eliminated_fps += 1
                            logger.debug(f"[FileContentFuzzer] SOFT-404 eliminated: {full_url}")
                            return

                        # --- Phase 2: Auth-required endpoints (always valid findings) ---
                        if status in (401, 403):
                            discovered_files.append({
                                "url": full_url,
                                "path": path,
                                "status": status,
                                "content_length": content_len,
                                "content_type": content_type,
                                "verified": True,
                                "evidence": f"Protected resource exists (HTTP {status})",
                                "confidence": 0.70,
                            })
                            return

                        # --- Phase 3: Content signature validation for 200 responses ---
                        if status == 200:
                            if not self._has_real_content(path, resp):
                                eliminated_fps += 1
                                logger.debug(f"[FileContentFuzzer] FALSE-POSITIVE eliminated (bad content): {full_url}")
                                return

                            discovered_files.append({
                                "url": full_url,
                                "path": path,
                                "status": status,
                                "content_length": content_len,
                                "content_type": content_type,
                                "verified": True,
                                "evidence": f"Genuine sensitive file: {resp.text[:150]}",
                                "confidence": 0.92,
                            })

                    except Exception as e:
                        logger.debug(f"[FileContentFuzzer] Error probing {full_url}: {e}")

            tasks = [probe_path(p) for p in paths[:60 if deep_mode else 30]]
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(
            f"[FileContentFuzzer] Fuzzing completed for '{target_url}': "
            f"Discovered {len(discovered_files)} verified paths "
            f"({eliminated_fps} false positives eliminated)."
        )
        return discovered_files
