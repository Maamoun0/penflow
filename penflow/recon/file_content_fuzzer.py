"""
FileContentFuzzer — Deep File, Path & Sensitive Document Enumerator for PenFlow.

Brute-forces high-risk paths, configuration files, source code leaks, backups,
and hidden endpoints across target URLs.
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


class FileContentFuzzer:
    """
    Asynchronous Sensitive File & Directory Content Fuzzer.
    Identifies exposed backups, environment variables, source code control files, and sensitive management interfaces.
    """

    def __init__(self, concurrency: int = 15, timeout: float = 4.0):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = timeout

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

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (PenFlow/22.0 Content Discovery)"}
        ) as client:

            async def probe_path(path: str):
                full_url = urljoin(target_url, path)
                async with self.semaphore:
                    try:
                        resp = await client.get(full_url)
                        status = resp.status_code
                        if status in (200, 206, 301, 302, 401, 403):
                            content_len = len(resp.content)
                            content_type = resp.headers.get("content-type", "")

                            # Filter false positive soft 404s (e.g. status 200 returning generic HTML 404 page)
                            is_interesting = status != 404
                            if status == 200 and "text/html" in content_type:
                                body_lower = resp.text[:1024].lower()
                                if any(err in body_lower for err in ["404 not found", "page not found", "does not exist"]):
                                    is_interesting = False

                            if is_interesting:
                                discovered_files.append({
                                    "url": full_url,
                                    "path": path,
                                    "status": status,
                                    "content_length": content_len,
                                    "content_type": content_type,
                                })
                    except Exception as e:
                        logger.debug(f"[FileContentFuzzer] Error probing {full_url}: {e}")

            tasks = [probe_path(p) for p in paths[:60 if deep_mode else 30]]
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"[FileContentFuzzer] Fuzzing completed for '{target_url}': Discovered {len(discovered_files)} accessible file paths.")
        return discovered_files
