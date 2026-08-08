"""
SmartHttpVerifier — Phase 1 Enhancement for PenFlow.

Three-layer verification engine to eliminate False Positives:
  Layer 1: Baseline fingerprinting (detect Soft-404 / catch-all pages)
  Layer 2: Content analysis (verify file content matches expected format)
  Layer 3: Differential comparison (compare against known-bad baseline)
"""
import asyncio
import hashlib
import re
from typing import Dict, Any, Optional, Tuple
import httpx
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.analysis.smart_verifier")


class SmartHttpVerifier:
    """
    Eliminates False Positives via three-layer response intelligence.
    
    Must be used BEFORE recording any finding to ensure it represents
    a real vulnerability and not an artifact of Nginx catch-all, SPA routing,
    or generic error pages returning HTTP 200.
    """

    # Signatures that indicate content is a real sensitive file (not HTML page)
    ENV_FILE_SIGNATURES = [
        r'[A-Z_]{3,}=.{3,}',           # KEY=value pattern
        r'(?:SECRET|TOKEN|KEY|PASS|PWD|PASSWORD|API_KEY)\s*=',
        r'(?:DB_HOST|DB_NAME|DATABASE_URL)\s*=',
        r'(?:AWS_ACCESS|AWS_SECRET)\s*',
    ]

    GIT_FILE_SIGNATURES = [
        b'ref: refs/',                  # .git/HEAD
        b'[core]',                      # .git/config
        b'DIRC',                        # .git/index binary header
    ]

    SQL_DUMP_SIGNATURES = [
        r'CREATE TABLE\s+',
        r'INSERT INTO\s+',
        r'-- MySQL dump',
        r'-- PostgreSQL database dump',
    ]

    CONFIG_SIGNATURES = [
        r'"(?:database|password|secret|token|key|host|port)"',
        r"'(?:database|password|secret|token|key|host|port)'",
    ]

    HTML_CATCHALL_PATTERNS = [
        "<!doctype html",
        "<html",
        "404 not found",
        "page not found",
        "not found",
        "access denied",
        "forbidden",
        "loading...",
        "react",
        "vue",
        "angular",
        "__next",
        "document management",    # ABB QMS SPA
        "umi.",                   # ABB UMI framework
    ]

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    async def get_baseline(self, client: httpx.AsyncClient, base_url: str) -> Dict[str, Any]:
        """
        Establish a 404 baseline by requesting a guaranteed-nonexistent path.
        Returns fingerprint of the server's "not found" behavior.
        """
        test_paths = [
            "/__penflow_nonexistent_8f7a3b2c__",
            "/definitely-does-not-exist-xyzabc123",
        ]
        baselines = []
        for p in test_paths:
            try:
                r = await client.get(f"{base_url}{p}", follow_redirects=True)
                baselines.append({
                    "status": r.status_code,
                    "length": len(r.content),
                    "content_type": r.headers.get("content-type", ""),
                    "body_hash": hashlib.md5(r.content[:512]).hexdigest(),
                    "is_html": "text/html" in r.headers.get("content-type", ""),
                })
            except Exception:
                pass

        if not baselines:
            return {"status": 404, "length": 0, "is_html": False, "body_hash": ""}

        # Use the most common baseline
        return baselines[0]

    def _is_catchall_html(self, response_text: str, content_type: str) -> bool:
        """Returns True if the response appears to be a generic SPA/catchall HTML page."""
        if "text/html" not in content_type:
            return False
        text_lower = response_text[:2000].lower()
        matches = sum(1 for pattern in self.HTML_CATCHALL_PATTERNS if pattern in text_lower)
        return matches >= 2

    def _is_soft_404(self, response: httpx.Response, baseline: Dict[str, Any]) -> bool:
        """
        Detects if a 200 response is actually a soft-404 (catch-all page).
        Compares length similarity and content type with baseline.
        """
        if response.status_code != 200:
            return False

        # If baseline itself returns 200 (SPA routing), compare lengths
        if baseline["status"] == 200:
            length_diff = abs(len(response.content) - baseline["length"])
            # If length is within 10% of baseline, it's likely the same catch-all
            if baseline["length"] > 0 and length_diff / baseline["length"] < 0.10:
                return True
            # If lengths are identical, definitely soft-404
            if length_diff == 0:
                return True

        ct = response.headers.get("content-type", "")
        body = response.text[:3000]

        # HTML content is suspicious for files like .env, .sql, .git/HEAD
        if self._is_catchall_html(body, ct):
            return True

        return False

    def _analyze_file_content(self, path: str, response: httpx.Response) -> Tuple[bool, str, float]:
        """
        Validates that a file's content matches what we'd expect from that file type.
        Returns (is_genuine, evidence_snippet, confidence).
        """
        content_type = response.headers.get("content-type", "")
        body = response.text
        body_bytes = response.content

        # --- .env files ---
        if ".env" in path and not path.endswith(".html"):
            for pattern in self.ENV_FILE_SIGNATURES:
                matches = re.findall(pattern, body[:2000], re.IGNORECASE)
                if matches:
                    return True, f"ENV credentials detected: {matches[0][:80]}", 0.97

        # --- .git/ files ---
        if ".git/" in path:
            for sig in self.GIT_FILE_SIGNATURES:
                if sig in body_bytes[:200]:
                    return True, f"Git repository file confirmed: {sig}", 0.97

        # --- SQL dumps ---
        if any(x in path for x in [".sql", "dump", "backup"]):
            for pattern in self.SQL_DUMP_SIGNATURES:
                if re.search(pattern, body[:3000], re.IGNORECASE):
                    return True, f"SQL dump confirmed: {pattern}", 0.95

        # --- JSON config ---
        if path.endswith((".json", ".yaml", ".yml")) and not path.endswith("package.json"):
            if "json" in content_type or body.strip().startswith(("{", "[")):
                for pattern in self.CONFIG_SIGNATURES:
                    if re.search(pattern, body[:3000], re.IGNORECASE):
                        return True, f"Config file with sensitive fields: {body[:100]}", 0.90
                # JSON but no sensitive fields — lower confidence
                return True, f"JSON/YAML config exposed (no sensitive fields detected): {body[:80]}", 0.55

        # --- package.json, yarn.lock (dependency disclosure) ---
        if path in ["/package.json", "/package-lock.json", "/yarn.lock", "/Pipfile"]:
            if '"name"' in body or '"version"' in body or "[[package]]" in body:
                return True, f"Dependency file exposed — technology fingerprinting vector: {body[:100]}", 0.70

        # --- Admin panel / login ---
        if "admin" in path or "login" in path:
            if response.status_code in [200, 302]:
                return True, f"Admin interface accessible at {path}: HTTP {response.status_code}", 0.75

        # --- server-status (Apache mod_status) ---
        if "server-status" in path:
            if "Apache Server Status" in body or "Server Version" in body:
                return True, "Apache mod_status exposed — server internals visible", 0.98

        # Default — file accessible but content not recognized
        return False, "File accessible but content does not match expected format (possible false positive)", 0.20

    async def verify_finding(
        self,
        client: httpx.AsyncClient,
        url: str,
        path: str,
        baseline: Optional[Dict[str, Any]] = None,
        base_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Full three-layer verification of a single finding.
        Returns enriched result with is_genuine flag and confidence score.
        """
        if baseline is None and base_url:
            baseline = await self.get_baseline(client, base_url)
        elif baseline is None:
            baseline = {"status": 404, "length": 0, "is_html": False, "body_hash": ""}

        try:
            response = await client.get(url, follow_redirects=True, headers={
                "Accept": "application/json, text/plain, */*"
            })
        except Exception as e:
            return {"url": url, "is_genuine": False, "reason": f"Request failed: {e}", "confidence": 0.0}

        status = response.status_code
        ct = response.headers.get("content-type", "")
        length = len(response.content)

        # Layer 1: Status code must be interesting
        if status == 404:
            return {"url": url, "is_genuine": False, "reason": "404 Not Found", "confidence": 0.0, "status": status}

        # Layer 2: Soft-404 / SPA catch-all detection
        if self._is_soft_404(response, baseline):
            return {
                "url": url,
                "is_genuine": False,
                "reason": "Soft-404 detected: Response matches catch-all SPA/Nginx page",
                "confidence": 0.05,
                "status": status,
                "length": length,
            }

        # Layer 3: Content analysis
        is_genuine, evidence, confidence = self._analyze_file_content(path, response)

        return {
            "url": url,
            "path": path,
            "status": status,
            "content_type": ct,
            "length": length,
            "is_genuine": is_genuine,
            "evidence": evidence,
            "confidence": confidence,
            "body_preview": response.text[:200] if is_genuine else "",
        }

    async def batch_verify(
        self,
        base_url: str,
        findings: list,
        concurrency: int = 10
    ) -> list:
        """
        Verify a batch of raw findings and return only genuine ones.
        Eliminates false positives automatically.
        """
        semaphore = asyncio.Semaphore(concurrency)
        verified = []

        async with httpx.AsyncClient(
            verify=False,
            timeout=self.timeout,
            follow_redirects=True
        ) as client:
            baseline = await self.get_baseline(client, base_url)
            logger.info(f"[SmartVerifier] Baseline for {base_url}: status={baseline['status']}, len={baseline['length']}")

            async def verify_one(finding):
                url = finding.get("url", "")
                path = finding.get("path", "")
                async with semaphore:
                    result = await self.verify_finding(client, url, path, baseline, base_url)
                    if result.get("is_genuine"):
                        verified.append({**finding, **result})
                    else:
                        logger.debug(f"[SmartVerifier] FALSE POSITIVE eliminated: {url} — {result.get('reason')}")

            tasks = [verify_one(f) for f in findings]
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"[SmartVerifier] Batch complete: {len(findings)} raw → {len(verified)} genuine findings")
        return verified
