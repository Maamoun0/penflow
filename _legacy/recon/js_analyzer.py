import asyncio
import re
from dataclasses import dataclass, field
from typing import List, Set, Dict

from penflow.network.http_client import HttpClient
from penflow.utils.logger import get_logger
from penflow.utils.url_utils import normalize_url
from penflow.utils.file_utils import get_scan_dir, safe_write_json
from penflow.core.event_bus import EventBus
from penflow.config import Config

logger = get_logger("penflow.recon.js_analyzer")

@dataclass
class JSAnalysisResult:
    source_url: str
    endpoints: Set[str] = field(default_factory=set)
    parameters: Set[str] = field(default_factory=set)
    secrets: Set[str] = field(default_factory=set)
    graphql_ops: Set[str] = field(default_factory=set)
    websocket_urls: Set[str] = field(default_factory=set)
    debug_paths: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)
    s3_buckets: Set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "source_url": self.source_url,
            "endpoints": list(self.endpoints),
            "parameters": list(self.parameters),
            "secrets": list(self.secrets),
            "graphql_ops": list(self.graphql_ops),
            "websocket_urls": list(self.websocket_urls),
            "debug_paths": list(self.debug_paths),
            "emails": list(self.emails),
            "s3_buckets": list(self.s3_buckets)
        }

class JSAnalyzer:
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
        self.event_bus = EventBus.get_instance()
        self.config = Config.load()
        
        js_cfg = self.config.get("recon.js_analysis", {})
        self.max_size = js_cfg.get("max_file_size_kb", 2048) * 1024
        
        # Compile regex patterns for performance
        self.patterns = {
            "endpoints": [
                re.compile(r'["\'](\/(?:api|rest|graphql|v[0-9])[^"\'\s]*)["\']', re.IGNORECASE),
                re.compile(r'["\'](https?://[^"\'\s]+)["\']', re.IGNORECASE)
            ],
            "paths": [
                re.compile(r'["\'](\/[a-zA-Z][a-zA-Z0-9_/\-\.]*)["\']')
            ],
            "parameters": [
                re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)='),
                re.compile(r'params\s*\.\s*([a-zA-Z_]+)')
            ],
            "secrets": [
                re.compile(r'(AKIA[0-9A-Z]{16})'), # AWS
                re.compile(r'(AIza[0-9A-Za-z_-]{35})'), # Firebase/Google
                re.compile(r'["\']?(?:api[_-]?key|apikey|api_secret|secret_key)["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
                re.compile(r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'), # JWT
                re.compile(r'Bearer\s+([A-Za-z0-9_\-\.]+)', re.IGNORECASE),
                re.compile(r'(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)')
            ],
            "graphql": [
                re.compile(r'(?:query|mutation|subscription)\s+(\w+)', re.IGNORECASE),
                re.compile(r'(__typename)', re.IGNORECASE)
            ],
            "websockets": [
                re.compile(r'["\'](wss?://[^"\'\s]+)["\']', re.IGNORECASE)
            ],
            "debug": [
                re.compile(r'["\'](\/(?:debug|admin|internal|test|_)[\w/\-]*)["\']', re.IGNORECASE)
            ],
            "s3": [
                re.compile(r'([a-zA-Z0-9_-]+\.s3\.amazonaws\.com)', re.IGNORECASE),
                re.compile(r'["\'](s3://[a-zA-Z0-9_-]+)["\']', re.IGNORECASE)
            ]
        }

    def analyze(self, js_content: str, source_url: str = '') -> JSAnalysisResult:
        """Static analysis of JS content using Regex."""
        res = JSAnalysisResult(source_url=source_url)
        
        # Split into lines if very large, or just scan entire block
        # For simplicity and cross-line matching, we scan the whole string
        
        # Endpoints & Paths
        for p in self.patterns["endpoints"] + self.patterns["paths"]:
            for match in p.finditer(js_content):
                val = match.group(1)
                # Ignore common false positives like JS methods
                if not val.startswith("//") and len(val) > 2:
                    res.endpoints.add(val)
                    
        # Parameters
        for p in self.patterns["parameters"]:
            for match in p.finditer(js_content):
                res.parameters.add(match.group(1))
                
        # Secrets
        for p in self.patterns["secrets"]:
            for match in p.finditer(js_content):
                # Ensure we get the captured group, or full match if no group
                val = match.group(1) if match.lastindex else match.group(0)
                if len(val) > 5:
                    res.secrets.add(f"Potential Secret: {val[:10]}...") # Masked for safety in logs

        # GraphQL
        for p in self.patterns["graphql"]:
            for match in p.finditer(js_content):
                val = match.group(1) if match.lastindex else match.group(0)
                res.graphql_ops.add(val)

        # Websockets
        for p in self.patterns["websockets"]:
            for match in p.finditer(js_content):
                res.websocket_urls.add(match.group(1))

        # Debug
        for p in self.patterns["debug"]:
            for match in p.finditer(js_content):
                res.debug_paths.add(match.group(1))

        # S3
        for p in self.patterns["s3"]:
            for match in p.finditer(js_content):
                res.s3_buckets.add(match.group(1) if match.lastindex else match.group(0))

        return res

    async def analyze_url(self, url: str) -> JSAnalysisResult | None:
        """Fetch and analyze a JS file."""
        logger.debug(f"Analyzing JS from {url}")
        try:
            response = await self.http_client.get(url)
            if not response or response.status != 200:
                return None
                
            # Check size
            if len(response.body) > self.max_size:
                logger.warning(f"JS file too large, skipping: {url} ({len(response.body)} bytes)")
                return None
                
            result = self.analyze(response.body, source_url=url)
            
            # Emit events for interesting findings
            if result.secrets:
                await self.event_bus.emit("VULN_DETECTED", {
                    "type": "hardcoded_secret",
                    "url": url,
                    "details": f"Found {len(result.secrets)} potential secrets."
                })
                
            if result.endpoints:
                for ep in result.endpoints:
                    if ep.startswith("/"):
                        from urllib.parse import urljoin
                        full_ep = urljoin(url, ep)
                    else:
                        full_ep = ep
                        
                    await self.event_bus.emit("ENDPOINT_FOUND", {
                        "url": normalize_url(full_ep),
                        "method": "GET",
                        "type": "api", # Assume api from JS
                        "source": "js_analysis"
                    })
                    
            return result
            
        except Exception as e:
            logger.error(f"Failed to analyze JS at {url}: {e}")
            return None

    async def analyze_multiple(self, urls: List[str]) -> List[JSAnalysisResult]:
        """Analyze multiple JS files concurrently."""
        tasks = [self.analyze_url(url) for url in urls if url.endswith(".js")]
        results = await asyncio.gather(*tasks)
        
        valid_results = [r for r in results if r]
        
        if valid_results:
            # Save combined results
            from urllib.parse import urlparse
            if len(urls) > 0:
                domain = urlparse(urls[0]).netloc.split(':')[0]
                out_dir = get_scan_dir(domain, "filtered")
                
                combined = []
                for r in valid_results:
                    combined.append(r.to_dict())
                
                safe_write_json(out_dir / "js_analysis.json", combined)
                
        return valid_results
