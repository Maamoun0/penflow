import asyncio
import json
from dataclasses import dataclass, field
from typing import List, Set

from penflow.network.http_client import HttpClient
from penflow.utils.logger import get_logger
from penflow.utils.url_utils import normalize_url, extract_domain
from penflow.utils.file_utils import get_scan_dir, safe_write_json
from penflow.core.event_bus import EventBus

logger = get_logger("penflow.recon.passive_recon")

@dataclass
class PassiveResult:
    urls: Set[str] = field(default_factory=set)
    subdomains: Set[str] = field(default_factory=set)
    parameters: Set[str] = field(default_factory=set)

class PassiveRecon:
    """Zero-bandwidth recon using third-party APIs like Wayback Machine and URLScan."""
    
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
        self.event_bus = EventBus.get_instance()

    async def gather(self, domain: str) -> PassiveResult:
        logger.info(f"Starting passive gathering for {domain}")
        result = PassiveResult()
        
        # We'll use Wayback Machine CDX API with a short timeout and limit
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
        
        try:
            # We pass timeout explicitly (e.g. 5 seconds) to prevent hanging, and skip retries
            response = await self.http_client.get(url, skip_cache=True, timeout=5.0, skip_retries=True)
            if response and response.status == 200:
                data = json.loads(response.body)
                if len(data) > 1: # Skip header row
                    for row in data[1:]:
                        if len(row) > 0:
                            raw_url = row[0]
                            norm_url = normalize_url(raw_url)
                            result.urls.add(norm_url)
                            
                            # Extract parameters from query strings
                            from urllib.parse import urlparse, parse_qs
                            parsed = urlparse(raw_url)
                            if parsed.query:
                                qs = parse_qs(parsed.query)
                                for param in qs.keys():
                                    result.parameters.add(param)
                                    
                            # Extract subdomain
                            if parsed.netloc:
                                sub = parsed.netloc.split(':')[0]
                                if sub.endswith(domain) and sub != domain:
                                    result.subdomains.add(sub)
        except Exception as e:
            logger.warning(f"Wayback gathering timed out or failed: {e}")
            
        logger.info(f"Passive gathering complete. Found {len(result.urls)} URLs and {len(result.parameters)} unique parameters.")
        
        # Save results
        out_dir = get_scan_dir(domain, "raw")
        safe_write_json(out_dir / "passive_urls.json", list(result.urls))
        safe_write_json(out_dir / "passive_params.json", list(result.parameters))
        
        return result
