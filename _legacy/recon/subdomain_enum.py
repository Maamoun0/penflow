import asyncio
import json
import socket
from typing import List, Dict, Set

from penflow.network.http_client import HttpClient
from penflow.utils.logger import get_logger
from penflow.utils.file_utils import get_scan_dir, safe_write_json
from penflow.core.event_bus import EventBus

logger = get_logger("penflow.recon.subdomain_enum")

class SubdomainEnumerator:
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
        self.event_bus = EventBus.get_instance()
        
    async def enumerate(self, domain: str) -> List[Dict[str, str]]:
        logger.info(f"Starting passive subdomain enumeration for {domain}")
        subdomains: Set[str] = set()
        
        # We run sources concurrently
        tasks = [
            self._fetch_crtsh(domain),
            self._fetch_wayback(domain)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for res in results:
            if isinstance(res, set):
                subdomains.update(res)
            elif isinstance(res, Exception):
                logger.error(f"Error in subdomain source: {res}")
                
        # Filter wildcards and normalize
        clean_subdomains = set()
        for sub in subdomains:
            sub = sub.strip().lower()
            if sub.startswith("*."):
                sub = sub[2:]
            if sub.endswith(f".{domain}") or sub == domain:
                clean_subdomains.add(sub)
                
        logger.info(f"Found {len(clean_subdomains)} unique subdomains from passive sources.")
        
        # Resolve DNS to find alive subdomains
        alive_results = await self._resolve_all(list(clean_subdomains))
        
        # Save to file
        scan_dir = get_scan_dir(domain, "raw")
        output_file = scan_dir / "subdomains.json"
        safe_write_json(output_file, alive_results)
        
        # Emit events for alive subdomains
        for res in alive_results:
            if res.get("alive"):
                await self.event_bus.emit("ENDPOINT_FOUND", {
                    "type": "subdomain",
                    "domain": domain,
                    "subdomain": res["subdomain"],
                    "ip": res.get("ip")
                })
                
        return alive_results

    async def _fetch_crtsh(self, domain: str) -> Set[str]:
        """Fetch subdomains from crt.sh (Certificate Transparency)."""
        subs = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            response = await self.http_client.get(url, skip_cache=True, timeout=5.0, skip_retries=True)
            if response and response.status == 200:
                data = json.loads(response.body)
                for entry in data:
                    name = entry.get("name_value", "")
                    # crt.sh sometimes returns multiple domains separated by newlines
                    for n in name.split('\n'):
                        subs.add(n)
        except Exception as e:
            logger.warning(f"crt.sh fetch failed: {e}")
        return subs

    async def _fetch_wayback(self, domain: str) -> Set[str]:
        """Fetch subdomains from Wayback Machine."""
        subs = set()
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
        try:
            response = await self.http_client.get(url, skip_cache=True, timeout=5.0, skip_retries=True)
            if response and response.status == 200:
                data = json.loads(response.body)
                if len(data) > 1: # Skip header row
                    for row in data[1:]:
                        if len(row) > 0:
                            from urllib.parse import urlparse
                            try:
                                parsed = urlparse(row[0])
                                if parsed.netloc:
                                    subs.add(parsed.netloc.split(':')[0])
                            except:
                                pass
        except Exception as e:
            logger.warning(f"Wayback fetch failed: {e}")
        return subs

    async def _resolve_all(self, subdomains: List[str]) -> List[Dict[str, str]]:
        """Concurrently resolve DNS for subdomains."""
        results = []
        sem = asyncio.Semaphore(50) # DNS limits
        
        async def resolve(sub: str):
            async with sem:
                loop = asyncio.get_running_loop()
                try:
                    # Run blocking gethostbyname in executor
                    ip = await loop.run_in_executor(None, socket.gethostbyname, sub)
                    return {"subdomain": sub, "alive": True, "ip": ip}
                except socket.gaierror:
                    return {"subdomain": sub, "alive": False, "ip": None}
                except Exception:
                    return {"subdomain": sub, "alive": False, "ip": None}

        tasks = [resolve(sub) for sub in subdomains]
        resolved = await asyncio.gather(*tasks)
        
        alive_count = sum(1 for r in resolved if r["alive"])
        logger.info(f"DNS Resolution: {alive_count}/{len(subdomains)} subdomains are alive.")
        
        return resolved
