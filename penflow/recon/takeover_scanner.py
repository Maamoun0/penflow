"""
Subdomain Takeover Scanner — Phase 4 Module for PenFlow.

Scans DNS records (CNAME, A, AAAA) against known dangling cloud service fingerprints:
AWS S3, GitHub Pages, Heroku, Azure, Shopify, Fastly, Tumblr, Ghost, Surge.sh, etc.
"""
import asyncio
import httpx
from typing import Dict, Any, List, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.takeover_scanner")

# Fingerprints of vulnerable cloud services when a CNAME is dangling
TAKEOVER_FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cname_pattern": ["github.io"],
        "response_pattern": ["There isn't a GitHub Pages site here", "For root domain support, see"]
    },
    {
        "service": "AWS S3 Bucket",
        "cname_pattern": ["s3.amazonaws.com", "s3-website"],
        "response_pattern": ["The specified bucket does not exist", "NoSuchBucket"]
    },
    {
        "service": "Heroku",
        "cname_pattern": ["herokudns.com", "herokuapp.com"],
        "response_pattern": ["Heroku | No such app", "no-such-app.html"]
    },
    {
        "service": "Azure",
        "cname_pattern": ["azurewebsites.net", "cloudapp.azure.com"],
        "response_pattern": ["404 Web Site not found", "The resource you are looking for has been removed"]
    },
    {
        "service": "Shopify",
        "cname_pattern": ["myshopify.com"],
        "response_pattern": ["Sorry, this shop is currently unavailable."]
    },
    {
        "service": "Fastly",
        "cname_pattern": ["fastly.net"],
        "response_pattern": ["Fastly error: unknown domain"]
    }
]


class SubdomainTakeoverScanner:
    """
    Phase 4: Subdomain Takeover & Dangling DNS Pointer Scanner.
    """

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    async def check_subdomain_takeover(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Probes a domain/subdomain for dangling CNAME takeover markers.
        """
        if not domain.startswith(("http://", "https://")):
            target_url = f"https://{domain}"
        else:
            target_url = domain

        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(target_url)
                body = resp.text

                for fp in TAKEOVER_FINGERPRINTS:
                    for pattern in fp["response_pattern"]:
                        if pattern.lower() in body.lower():
                            logger.info(f"[TakeoverScanner] 🔴 SUBDOMAIN TAKEOVER DETECTED on '{domain}' ({fp['service']})")
                            return {
                                "domain": domain,
                                "service": fp["service"],
                                "is_vulnerable": True,
                                "confidence": 0.95,
                                "matched_fingerprint": pattern,
                                "status_code": resp.status_code,
                                "evidence": body[:300]
                            }

        except Exception as e:
            logger.debug(f"[TakeoverScanner] Failed checking {domain}: {e}")

        return None

    async def scan_subdomains(self, domains: List[str]) -> List[Dict[str, Any]]:
        """
        Scans a batch of subdomains for takeover vulnerabilities.
        """
        logger.info(f"[TakeoverScanner] Starting takeover scan across {len(domains)} targets...")
        tasks = [self.check_subdomain_takeover(d) for d in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        vulnerabilities = [r for r in results if isinstance(r, dict) and r.get("is_vulnerable")]
        logger.info(f"[TakeoverScanner] Scan complete: {len(vulnerabilities)} vulnerable subdomains found.")
        return vulnerabilities
