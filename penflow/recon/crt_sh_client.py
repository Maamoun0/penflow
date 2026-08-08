import httpx
from typing import List, Dict, Any, Set
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.crt_sh")

class CrtShClient:
    """
    Queries crt.sh Certificate Transparency Logs to discover real subdomains for a target domain.
    """
    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout
        self.base_url = "https://crt.sh"

    async def fetch_subdomains(self, domain: str) -> List[str]:
        clean_domain = domain.strip().lower()
        for prefix in ["https://", "http://"]:
            if clean_domain.startswith(prefix):
                clean_domain = clean_domain[len(prefix):]
        clean_domain = clean_domain.split("/")[0].split("?")[0].split(":")[0]
        url = f"{self.base_url}/?q=%.{clean_domain}&output=json"
        found_subdomains: Set[str] = set()

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            name_clean = name.strip().lower()
                            if name_clean.endswith(clean_domain) and not name_clean.startswith("*."):
                                found_subdomains.add(name_clean)
                    logger.info(f"[CrtShClient] Discovered {len(found_subdomains)} subdomains for '{clean_domain}'")
                else:
                    logger.warning(f"[CrtShClient] crt.sh returned HTTP status {response.status_code}")
        except Exception as e:
            logger.warning(f"[CrtShClient] Failed to query crt.sh for '{clean_domain}': {str(e)}")

        return sorted(list(found_subdomains))
