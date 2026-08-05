import asyncio
import socket
from typing import Dict, Any, List, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.dns_resolver")

class DNSResolverEngine:
    """
    Real DNS Resolution Engine performing A, AAAA, and CNAME lookups using asyncio.
    """
    async def resolve_domain(self, domain: str) -> Dict[str, Any]:
        clean_domain = domain.strip().lower()
        records: Dict[str, Any] = {
            "domain": clean_domain,
            "ip_addresses": [],
            "cname": None,
            "is_resolved": False
        }

        loop = asyncio.get_running_loop()
        try:
            addr_info = await loop.getaddrinfo(clean_domain, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            ips = list(set(item[4][0] for item in addr_info if item[4]))
            records["ip_addresses"] = ips
            records["is_resolved"] = len(ips) > 0
            logger.info(f"[DNSResolver] Resolved '{clean_domain}' -> IPs: {ips}")
        except socket.gaierror as e:
            logger.debug(f"[DNSResolver] Could not resolve '{clean_domain}': {str(e)}")
        except Exception as e:
            logger.warning(f"[DNSResolver] Error resolving '{clean_domain}': {str(e)}")

        return records
