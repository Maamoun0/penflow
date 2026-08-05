import asyncio
from typing import List, Dict

from penflow.utils.logger import get_logger

logger = get_logger("penflow.recon.port_scanner")

class PortScanner:
    def __init__(self, timeout: float = 3.0, max_concurrent: int = 100):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        # Common web/API ports
        self.default_ports = [80, 443, 8080, 8443, 8000, 3000, 5000, 9090, 8888, 9200, 27017, 6379]

    async def _check_port(self, host: str, port: int) -> Dict[str, any]:
        async with self.semaphore:
            try:
                # Use open_connection for async socket connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), 
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                
                # Guess service
                service = "http" if port in (80, 8080, 8000, 3000, 5000, 9090, 8888) else "unknown"
                if port in (443, 8443): service = "https"
                if port == 9200: service = "elasticsearch"
                if port == 27017: service = "mongodb"
                if port == 6379: service = "redis"
                
                return {"host": host, "port": port, "open": True, "service": service}
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return {"host": host, "port": port, "open": False, "service": "unknown"}

    async def scan_host(self, host: str, ports: List[int] = None) -> List[Dict[str, any]]:
        """Scan a single host for open ports."""
        if not ports:
            ports = self.default_ports
            
        logger.debug(f"Port scanning {host} for {len(ports)} ports...")
        tasks = [self._check_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        # Return only open ports
        open_ports = [r for r in results if r["open"]]
        return open_ports

    async def scan_hosts(self, hosts: List[str], ports: List[int] = None) -> List[Dict[str, any]]:
        """Scan multiple hosts concurrently."""
        logger.info(f"Port scanning {len(hosts)} hosts...")
        tasks = [self.scan_host(host, ports) for host in hosts]
        results = await asyncio.gather(*tasks)
        
        # Flatten results
        all_open = []
        for host_res in results:
            all_open.extend(host_res)
            
        logger.info(f"Found {len(all_open)} open web ports across hosts.")
        return all_open
