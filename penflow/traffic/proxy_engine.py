from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.traffic.proxy_engine")

@dataclass
class ProxyConfig:
    """
    Proxy Configuration data structure for routing outbound HTTP requests
    through interception tools like Burp Suite or Caido.
    """
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    verify_ssl: bool = False
    ca_bundle_path: Optional[str] = None

    def get_proxies_dict(self) -> Dict[str, str]:
        proxies = {}
        if self.http_proxy:
            proxies["http://"] = self.http_proxy
        if self.https_proxy:
            proxies["https://"] = self.https_proxy
        elif self.http_proxy:
            proxies["https://"] = self.http_proxy
        return proxies
