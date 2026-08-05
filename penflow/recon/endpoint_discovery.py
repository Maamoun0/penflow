from dataclasses import dataclass, field
from typing import Dict, List, Optional
from penflow.shared.utils import get_utc_timestamp

@dataclass
class DiscoveredEndpoint:
    url: str
    endpoint_type: str  # REST, GraphQL, WebSocket, gRPC
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=get_utc_timestamp)

class EndpointDiscoveryEngine:
    """
    Tracks REST, GraphQL, WebSocket, and gRPC endpoints and parameters.
    """
    def __init__(self):
        self._endpoints: Dict[str, DiscoveredEndpoint] = {}

    def record_endpoint(self, url: str, endpoint_type: str = "REST", method: str = "GET", parameters: Optional[List[str]] = None) -> DiscoveredEndpoint:
        key = f"{method.upper()}:{url.strip().lower()}"
        if key in self._endpoints:
            ep = self._endpoints[key]
            if parameters:
                for p in parameters:
                    if p not in ep.parameters:
                        ep.parameters.append(p)
            return ep

        ep = DiscoveredEndpoint(
            url=url.strip().lower(),
            endpoint_type=endpoint_type.upper(),
            method=method.upper(),
            parameters=parameters or []
        )
        self._endpoints[key] = ep
        return ep

    def get_endpoints_by_type(self, endpoint_type: str) -> List[DiscoveredEndpoint]:
        return [ep for ep in self._endpoints.values() if ep.endpoint_type == endpoint_type.upper()]

    def get_all_endpoints(self) -> List[DiscoveredEndpoint]:
        return list(self._endpoints.values())
