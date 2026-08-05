from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.traffic.session_manager import SessionManager
from penflow.traffic.http_client import StatefulHttpClient
from penflow.traffic.diff_engine import DifferentialEngine

from penflow.traffic.proxy_engine import ProxyConfig

@dataclass
class CapabilityExecutionContext:
    asset: str
    knowledge_store: KnowledgeStore
    session_manager: SessionManager = field(default_factory=SessionManager)
    proxy_config: Optional[ProxyConfig] = None
    http_client: Optional[StatefulHttpClient] = None
    diff_engine: DifferentialEngine = field(default_factory=DifferentialEngine)
    observations: List[Dict[str, Any]] = field(default_factory=list)
    plan: Dict[str, Any] = field(default_factory=dict)
    shared_cache: Dict[str, Any] = field(default_factory=dict)
    shared_evidence: Dict[str, Any] = field(default_factory=dict)
    shared_sessions: Dict[str, Any] = field(default_factory=dict)

    def get_http_client(self) -> StatefulHttpClient:
        if self.http_client is None:
            self.http_client = StatefulHttpClient(session_manager=self.session_manager, proxy_config=self.proxy_config)
        return self.http_client

    def get_dynamic_endpoints(self) -> List[Any]:
        if "dynamic_endpoints" in self.shared_cache:
            return self.shared_cache["dynamic_endpoints"]
        if hasattr(self.knowledge_store, "observations"):
            obs_list = self.knowledge_store.observations.get_all()
            endpoints = []
            for ob in obs_list:
                data = ob.data if hasattr(ob, "data") else {}
                if isinstance(data, dict) and "endpoints" in data:
                    endpoints.extend(data["endpoints"])
            if endpoints:
                return endpoints
        return []

# Compatibility alias

ExecutionContext = CapabilityExecutionContext

