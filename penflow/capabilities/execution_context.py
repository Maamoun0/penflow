from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.traffic.session_manager import SessionManager
from penflow.traffic.http_client import StatefulHttpClient
from penflow.traffic.diff_engine import DifferentialEngine
from penflow.intelligence.state_manager import ExploitStateStore

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
    state_store: Optional[ExploitStateStore] = None

    def __post_init__(self):
        if self.asset:
            clean = self.asset.strip()
            for prefix in ("https://", "http://"):
                while clean.startswith(prefix):
                    clean = clean[len(prefix):]
            self.asset = clean.split("/")[0].split("?")[0]
        if self.state_store is None:
            self.state_store = ExploitStateStore()

    def get_http_client(self) -> StatefulHttpClient:
        if self.http_client is None:
            self.http_client = StatefulHttpClient(
                session_manager=self.session_manager,
                scope_domains=[self.asset] if self.asset else None,
                proxy_config=self.proxy_config
            )
        return self.http_client

    def get_observation_data(self) -> List[Dict[str, Any]]:
        """Returns normalized list of observation data dictionaries across memory and knowledge store."""
        results = []
        for obs in self.observations:
            if hasattr(obs, "data"):
                results.append(obs.data)
            elif isinstance(obs, dict):
                if "data" in obs and isinstance(obs["data"], dict):
                    results.append(obs["data"])
                else:
                    results.append(obs)
        if hasattr(self.knowledge_store, "observations"):
            for rec in self.knowledge_store.observations.get_all():
                if hasattr(rec, "data") and isinstance(rec.data, dict):
                    if rec.data not in results:
                        results.append(rec.data)
        return results

    def get_dynamic_endpoints(self) -> List[Any]:
        if "dynamic_endpoints" in self.shared_cache:
            return self.shared_cache["dynamic_endpoints"]
        endpoints = []
        for data in self.get_observation_data():
            if isinstance(data, dict):
                if "endpoints" in data:
                    endpoints.extend(data["endpoints"])
                if "forms" in data:
                    for form in data["forms"]:
                        if isinstance(form, dict) and form.get("action"):
                            endpoints.append({
                                "url": form["action"],
                                "method": form.get("method", "POST"),
                                "parameters": form.get("parameters", [])
                            })
        return endpoints

# Compatibility alias

ExecutionContext = CapabilityExecutionContext

