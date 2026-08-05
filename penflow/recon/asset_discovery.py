from typing import Dict, List, Optional
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.knowledge.asset_registry import AssetNode
from penflow.recon.scope_manager import ScopeManager

class AssetDiscoveryEngine:
    """
    Discovers and registers new assets (subdomains, URLs, IPs, hostnames, repos, certs) into KnowledgeStore.
    """
    def __init__(self, knowledge_store: KnowledgeStore, scope_manager: Optional[ScopeManager] = None):
        self.knowledge = knowledge_store
        self.scope = scope_manager or ScopeManager()

    def discover_asset(self, canonical_name: str, asset_type: str, metadata: Optional[Dict[str, str]] = None) -> Optional[AssetNode]:
        if not self.scope.is_in_scope(canonical_name):
            return None

        return self.knowledge.assets.register_asset(canonical_name, asset_type, metadata)
