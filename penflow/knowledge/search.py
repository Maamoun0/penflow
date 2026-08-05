from typing import List, Dict, Any, Optional, Set
from penflow.knowledge.asset_registry import AssetRegistry, AssetNode
from penflow.knowledge.relationships import RelationshipRegistry, RelationshipEdge
from penflow.knowledge.index import IndexEngine

class SearchEngine:
    """
    Search Engine facilitating multi-criteria queries across knowledge assets and relationships.
    """
    def __init__(self, asset_registry: AssetRegistry, relationships: RelationshipRegistry, index_engine: IndexEngine):
        self.asset_registry = asset_registry
        self.relationships = relationships
        self.index = index_engine

    def full_text_search(self, query: str) -> List[AssetNode]:
        q_clean = query.strip().lower()
        results = []
        for asset in self.asset_registry.get_all_assets():
            if q_clean in asset.canonical_name or any(q_clean in alias for alias in asset.aliases):
                results.append(asset)
        return results

    def tag_search(self, tag_key: str, tag_value: str) -> List[AssetNode]:
        results = []
        for asset in self.asset_registry.get_all_assets():
            if asset.metadata.get(tag_key, "").lower() == tag_value.lower():
                results.append(asset)
        return results

    def technology_search(self, tech_name: str) -> List[AssetNode]:
        entity_ids = self.index.lookup("technologies", tech_name)
        results = []
        for asset in self.asset_registry.get_all_assets():
            if asset.id in entity_ids or asset.metadata.get("technology", "").lower() == tech_name.lower():
                results.append(asset)
        return results

    def time_range_search(self, start_timestamp: float, end_timestamp: float) -> List[AssetNode]:
        results = []
        for asset in self.asset_registry.get_all_assets():
            if start_timestamp <= asset.first_seen <= end_timestamp or start_timestamp <= asset.last_seen <= end_timestamp:
                results.append(asset)
        return results
