from typing import Dict, List, Any, Optional, Set
from penflow.knowledge.asset_registry import AssetRegistry, AssetNode
from penflow.knowledge.relationships import RelationshipRegistry, RelationshipEdge

class KnowledgeGraph:
    """
    Graph coordinator combining AssetRegistry nodes and RelationshipRegistry edges for deep query capabilities.
    Supports multi-hop traversal: Asset -> Subdomain -> Endpoint -> Security Hypothesis.
    """
    def __init__(self, asset_registry: AssetRegistry, relationship_registry: RelationshipRegistry):
        self.asset_registry = asset_registry
        self.relationships = relationship_registry

    def add_node(self, name: str, asset_type: str, metadata: Optional[Dict[str, str]] = None) -> AssetNode:
        return self.asset_registry.register_asset(name, asset_type, metadata)

    def add_edge(self, source_id: str, relation_type: str, target_id: str) -> RelationshipEdge:
        return self.relationships.add_relationship(source_id, relation_type, target_id)

    def query_related_assets(self, source_asset_name: str, relation_type: Optional[str] = None) -> List[AssetNode]:
        source_node = self.asset_registry.get_asset_by_name(source_asset_name)
        if not source_node:
            return []

        edges = self.relationships.get_outgoing_relationships(source_node.id)
        if relation_type:
            edges = [e for e in edges if e.relation_type == relation_type]

        target_nodes = []
        for edge in edges:
            node = self.asset_registry._assets.get(edge.target_id)
            if node:
                target_nodes.append(node)
        return target_nodes

    def traverse_graph(self, start_asset_name: str, max_depth: int = 3) -> Dict[str, Any]:
        """
        Traverses graph up to max_depth returning sub-graph structure.
        """
        start_node = self.asset_registry.get_asset_by_name(start_asset_name)
        if not start_node:
            return {"start": start_asset_name, "nodes": [], "edges": []}

        visited_nodes: Set[str] = set([start_node.id])
        collected_nodes: List[Dict[str, Any]] = [{"id": start_node.id, "name": start_node.canonical_name, "type": start_node.asset_type}]
        collected_edges: List[Dict[str, Any]] = []

        frontier = [(start_node.id, 0)]

        while frontier:
            curr_id, depth = frontier.pop(0)
            if depth >= max_depth:
                continue

            outgoing = self.relationships.get_outgoing_relationships(curr_id)
            for edge in outgoing:
                collected_edges.append({
                    "source": edge.source_id,
                    "relation": edge.relation_type,
                    "target": edge.target_id
                })
                if edge.target_id not in visited_nodes:
                    visited_nodes.add(edge.target_id)
                    target_node = self.asset_registry._assets.get(edge.target_id)
                    if target_node:
                        collected_nodes.append({"id": target_node.id, "name": target_node.canonical_name, "type": target_node.asset_type})
                    frontier.append((edge.target_id, depth + 1))

        return {
            "start": start_asset_name,
            "nodes": collected_nodes,
            "edges": collected_edges
        }
