"""
FindingContextGraph — Graph-Based Contextual Vulnerability & Asset Relationship Engine for PenFlow.

Models complex multi-target topologies as a connected knowledge graph:
  - Nodes: Assets, Endpoints, Findings, Parameters, Identifiers, Leaked Secrets
  - Edges: AFFECTS, LEAKS_ACCESS_TO, CROSS_ORIGIN_PERMITTED, PRIVILEGE_ESCALATES_TO, ENABLES_PIVOT
  - Traversal: Identifies multi-hop exploit paths combining isolated Low/Medium issues into Critical chains.
"""
from typing import Dict, List, Any, Optional, Set, Tuple
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.finding_graph")


class GraphNode:
    """Represents an entity in the security graph."""
    def __init__(self, node_id: str, node_type: str, label: str, properties: Optional[Dict[str, Any]] = None):
        self.node_id = node_id
        self.node_type = node_type  # asset | endpoint | finding | identity | secret
        self.label = label
        self.properties = properties or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "properties": self.properties
        }


class GraphEdge:
    """Represents a directional relationship between two nodes."""
    def __init__(self, source_id: str, target_id: str, relationship: str, weight: float = 1.0, properties: Optional[Dict[str, Any]] = None):
        self.source_id = source_id
        self.target_id = target_id
        self.relationship = relationship  # AFFECTS | LEAKS_TO | ENABLES_CHAIN | REACHES
        self.weight = weight
        self.properties = properties or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship": self.relationship,
            "weight": self.weight,
            "properties": self.properties
        }


class FindingContextGraph:
    """
    Contextual graph tracking relationships across discovered assets, vulnerabilities, and exploit prerequisites.
    """
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.adjacency: Dict[str, List[GraphEdge]] = {}

    def add_node(self, node_id: str, node_type: str, label: str, properties: Optional[Dict[str, Any]] = None) -> GraphNode:
        node = GraphNode(node_id, node_type, label, properties)
        self.nodes[node_id] = node
        if node_id not in self.adjacency:
            self.adjacency[node_id] = []
        return node

    def add_edge(self, source_id: str, target_id: str, relationship: str, weight: float = 1.0, properties: Optional[Dict[str, Any]] = None) -> GraphEdge:
        if source_id not in self.nodes or target_id not in self.nodes:
            logger.warning(f"[FindingContextGraph] Cannot create edge between non-existent nodes: {source_id} -> {target_id}")
        edge = GraphEdge(source_id, target_id, relationship, weight, properties)
        self.adjacency[source_id].append(edge)
        return edge

    def find_exploit_paths(self, start_finding_id: str, max_depth: int = 4) -> List[List[str]]:
        """Finds all multi-hop exploit paths originating from a given finding node."""
        paths: List[List[str]] = []

        def dfs(current: str, path: List[str], depth: int):
            if depth > max_depth:
                return
            for edge in self.adjacency.get(current, []):
                next_node = edge.target_id
                if next_node not in path:
                    new_path = path + [next_node]
                    paths.append(new_path)
                    dfs(next_node, new_path, depth + 1)

        if start_finding_id in self.nodes:
            dfs(start_finding_id, [start_finding_id], 1)

        return paths

    def export_graph(self) -> Dict[str, Any]:
        """Serializes the graph for analysis and visualization."""
        all_edges = []
        for src, edges in self.adjacency.items():
            for e in edges:
                all_edges.append(e.to_dict())
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(all_edges),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": all_edges
        }
