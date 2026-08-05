from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple
from penflow.shared.utils import generate_uuid, get_utc_timestamp

@dataclass(frozen=True)
class RelationshipEdge:
    id: str = field(default_factory=generate_uuid)
    source_id: str = ""
    relation_type: str = ""  # HAS_ENDPOINT, HAS_PARAMETER, USES_TECH, CONTAINS_SECRET, BOUND_TO_CERT
    target_id: str = ""
    created_at: float = field(default_factory=get_utc_timestamp)

class RelationshipRegistry:
    """
    Registry for directed edges between domain entities across the knowledge graph.
    """
    def __init__(self):
        self._edges: Dict[str, RelationshipEdge] = {}
        self._outgoing: Dict[str, Set[str]] = {}  # source_id -> edge_ids
        self._incoming: Dict[str, Set[str]] = {}  # target_id -> edge_ids

    def add_relationship(self, source_id: str, relation_type: str, target_id: str) -> RelationshipEdge:
        # Avoid duplicate edges
        for edge in self._edges.values():
            if edge.source_id == source_id and edge.relation_type == relation_type and edge.target_id == target_id:
                return edge

        edge = RelationshipEdge(
            source_id=source_id,
            relation_type=relation_type,
            target_id=target_id,
            created_at=get_utc_timestamp()
        )
        self._edges[edge.id] = edge
        
        self._outgoing.setdefault(source_id, set()).add(edge.id)
        self._incoming.setdefault(target_id, set()).add(edge.id)
        return edge

    def get_outgoing_relationships(self, source_id: str) -> List[RelationshipEdge]:
        edge_ids = self._outgoing.get(source_id, set())
        return [self._edges[eid] for eid in edge_ids]

    def get_incoming_relationships(self, target_id: str) -> List[RelationshipEdge]:
        edge_ids = self._incoming.get(target_id, set())
        return [self._edges[eid] for eid in edge_ids]

    def get_all_edges(self) -> List[RelationshipEdge]:
        return list(self._edges.values())
