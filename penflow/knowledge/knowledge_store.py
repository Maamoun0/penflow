from penflow.knowledge.asset_registry import AssetRegistry
from penflow.knowledge.relationships import RelationshipRegistry
from penflow.knowledge.knowledge_graph import KnowledgeGraph
from penflow.knowledge.observation_store import ObservationStore
from penflow.knowledge.evidence_store import EvidenceStore
from penflow.knowledge.memory import MemoryEngine
from penflow.knowledge.timeline import TimelineEngine
from penflow.knowledge.index import IndexEngine
from penflow.knowledge.search import SearchEngine
from penflow.intelligence.experience_layer import ExperienceLayer
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.knowledge.store")

class KnowledgeStore:
    """
    Central Knowledge Platform facade: Single Source of Truth for PenFlow SROS.
    Workers/Agents read from and write to this central platform exclusively.
    """
    def __init__(self):
        self.assets = AssetRegistry()
        self.relationships = RelationshipRegistry()
        self.graph = KnowledgeGraph(self.assets, self.relationships)
        self.observations = ObservationStore()
        self.evidence = EvidenceStore()
        self.memory = MemoryEngine()
        self.timeline = TimelineEngine()
        self.index = IndexEngine()
        self.search = SearchEngine(self.assets, self.relationships, self.index)
        self.experience = ExperienceLayer()
        logger.info("[KnowledgeStore] Knowledge Platform initialized as Single Source of Truth.")
