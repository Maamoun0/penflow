from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from penflow.knowledge.knowledge_store import KnowledgeStore

@dataclass
class PlanningContext:
    """
    Context provided to the Planning Engine containing KnowledgeStore,
    current target state, and observation summaries.
    """
    knowledge_store: KnowledgeStore
    target_id: str = ""
    target_domain: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
