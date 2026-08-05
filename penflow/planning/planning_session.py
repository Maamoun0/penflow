from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from penflow.planning.hypothesis_registry import HypothesisRegistry
from penflow.shared.utils import generate_uuid, get_utc_timestamp

@dataclass
class PlanningSession:
    """
    Manages state, active hypotheses, and metadata for an ongoing planning cycle.
    """
    session_id: str = field(default_factory=generate_uuid)
    target_id: str = ""
    registry: HypothesisRegistry = field(default_factory=HypothesisRegistry)
    is_active: bool = True
    created_at: float = field(default_factory=get_utc_timestamp)
