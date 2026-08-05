from dataclasses import dataclass, field
from typing import List, Dict, Any
from penflow.planning.hypothesis import Hypothesis
from penflow.shared.utils import generate_uuid, get_utc_timestamp

@dataclass
class ExecutionPlan:
    """
    Abstract Execution Plan produced by the Planner.
    Strictly contains ordered hypotheses, dependencies, capabilities, estimated cost & value.
    NEVER contains HTTP requests or vulnerability payload logic.
    """
    id: str = field(default_factory=generate_uuid)
    ordered_hypotheses: List[Hypothesis] = field(default_factory=list)
    dependencies: Dict[str, List[str]] = field(default_factory=dict)
    required_capabilities: List[str] = field(default_factory=list)
    estimated_cost: float = 0.0
    estimated_runtime_seconds: float = 0.0
    expected_value: float = 0.0
    created_at: float = field(default_factory=get_utc_timestamp)
