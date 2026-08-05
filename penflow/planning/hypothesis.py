from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from penflow.shared.utils import generate_uuid, get_utc_timestamp

@dataclass
class Hypothesis:
    """
    Represents one explainable security hypothesis inside the PenFlow Planning Engine.
    """
    id: str = field(default_factory=generate_uuid)
    title: str = ""
    description: str = ""
    reason: str = ""
    confidence: float = 0.5
    priority: float = 5.0
    required_capabilities: List[str] = field(default_factory=list)
    required_observations: List[str] = field(default_factory=list)
    blocking_conditions: List[str] = field(default_factory=list)
    expected_evidence: List[str] = field(default_factory=list)
    status: str = "DRAFT"  # DRAFT, ACTIVE, EVALUATED, ARCHIVED, INVALIDATED
    created_at: float = field(default_factory=get_utc_timestamp)
    updated_at: float = field(default_factory=get_utc_timestamp)
