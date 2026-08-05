from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from penflow.shared.utils import generate_uuid, get_utc_timestamp

@dataclass
class TestingHypothesis:
    id: str = field(default_factory=generate_uuid)
    target: str = ""
    reason: str = ""
    confidence: float = 0.5
    required_evidence: List[str] = field(default_factory=list)
    required_capabilities: List[str] = field(default_factory=list)
    blocking_conditions: List[str] = field(default_factory=list)

@dataclass
class Strategy:
    id: str = field(default_factory=generate_uuid)
    title: str = ""
    ordered_execution_plan: List[str] = field(default_factory=list)
    required_agents: List[str] = field(default_factory=list)
    expected_evidence: List[str] = field(default_factory=list)
    validation_rules: List[str] = field(default_factory=list)
    stop_conditions: List[str] = field(default_factory=list)
    success_conditions: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)  # Strategy IDs
    status: str = "CREATED"  # CREATED, SCHEDULED, RUNNING, COMPLETED, FAILED
    created_at: float = field(default_factory=get_utc_timestamp)
