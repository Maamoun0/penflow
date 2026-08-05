import time
import uuid
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
from penflow.utils.logger import get_logger

logger = get_logger("penflow.core.acp_protocol")

class ACPMessageType:
    RECON_INTEL_PUBLISHED = "ReconIntelPublished"
    HYPOTHESIS_TASK_DISPATCHED = "HypothesisTaskDispatched"
    CANDIDATE_FINDING_SUBMITTED = "CandidateFindingSubmitted"
    FINDING_VERIFIED = "FindingVerified"
    FINDING_REJECTED = "FindingRejected"
    INTEL_PREEMPTION_TRIGGERED = "IntelPreemptionTriggered"
    TASK_PREEMPTED = "TaskPreempted"
    RESOURCE_BUDGET_ALERT = "ResourceBudgetAlert"

@dataclass
class ACPAgentAddress:
    team: str
    agent: str

@dataclass
class ACPMessageMeta:
    priority: str = "NORMAL"  # LOW, NORMAL, HIGH, CRITICAL
    ttl_seconds: int = 3600

@dataclass
class ACPMessage:
    """
    Standard Message Envelope for the Agent Communication Protocol (ACP v1.0).
    Ensures structured inter-team communication across the Swarm platform.
    """
    acp_version: str = "1.0"
    message_id: str = field(default_factory=lambda: f"acp_msg_{uuid.uuid4().hex[:12]}")
    correlation_id: str = field(default_factory=lambda: f"flow_{uuid.uuid4().hex[:8]}")
    timestamp: float = field(default_factory=time.time)
    sender: Dict[str, str] = field(default_factory=dict)     # {"team": "ReconTeam", "agent": "SubdomainAgent"}
    recipient: Dict[str, str] = field(default_factory=dict)  # {"team": "PlanningTeam", "agent": "StrategyAgent"}
    intent: str = "INTEL_PUBLISH"
    message_type: str = ACPMessageType.RECON_INTEL_PUBLISHED
    payload: Dict[str, Any] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str) -> "ACPMessage":
        data = json.loads(json_str)
        return cls(**data)

    def validate(self) -> bool:
        """Validates that the message adheres to ACP v1.0 specifications."""
        if not self.message_type or not self.sender.get("team"):
            logger.error(f"[ACPProtocol] Invalid ACP message: missing message_type or sender.team")
            return False
        return True
