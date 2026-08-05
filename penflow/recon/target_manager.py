from dataclasses import dataclass, field
from typing import Dict, List, Optional
from penflow.shared.utils import generate_uuid, get_utc_timestamp

@dataclass
class TargetProgram:
    id: str = field(default_factory=generate_uuid)
    name: str = ""
    domain: str = ""
    status: str = "ACTIVE"  # ACTIVE, PAUSED, STOPPED
    priority: int = 5
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=get_utc_timestamp)

class TargetManager:
    """
    Manages active, paused, and stopped target programs for continuous reconnaissance.
    """
    def __init__(self):
        self._targets: Dict[str, TargetProgram] = {}

    def add_target(self, name: str, domain: str, priority: int = 5, tags: Optional[List[str]] = None, metadata: Optional[Dict[str, str]] = None) -> TargetProgram:
        target = TargetProgram(
            name=name,
            domain=domain.strip().lower(),
            priority=priority,
            tags=tags or [],
            metadata=metadata or {}
        )
        self._targets[target.id] = target
        return target

    def remove_target(self, target_id: str) -> bool:
        return self._targets.pop(target_id, None) is not None

    def pause_target(self, target_id: str) -> None:
        if target_id in self._targets:
            self._targets[target_id].status = "PAUSED"

    def resume_target(self, target_id: str) -> None:
        if target_id in self._targets:
            self._targets[target_id].status = "ACTIVE"

    def get_target(self, target_id: str) -> Optional[TargetProgram]:
        return self._targets.get(target_id)

    def get_active_targets(self) -> List[TargetProgram]:
        return [t for t in self._targets.values() if t.status == "ACTIVE"]
