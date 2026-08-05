from typing import List, Set
from penflow.capabilities.capability import Capability
from penflow.capabilities.registry import CapabilityRegistry
from penflow.capabilities.exceptions import CapabilityConflictError, CapabilityDependencyError

class CapabilityConstraintsEngine:
    """
    Validates capability dependency graphs and conflict detection.
    """
    def __init__(self, registry: CapabilityRegistry):
        self.registry = registry

    def validate_constraints(self, capability_ids: List[str]) -> None:
        selected_set = set(capability_ids)

        # 1. Check Conflicts
        for cap_id in capability_ids:
            cap = self.registry.get_capability(cap_id)
            if cap:
                conflicts = set(cap.conflicts) & selected_set
                if conflicts:
                    raise CapabilityConflictError(
                        f"Capability '{cap_id}' conflicts with selected capabilities: {list(conflicts)}"
                    )

        # 2. Check Dependencies
        for cap_id in capability_ids:
            cap = self.registry.get_capability(cap_id)
            if cap:
                missing_deps = [dep for dep in cap.dependencies if dep not in selected_set]
                if missing_deps:
                    raise CapabilityDependencyError(
                        f"Capability '{cap_id}' missing required dependencies: {missing_deps}"
                    )
