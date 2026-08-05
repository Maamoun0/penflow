import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from penflow.shared.utils import generate_uuid, get_utc_timestamp

@dataclass
class ReconTaskSpec:
    id: str = field(default_factory=generate_uuid)
    target_asset: str = ""
    recon_type: str = "subdomain_scan"
    priority: int = 5
    scheduled_at: float = field(default_factory=get_utc_timestamp)

class ReconScheduler:
    """
    Schedules recon jobs, avoids duplicate work, and prioritizes fresh assets.
    """
    def __init__(self):
        self._scheduled: Dict[str, ReconTaskSpec] = {}
        self._active_signatures: Set[str] = set()

    def schedule_job(self, target_asset: str, recon_type: str, priority: int = 5) -> Optional[ReconTaskSpec]:
        asset_clean = target_asset.strip().lower()
        sig = f"{asset_clean}:{recon_type}"

        if sig in self._active_signatures:
            return None  # Duplicate job ignored

        spec = ReconTaskSpec(target_asset=asset_clean, recon_type=recon_type, priority=priority)
        self._scheduled[spec.id] = spec
        self._active_signatures.add(sig)
        return spec

    def get_next_job(self) -> Optional[ReconTaskSpec]:
        if not self._scheduled:
            return None

        # Sort highest priority first, then oldest scheduled_at
        sorted_specs = sorted(self._scheduled.values(), key=lambda s: (-s.priority, s.scheduled_at))
        chosen = sorted_specs[0]
        self._scheduled.pop(chosen.id)
        
        sig = f"{chosen.target_asset}:{chosen.recon_type}"
        self._active_signatures.discard(sig)
        return chosen
