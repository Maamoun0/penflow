from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from penflow.shared.utils import generate_uuid, get_utc_timestamp

@dataclass
class ReconChangeEvent:
    id: str = field(default_factory=generate_uuid)
    change_type: str = ""  # new_js, new_endpoint, new_certificate, dns_changed, technology_changed
    asset: str = ""
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    timestamp: float = field(default_factory=get_utc_timestamp)

class ChangeDetector:
    """
    Diff detection engine producing ReconChangeEvent objects on target delta observation.
    """
    def __init__(self):
        self._history: Dict[str, Dict[str, Any]] = {}
        self.detected_changes: List[ReconChangeEvent] = []

    def inspect_and_detect(self, asset: str, property_name: str, new_value: Any, change_type: str) -> Optional[ReconChangeEvent]:
        asset_clean = asset.strip().lower()
        key = f"{asset_clean}:{property_name}"
        
        if key not in self._history:
            self._history[key] = new_value
            evt = ReconChangeEvent(change_type=change_type, asset=asset_clean, old_value=None, new_value=new_value)
            self.detected_changes.append(evt)
            return evt

        old_val = self._history[key]
        if old_val != new_value:
            self._history[key] = new_value
            evt = ReconChangeEvent(change_type=change_type, asset=asset_clean, old_value=old_val, new_value=new_value)
            self.detected_changes.append(evt)
            return evt

        return None
