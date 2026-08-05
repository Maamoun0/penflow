from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from penflow.shared.utils import generate_uuid, get_utc_timestamp

@dataclass(frozen=True)
class TimelineEvent:
    id: str = field(default_factory=generate_uuid)
    asset_id: str = ""
    event_type: str = ""  # new_endpoint, new_js, new_admin_path, new_graphql
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=get_utc_timestamp)

class TimelineEngine:
    """
    Chronological timeline engine tracking asset state evolution over time.
    """
    def __init__(self):
        self._timeline: Dict[str, List[TimelineEvent]] = {}  # asset_id -> events

    def record_event(self, asset_id: str, event_type: str, description: str, details: Optional[Dict[str, Any]] = None) -> TimelineEvent:
        if asset_id not in self._timeline:
            self._timeline[asset_id] = []

        evt = TimelineEvent(
            asset_id=asset_id,
            event_type=event_type,
            description=description,
            details=details or {},
            timestamp=get_utc_timestamp()
        )
        self._timeline[asset_id].append(evt)
        # Sort chronologically
        self._timeline[asset_id].sort(key=lambda e: e.timestamp)
        return evt

    def get_asset_timeline(self, asset_id: str) -> List[TimelineEvent]:
        return list(self._timeline.get(asset_id, []))
