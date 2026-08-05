from dataclasses import dataclass, field
from typing import Dict, List, Any
from penflow.shared.utils import generate_uuid, get_utc_timestamp

@dataclass(frozen=True)
class ObservationRecord:
    id: str = field(default_factory=generate_uuid)
    asset_id: str = ""
    observation_type: str = ""  # http_response, header, certificate, js_file, repository, dns_record, technology_fingerprint
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=get_utc_timestamp)

class ObservationStore:
    """
    Append-only, immutable history store for raw discoveries and observations.
    """
    def __init__(self):
        self._records: List[ObservationRecord] = []

    def record_observation(self, asset_id: str, obs_type: str, data: Dict[str, Any]) -> ObservationRecord:
        record = ObservationRecord(
            asset_id=asset_id,
            observation_type=obs_type,
            data=data,
            timestamp=get_utc_timestamp()
        )
        self._records.append(record)
        return record

    def get_by_asset(self, asset_id: str) -> List[ObservationRecord]:
        return [r for r in self._records if r.asset_id == asset_id]

    def get_by_type(self, obs_type: str) -> List[ObservationRecord]:
        return [r for r in self._records if r.observation_type == obs_type]

    def get_all(self) -> List[ObservationRecord]:
        return list(self._records)
