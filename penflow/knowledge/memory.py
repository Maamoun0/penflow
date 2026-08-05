from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from penflow.shared.utils import generate_uuid, get_utc_timestamp

@dataclass
class MemoryEntry:
    id: str = field(default_factory=generate_uuid)
    category: str = ""  # interesting_endpoints, vulnerable_patterns, discovered_tech, previous_findings, successful_payloads, failed_payloads
    key: str = ""
    value: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    created_at: float = field(default_factory=get_utc_timestamp)

class MemoryEngine:
    """
    Persistent memory engine storing historical patterns, endpoints, technologies, and payload execution outcomes.
    """
    def __init__(self):
        self._memory: Dict[str, List[MemoryEntry]] = {
            "interesting_endpoints": [],
            "vulnerable_patterns": [],
            "discovered_tech": [],
            "previous_findings": [],
            "successful_payloads": [],
            "failed_payloads": []
        }

    def store_memory(self, category: str, key: str, value: Dict[str, Any], confidence: float = 1.0) -> MemoryEntry:
        if category not in self._memory:
            self._memory[category] = []

        entry = MemoryEntry(
            category=category,
            key=key,
            value=value,
            confidence=confidence,
            created_at=get_utc_timestamp()
        )
        self._memory[category].append(entry)
        return entry

    def get_memories(self, category: str, key_filter: Optional[str] = None) -> List[MemoryEntry]:
        entries = self._memory.get(category, [])
        if key_filter:
            return [e for e in entries if key_filter.lower() in e.key.lower()]
        return list(entries)
