import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from penflow.shared.utils import compute_sha256, get_utc_timestamp
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.knowledge.evidence_cas")

@dataclass
class EvidenceBundle:
    hash_id: str
    target: str
    vulnerability_type: str
    raw_traces: Dict[str, Any]
    timestamp: float = field(default_factory=get_utc_timestamp)

class EvidenceCAS:
    """
    Content-Addressable Storage (CAS) for Security Research Evidence using SHA-256 digests.
    Ensures absolute tamper-proof evidence bundles.
    """
    def __init__(self):
        self._store: Dict[str, EvidenceBundle] = {}

    def store_evidence(self, target: str, vuln_type: str, raw_traces: Dict[str, Any]) -> EvidenceBundle:
        payload_bytes = json.dumps(raw_traces, sort_keys=True, default=str).encode("utf-8")
        hash_digest = compute_sha256(payload_bytes)

        bundle = EvidenceBundle(
            hash_id=hash_digest,
            target=target,
            vulnerability_type=vuln_type,
            raw_traces=raw_traces
        )
        self._store[hash_digest] = bundle
        logger.info(f"[EvidenceCAS] Stored tamper-proof evidence bundle '{hash_digest}' for vulnerability '{vuln_type}' on '{target}'")
        return bundle

    def get_evidence(self, hash_id: str) -> Optional[EvidenceBundle]:
        return self._store.get(hash_id)
