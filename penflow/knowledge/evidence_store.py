from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from penflow.shared.utils import compute_sha256, get_utc_timestamp
from penflow.shared.exceptions import InfrastructureError

@dataclass(frozen=True)
class EvidenceArtifact:
    sha256: str
    content_type: str
    data: bytes
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=get_utc_timestamp)

class EvidenceStore:
    """
    Immutable Content-Addressable Storage (CAS) for raw evidence artifacts indexed by SHA-256 hash.
    """
    def __init__(self):
        self._artifacts: Dict[str, EvidenceArtifact] = {}

    def store_evidence(self, data: bytes | str, content_type: str = "text/plain", metadata: Optional[Dict[str, Any]] = None) -> EvidenceArtifact:
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data

        hash_key = compute_sha256(data_bytes)
        
        if hash_key in self._artifacts:
            return self._artifacts[hash_key]

        artifact = EvidenceArtifact(
            sha256=hash_key,
            content_type=content_type,
            data=data_bytes,
            metadata=metadata or {},
            created_at=get_utc_timestamp()
        )
        self._artifacts[hash_key] = artifact
        return artifact

    def get_evidence(self, sha256_hash: str) -> Optional[EvidenceArtifact]:
        return self._artifacts.get(sha256_hash)

    def has_evidence(self, sha256_hash: str) -> bool:
        return sha256_hash in self._artifacts
