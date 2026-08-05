from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
import uuid
import time
from penflow.shared.utils import get_utc_timestamp

class IdentityType(str, Enum):
    ADMIN = "admin"
    PRIVILEGED = "privileged"
    STANDARD_USER_A = "user_a"
    STANDARD_USER_B = "user_b"
    UNAUTHENTICATED_GUEST = "guest"
    CUSTOM = "custom"

@dataclass
class AuthCredentials:
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    bearer_token: Optional[str] = None
    api_key: Optional[str] = None
    custom_params: Dict[str, str] = field(default_factory=dict)

    def get_effective_headers(self) -> Dict[str, str]:
        hdrs = dict(self.headers)
        if self.bearer_token:
            hdrs["Authorization"] = f"Bearer {self.bearer_token}"
        if self.api_key:
            hdrs["X-API-Key"] = self.api_key
        return hdrs

@dataclass
class Identity:
    id: str
    name: str
    identity_type: IdentityType
    credentials: AuthCredentials = field(default_factory=AuthCredentials)
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_active: bool = True

@dataclass
class TrafficRequest:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)
    body: Optional[str] = None
    json_data: Optional[Any] = None
    identity_id: Optional[str] = None
    timeout: float = 10.0
    timestamp: str = field(default_factory=get_utc_timestamp)

@dataclass
class TrafficResponse:
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body_text: str = ""
    body_json: Optional[Any] = None
    content_length: int = 0
    response_time_ms: float = 0.0
    is_error: bool = False
    timestamp: str = field(default_factory=get_utc_timestamp)

@dataclass
class TrafficExchange:
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request: Optional[TrafficRequest] = None
    response: Optional[TrafficResponse] = None
    elapsed_ms: float = 0.0
    identity_used: Optional[str] = None
    timestamp: str = field(default_factory=get_utc_timestamp)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
            "elapsed_ms": self.elapsed_ms,
            "identity_used": self.identity_used,
            "request": {
                "method": self.request.method if self.request else "",
                "url": self.request.url if self.request else "",
                "headers": self.request.headers if self.request else {},
                "params": self.request.params if self.request else {},
                "body": self.request.body if self.request else None,
            } if self.request else None,
            "response": {
                "status_code": self.response.status_code if self.response else 0,
                "headers": self.response.headers if self.response else {},
                "content_length": self.response.content_length if self.response else 0,
                "body_snippet": (self.response.body_text[:500] if self.response else ""),
            } if self.response else None
        }

@dataclass
class DiffField:
    field_path: str
    val_a: Any
    val_b: Any
    is_sensitive: bool = False
    note: str = ""

@dataclass
class DiffResult:
    endpoint_url: str
    identity_a: str
    identity_b: str
    status_code_a: int
    status_code_b: int
    body_similarity_ratio: float
    length_delta: int
    structural_match: bool
    discrepant_fields: List[DiffField] = field(default_factory=list)
    leaked_identifiers: List[str] = field(default_factory=list)
    is_potential_idor: bool = False
    is_potential_bfla: bool = False
    confidence_score: float = 0.0
    reasoning: str = ""
    evidence_exchange_a: Optional[TrafficExchange] = None
    evidence_exchange_b: Optional[TrafficExchange] = None
