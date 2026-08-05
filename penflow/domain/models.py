from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid

# =====================================================================
# 1. KNOWLEDGE WORLD (المعرفة العامة المستقلة عن الهدف)
# =====================================================================

@dataclass
class Knowledge:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    topic: str = ""  # e.g., 'GraphQL', 'JWT', 'OAuth'
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Technique:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""  # e.g., 'JWT Header Swap', 'UUID Enumeration'
    category: str = ""
    steps: List[str] = field(default_factory=list)

@dataclass
class Playbook:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""  # e.g., 'GraphQL Security Playbook'
    techniques: List[str] = field(default_factory=list)

@dataclass
class Research:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    source_url: str = ""
    summary: str = ""

@dataclass
class Pattern:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    condition: Dict[str, Any] = field(default_factory=dict)
    implied_vulnerability: str = ""

# =====================================================================
# 2. TARGET WORLD (العالم الحقيقي للهدف)
# =====================================================================

@dataclass
class Program:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    platform: str = "HackerOne"

@dataclass
class Scope:
    in_scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)

@dataclass
class Target:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    program_id: str = ""
    domain: str = ""
    scope: Scope = field(default_factory=Scope)

@dataclass
class Asset:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str = ""
    asset_type: str = "subdomain"  # subdomain, ip, s3_bucket, repository
    value: str = ""

@dataclass
class Parameter:
    name: str = ""
    param_type: str = "query"  # query, header, body_json, path
    sample_value: str = ""

@dataclass
class Endpoint:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str = ""
    asset_id: str = ""
    url: str = ""
    method: str = "GET"
    parameters: List[Parameter] = field(default_factory=list)

@dataclass
class Identity:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""  # User A, User B, Admin, Guest
    role: str = "user"
    user_id_ref: Optional[str] = None

@dataclass
class Session:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    identity_id: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)

@dataclass
class Relationship:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str = ""
    relation_type: str = ""  # e.g., 'USES_JWT', 'BELONGS_TO_SUBDOMAIN'
    target_id: str = ""

# =====================================================================
# 3. EXECUTION WORLD (عالم التنفيذ والتخطيط)
# =====================================================================

@dataclass
class Goal:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str = ""
    description: str = ""

@dataclass
class Task:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    goal_id: str = ""
    agent_assigned: str = ""
    task_type: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    status: str = "PENDING"
    dag_dependencies: List[str] = field(default_factory=list)

@dataclass
class Plan:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    goal_id: str = ""
    tasks: List[Task] = field(default_factory=list)

@dataclass
class Observation:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str = ""
    source: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

# =====================================================================
# 4. RESULT WORLD (عالم النتائج والأدلة)
# =====================================================================

@dataclass
class Candidate:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str = ""
    endpoint_id: str = ""
    vuln_type: str = ""
    discovered_by: str = ""
    confidence: float = 0.5
    raw_evidence: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    candidate_id: str = ""
    target_id: str = ""
    vuln_type: str = ""
    confidence: float = 0.95

@dataclass
class VerifiedFinding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    target_id: str = ""
    evidence_bundle_id: str = ""
    verified_at: float = field(default_factory=time.time)

@dataclass
class Evidence:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    har_log: Dict[str, Any] = field(default_factory=dict)
    raw_traces: List[str] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)

# =====================================================================
# 5. EXPERIENCE LAYER (الطبقة الخمسية: الخبرة المكتسبة عبر الزمن)
# =====================================================================

@dataclass
class ExperiencePattern:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tech_combination: List[str] = field(default_factory=list)  # e.g., ['GraphQL', 'JWT']
    technique_name: str = ""
    success_rate: float = 0.0  # Percentage of historical success
    times_tested: int = 0
    times_succeeded: int = 0
