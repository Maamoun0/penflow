from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional

@dataclass
class Capability:
    id: str
    name: str
    description: str = ""
    version: str = "1.0.0"
    author: str = "PenFlow Architecture Team"
    tags: List[str] = field(default_factory=list)
    required_observations: List[str] = field(default_factory=list)
    required_asset_types: List[str] = field(default_factory=list)
    required_technologies: List[str] = field(default_factory=list)
    supported_protocols: List[str] = field(default_factory=list)
    estimated_runtime: float = 10.0
    estimated_cost: float = 1.0
    parallelizable: bool = True
    dependencies: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    priority: int = 5
