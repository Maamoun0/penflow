from dataclasses import dataclass, field
from typing import Dict, List, Optional
from penflow.shared.utils import get_utc_timestamp

@dataclass
class TechnologyProfile:
    asset: str
    framework: Optional[str] = None
    backend: Optional[str] = None
    frontend: Optional[str] = None
    cloud: Optional[str] = None
    cdn: Optional[str] = None
    waf: Optional[str] = None
    authentication: Optional[str] = None
    caching: Optional[str] = None
    updated_at: float = field(default_factory=get_utc_timestamp)

class TechnologyFingerprintEngine:
    """
    Technology fingerprinting profile manager.
    """
    def __init__(self):
        self._profiles: Dict[str, TechnologyProfile] = {}

    def update_profile(
        self,
        asset: str,
        framework: Optional[str] = None,
        backend: Optional[str] = None,
        frontend: Optional[str] = None,
        cloud: Optional[str] = None,
        cdn: Optional[str] = None,
        waf: Optional[str] = None,
        authentication: Optional[str] = None,
        caching: Optional[str] = None
    ) -> TechnologyProfile:
        asset_clean = asset.strip().lower()
        if asset_clean not in self._profiles:
            self._profiles[asset_clean] = TechnologyProfile(asset=asset_clean)

        prof = self._profiles[asset_clean]
        if framework: prof.framework = framework
        if backend: prof.backend = backend
        if frontend: prof.frontend = frontend
        if cloud: prof.cloud = cloud
        if cdn: prof.cdn = cdn
        if waf: prof.waf = waf
        if authentication: prof.authentication = authentication
        if caching: prof.caching = caching
        prof.updated_at = get_utc_timestamp()
        return prof

    def get_profile(self, asset: str) -> Optional[TechnologyProfile]:
        return self._profiles.get(asset.strip().lower())
