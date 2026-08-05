from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from penflow.shared.utils import generate_uuid, get_utc_timestamp

@dataclass
class AssetNode:
    id: str = field(default_factory=generate_uuid)
    canonical_name: str = ""
    asset_type: str = "subdomain"  # subdomain, url, ip, repository, mobile_app, api_endpoint, certificate, cloud_resource
    aliases: Set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=get_utc_timestamp)
    last_seen: float = field(default_factory=get_utc_timestamp)
    metadata: Dict[str, str] = field(default_factory=dict)

class AssetRegistry:
    """
    Maintains one canonical identity for every asset, tracking aliases and first/last seen timestamps.
    """
    def __init__(self):
        self._assets: Dict[str, AssetNode] = {}
        self._canonical_lookup: Dict[str, str] = {}  # alias or canonical -> asset_id

    def register_asset(self, canonical_name: str, asset_type: str, metadata: Optional[Dict[str, str]] = None) -> AssetNode:
        name_clean = canonical_name.strip().lower()
        now = get_utc_timestamp()

        if name_clean in self._canonical_lookup:
            asset_id = self._canonical_lookup[name_clean]
            asset = self._assets[asset_id]
            asset.last_seen = now
            if metadata:
                asset.metadata.update(metadata)
            return asset

        asset = AssetNode(
            canonical_name=name_clean,
            asset_type=asset_type,
            first_seen=now,
            last_seen=now,
            metadata=metadata or {}
        )
        asset.aliases.add(name_clean)
        self._assets[asset.id] = asset
        self._canonical_lookup[name_clean] = asset.id
        return asset

    def add_alias(self, asset_id: str, alias: str) -> None:
        alias_clean = alias.strip().lower()
        if asset_id in self._assets:
            asset = self._assets[asset_id]
            asset.aliases.add(alias_clean)
            self._canonical_lookup[alias_clean] = asset_id

    def get_asset_by_name(self, name: str) -> Optional[AssetNode]:
        name_clean = name.strip().lower()
        asset_id = self._canonical_lookup.get(name_clean)
        if asset_id:
            return self._assets.get(asset_id)
        return None

    def get_all(self) -> List[AssetNode]:
        return list(self._assets.values())

    def get_all_assets(self) -> List[AssetNode]:
        return list(self._assets.values())
