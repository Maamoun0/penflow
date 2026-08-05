"""
Bug Bounty Program Scope Monitor Engine for PenFlow.

Monitors HackerOne / Bugcrowd structured program scope manifests.
Performs real-time asset diffing to identify newly added in-scope targets
and triggers automated autonomous research scans ahead of competitors.
"""
import time
import json
import httpx
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.bugbounty_scope_monitor")


@dataclass
class ScopeAsset:
    identifier: str
    asset_type: str  # URL, DOMAIN, WILDCARD, CIDR
    eligible_for_bounty: bool = True
    max_severity: str = "CRITICAL"
    first_seen: float = field(default_factory=time.time)


class BugBountyScopeMonitor:
    """
    Monitors Bug Bounty scopes and triggers immediate research scans on new targets.
    """

    def __init__(self):
        self._known_scopes: Dict[str, Set[str]] = {}  # program_handle -> set of asset identifiers

    def parse_hackerone_scope_manifest(self, program_handle: str, scope_json: Dict[str, Any]) -> List[ScopeAsset]:
        """Parses structured HackerOne JSON scope data into ScopeAsset objects."""
        assets: List[ScopeAsset] = []
        raw_targets = scope_json.get("targets", {}).get("in_scope", []) or scope_json.get("in_scope", [])

        for item in raw_targets:
            asset_val = item.get("asset_identifier") or item.get("target") or item.get("endpoint", "")
            asset_type = item.get("asset_type") or ("WILDCARD" if "*." in asset_val else "DOMAIN")
            bounty_eligible = item.get("eligible_for_bounty", True)
            max_sev = item.get("max_severity", "CRITICAL")

            if asset_val:
                assets.append(ScopeAsset(
                    identifier=asset_val.strip().lower(),
                    asset_type=asset_type.upper(),
                    eligible_for_bounty=bounty_eligible,
                    max_severity=max_sev
                ))

        logger.info(f"[ScopeMonitor] Parsed {len(assets)} in-scope assets for program '{program_handle}'.")
        return assets

    def detect_new_scope_assets(self, program_handle: str, current_assets: List[ScopeAsset]) -> List[ScopeAsset]:
        """Compares current scope state against historical snapshot to find newly added targets."""
        current_ids = {a.identifier for a in current_assets}

        if program_handle not in self._known_scopes:
            # Initial baseline run
            self._known_scopes[program_handle] = current_ids
            logger.info(f"[ScopeMonitor] Established baseline scope snapshot for '{program_handle}' ({len(current_ids)} assets).")
            return []

        previous_ids = self._known_scopes[program_handle]
        new_ids = current_ids - previous_ids

        # Update snapshot
        self._known_scopes[program_handle] = current_ids

        new_assets = [a for a in current_assets if a.identifier in new_ids]
        if new_assets:
            logger.warning(
                f"[ScopeMonitor] 🚨 ALERT! Detected {len(new_assets)} NEW IN-SCOPE ASSETS for '{program_handle}': "
                f"{[a.identifier for a in new_assets]}"
            )
        return new_assets

    async def fetch_remote_scope(self, scope_url: str) -> Dict[str, Any]:
        """Fetches remote JSON scope file from a program URL or feed API."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(scope_url)
                if resp.status_code == 200:
                    return resp.json()
        except Exception as e:
            logger.error(f"[ScopeMonitor] Error fetching remote scope from '{scope_url}': {e}")
        return {}
