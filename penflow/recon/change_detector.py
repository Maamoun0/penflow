"""
Continuous Change Detection Engine for PenFlow.

Capabilities:
  - Tracks JS bundle hashes and triggers re-analysis on bundle updates.
  - Diffing historical vs current subdomains & DNS CNAME records to detect new attack surfaces.
  - State tracking for asset observation changes.
"""
import hashlib
from typing import Dict, Any, List, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.change_detector")


class ReconChangeEvent:
    def __init__(self, target_asset: str, change_type: str, old_value: Any = None, new_value: Any = None, details: Optional[Dict[str, Any]] = None):
        self.target_asset = target_asset
        self.change_type = change_type
        self.old_value = old_value
        self.new_value = new_value
        self.details = details or {}


class ChangeDetectionEngine:
    """
    Tracks client-side JS bundle hashes and asset topologies to detect attack surface changes.
    """

    def __init__(self):
        self._state: Dict[str, Any] = {}

    def compute_hash(self, content: str) -> str:
        """Computes SHA-256 hash of a string content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def detect_js_changes(self, historical_hashes: Dict[str, str], current_bundles: Dict[str, str]) -> Dict[str, Any]:
        """Compares historical JS bundle hashes against current versions."""
        modified: List[str] = []
        new_files: List[str] = []

        for filename, content in current_bundles.items():
            curr_hash = self.compute_hash(content)
            if filename not in historical_hashes:
                new_files.append(filename)
            elif historical_hashes[filename] != curr_hash:
                modified.append(filename)

        has_changes = len(modified) > 0 or len(new_files) > 0
        if has_changes:
            logger.info(f"[ChangeDetector] Detected JS bundle changes: {len(modified)} modified, {len(new_files)} new files.")

        return {
            "has_changes": has_changes,
            "modified_bundles": modified,
            "new_bundles": new_files
        }

    def diff_subdomains(self, historical_subdomains: List[str], current_subdomains: List[str]) -> List[str]:
        """Returns new subdomains discovered since last scan."""
        hist_set = set(historical_subdomains)
        new_subs = [s for s in current_subdomains if s not in hist_set]
        if new_subs:
            logger.info(f"[ChangeDetector] Discovered {len(new_subs)} new subdomains!")
        return new_subs

    def inspect_and_detect(
        self,
        asset: str,
        property_name: Optional[str] = None,
        new_value: Any = None,
        change_type: str = "asset_changed",
        *args,
        **kwargs
    ) -> Optional[ReconChangeEvent]:
        """Tracks state changes for asset observations."""
        key = property_name or (args[0] if len(args) > 0 else "default_key")
        val = new_value if new_value is not None else (args[1] if len(args) > 1 else None)
        c_type = change_type or kwargs.get("change_type", "asset_changed")

        state_key = f"{asset}:{key}"
        old_val = self._state.get(state_key)

        if old_val is None:
            self._state[state_key] = val
            return ReconChangeEvent(asset, c_type, old_value=None, new_value=val)
        elif old_val != val:
            self._state[state_key] = val
            return ReconChangeEvent(asset, c_type, old_value=old_val, new_value=val)

        return None


# Backward compatibility aliases
ChangeDetector = ChangeDetectionEngine
