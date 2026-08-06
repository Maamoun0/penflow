"""
Continuous Change Detection Engine for PenFlow.

Capabilities:
  - Tracks JS bundle hashes and triggers re-analysis on bundle updates.
  - Diffing historical vs current subdomains & DNS CNAME records to detect new attack surfaces.
"""
import hashlib
from typing import Dict, Any, List, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.change_detector")


class ReconChangeEvent:
    def __init__(self, target_asset: str, change_type: str, details: Dict[str, Any]):
        self.target_asset = target_asset
        self.change_type = change_type
        self.details = details


class ChangeDetectionEngine:
    """
    Tracks client-side JS bundle hashes and asset topologies to detect attack surface changes.
    """

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

    def inspect_and_detect(self, asset: str, obs_type: str, data: Dict[str, Any]) -> Optional[ReconChangeEvent]:
        """Backward compatibility method for ReconPipeline."""
        return ReconChangeEvent(asset, obs_type, data)


# Backward compatibility aliases
ChangeDetector = ChangeDetectionEngine
