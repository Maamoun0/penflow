"""
Phase 31 Unit Tests — Bug Bounty Program Scope Monitor.
Verifies:
  1. Parsing HackerOne JSON scope manifests.
  2. Detecting newly added in-scope targets on scope update iterations.
"""
import pytest
from penflow.recon.bugbounty_scope_monitor import BugBountyScopeMonitor, ScopeAsset


def test_scope_monitor_parsing_and_diffing():
    monitor = BugBountyScopeMonitor()

    raw_scope_v1 = {
        "targets": {
            "in_scope": [
                {"asset_identifier": "api.target.com", "asset_type": "URL", "eligible_for_bounty": True},
                {"asset_identifier": "*.target.com", "asset_type": "WILDCARD", "eligible_for_bounty": True}
            ]
        }
    }

    assets_v1 = monitor.parse_hackerone_scope_manifest("target_corp", raw_scope_v1)
    assert len(assets_v1) == 2
    assert assets_v1[0].identifier == "api.target.com"

    # Initial run establishes baseline snapshot
    new_v1 = monitor.detect_new_scope_assets("target_corp", assets_v1)
    assert len(new_v1) == 0

    # Version 2 with a new asset added
    raw_scope_v2 = {
        "targets": {
            "in_scope": [
                {"asset_identifier": "api.target.com", "asset_type": "URL", "eligible_for_bounty": True},
                {"asset_identifier": "*.target.com", "asset_type": "WILDCARD", "eligible_for_bounty": True},
                {"asset_identifier": "new-auth.target.com", "asset_type": "DOMAIN", "eligible_for_bounty": True}
            ]
        }
    }

    assets_v2 = monitor.parse_hackerone_scope_manifest("target_corp", raw_scope_v2)
    assert len(assets_v2) == 3

    new_v2 = monitor.detect_new_scope_assets("target_corp", assets_v2)
    assert len(new_v2) == 1
    assert new_v2[0].identifier == "new-auth.target.com"
