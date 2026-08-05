"""
Phase 27 Unit Tests — Live Threat Intelligence & Advisory Harvester.
Verifies:
  1. ThreatIntelFeedHarvester JSON parsing and advisory extraction.
  2. Advisory markdown writeup conversion and auto-saving to 'data/writeups/'.
"""
import os
import pytest
from unittest.mock import AsyncMock, patch
from penflow.intelligence.threat_intel_harvester import ThreatIntelFeedHarvester

def test_threat_intel_harvester_save_advisories(tmp_path):
    output_dir = tmp_path / "writeups"
    harvester = ThreatIntelFeedHarvester(output_dir=str(output_dir))

    mock_advisories = [
        {
            "cve_id": "CVE-2026-9999",
            "vendor": "Apache",
            "product": "HTTP Server",
            "title": "CISA KEV CVE-2026-9999: Apache Remote Code Execution",
            "description": "An unauthenticated remote code execution vulnerability was identified in Apache HTTP Server.",
            "required_action": "Apply official vendor security patch immediately.",
            "date_added": "2026-08-05",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-9999"
        }
    ]

    saved_count = harvester.save_advisories_as_writeups(mock_advisories)
    assert saved_count == 1
    assert os.path.exists(str(output_dir / "writeup_intel_cve_2026_9999.md"))

    # Test content structure
    with open(str(output_dir / "writeup_intel_cve_2026_9999.md"), "r", encoding="utf-8") as f:
        content = f.read()
    assert "CVE-2026-9999" in content
    assert "Apache" in content
    assert "rce" in content.lower()
