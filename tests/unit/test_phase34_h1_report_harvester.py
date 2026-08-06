"""
Phase 34 Unit Tests — HackerOne Disclosed Reports Ingestion Engine.
Verifies conversion of raw HackerOne report objects into PenFlow markdown writeup files.
"""
import os
import tempfile
import pytest
from penflow.intelligence.hackerone_report_harvester import HackerOneReportHarvester


def test_h1_report_conversion():
    with tempfile.TemporaryDirectory() as tmp_dir:
        harvester = HackerOneReportHarvester(writeup_dir=tmp_dir)

        filepath = harvester.convert_report_to_writeup(
            report_id="123456",
            title="BOLA in User API Profile Endpoint",
            summary="User B token can access User A profile records.",
            vuln_type="id_access_analysis"
        )

        assert filepath is not None
        assert os.path.exists(filepath)

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        assert "123456" in content
        assert "BOLA in User API Profile Endpoint" in content
        assert "id_access_analysis" in content
