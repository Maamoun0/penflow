"""
Unit tests for HackerOneDisclosedReportsMiner & H1 Knowledge Continuous Training.
"""

import os
import pytest
from penflow.intelligence.h1_disclosed_reports_miner import HackerOneDisclosedReportsMiner
from penflow.intelligence.threat_intel_harvester import ThreatIntelFeedHarvester
from penflow.intelligence.continuous_learner import ContinuousLearnerDaemon


@pytest.mark.asyncio
async def test_h1_disclosed_reports_miner_harvesting(tmp_path):
    miner = HackerOneDisclosedReportsMiner(output_dir=str(tmp_path))
    reports = await miner.fetch_disclosed_h1_reports(max_items=5)
    
    assert len(reports) > 0
    saved_count = miner.save_h1_writeups(reports)
    assert saved_count > 0
    
    files = os.listdir(tmp_path)
    assert any(f.startswith("h1_writeup_") and f.endswith(".md") for f in files)


@pytest.mark.asyncio
async def test_continuous_learner_with_h1_miner(tmp_path):
    daemon = ContinuousLearnerDaemon(watch_dir=str(tmp_path), rules_file=str(tmp_path / "mined_rules.yaml"))
    res = await daemon.harvest_and_learn_once_async()
    
    assert "updated" in res
    assert os.path.exists(tmp_path / "mined_rules.yaml")
