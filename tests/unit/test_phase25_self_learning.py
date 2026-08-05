"""
Phase 25 Unit Tests — Self-Learning & Knowledge Ingestion Engine.
Verifies:
  1. WriteupMiner pattern extraction, vulnerability classification, and path parsing.
  2. WriteupIngestionEngine dataset mining and YAML rules generation (config/rules/mined_rules.yaml).
  3. ExperienceLayer writeup absorption and weight adjustments.
  4. DeclarativeRuleLoader integration with mined YAML rules.
"""
import os
import pytest
from penflow.intelligence.writeup_miner import WriteupMiner
from penflow.intelligence.writeup_loader import WriteupIngestionEngine
from penflow.intelligence.experience_layer import ExperienceLayer
from penflow.planning.rule_loader import DeclarativeRuleLoader

def test_writeup_miner_parsing():
    miner = WriteupMiner()
    title = "SSRF AWS Metadata IAM Key Theft"
    content = "Target contained an SSRF on /api/v1/fetch?url=http://169.254.169.254/latest/meta-data/ exposing AWS IAM keys."
    writeup = miner.parse_writeup_text(title, content)

    assert writeup.title == title
    assert "ssrf" in writeup.detected_vulnerabilities
    assert "aws" in writeup.target_technology.lower()
    assert len(writeup.extracted_patterns) > 0

def test_experience_layer_absorption():
    exp = ExperienceLayer()
    miner = WriteupMiner()
    writeup = miner.parse_writeup_text(
        "BOLA User Profile Access",
        "Found BOLA on /api/v1/user/profile?id=100 using User A token for User B."
    )
    exp.absorb_writeup(writeup)
    mult = exp.get_priority_multiplier("idor")
    assert mult > 1.0

def test_writeup_ingestion_engine():
    engine = WriteupIngestionEngine()
    res = engine.ingest_directory("data/writeups", rules_output_file="config/rules/mined_rules.yaml")
    assert res["ingested_count"] >= 5
    assert res["rules_generated"] > 0
    assert os.path.exists("config/rules/mined_rules.yaml")

def test_rule_loader_loads_mined_rules():
    loader = DeclarativeRuleLoader(rules_dir="config/rules")
    rules = loader.load_rules()
    assert len(rules) > 0
    mined_ids = [r.rule_id for r in rules if r.rule_id.startswith("R_MINED_")]
    assert len(mined_ids) > 0
