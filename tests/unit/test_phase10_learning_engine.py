import os
import pytest
from penflow.intelligence.writeup_loader import WriteupIngestionEngine
from penflow.intelligence.experience_layer import ExperienceLayer

def test_writeup_ingestion_engine(tmp_path):
    # 1. Create temporary sample writeup
    sample_dir = tmp_path / "writeups"
    sample_dir.mkdir()
    sample_file = sample_dir / "sample_idor_writeup.md"
    sample_file.write_text("""
    # BOLA in User Invoices API
    Discovered IDOR on /api/v1/invoices/999 by swapping authorization tokens.
    Target framework: Node.js Express.
    """)

    experience = ExperienceLayer()
    engine = WriteupIngestionEngine(experience_layer=experience)

    rules_out = tmp_path / "rules" / "mined_rules.yaml"
    res = engine.ingest_directory(str(sample_dir), rules_output_file=str(rules_out))

    assert res["ingested_count"] == 1
    assert res["rules_generated"] > 0
    assert os.path.exists(str(rules_out))

    # Verify stats update in ExperienceLayer
    stats = experience.get_all_stats()
    assert "idor" in stats
    assert experience.get_priority_multiplier("idor") > 1.0
