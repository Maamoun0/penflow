"""
Phase 26 Unit Tests — Continuous Background Learning Daemon.
Verifies:
  1. ContinuousLearnerDaemon file change monitoring and incremental training trigger.
  2. Single check & learn loop execution.
"""
import os
import pytest
from penflow.intelligence.continuous_learner import ContinuousLearnerDaemon

def test_continuous_learner_daemon_check_once(tmp_path):
    writeup_dir = tmp_path / "writeups"
    rules_file = tmp_path / "rules" / "mined_rules.yaml"
    writeup_dir.mkdir()

    # Create dummy writeup file
    sample_file = writeup_dir / "test_writeup.md"
    sample_file.write_text("""
# Test Writeup for Continuous Daemon
Endpoint: /api/v1/user/test?id=100
Vulnerability: idor
    """)

    daemon = ContinuousLearnerDaemon(watch_dir=str(writeup_dir), rules_file=str(rules_file), interval_seconds=1.0)
    res = daemon.check_and_learn_once()

    assert res["updated"] is True
    assert res["details"]["ingested_count"] >= 1
    assert os.path.exists(str(rules_file))

    # Second check without changes should return updated=False
    res_second = daemon.check_and_learn_once()
    assert res_second["updated"] is False
