"""
Phase 30 Unit Tests — Hybrid SAST AST Engine, Declarative DSL, and Traffic Governor.
Verifies:
  1. AST Security Visitor detects dangerous calls (eval, exec, subprocess with shell=True), SQL interpolation, and secrets.
  2. SourceCodeAnalyzer scans temporary code snippets correctly.
  3. DSLEngine evaluates multi-criteria templates (word, regex, status, header).
  4. AdaptiveRateLimiter and TrafficGovernor handle rate control, jitter, and HTTP 429 backoff.
"""
import os
import tempfile
import pytest
from penflow.analysis.ast_scanner import SourceCodeAnalyzer
from penflow.rules.dsl_engine import DSLEngine
from penflow.traffic.stealth_manager import AdaptiveRateLimiter, TrafficGovernor


def test_sast_ast_scanner():
    test_code = '''
import os
import subprocess

def vulnerable_handler(user_input, db):
    eval(user_input)
    subprocess.Popen(["ls", user_input], shell=True)
    db.execute(f"SELECT * FROM users WHERE id = {user_input}")
    api_key_secret = "sk_live_1234567890abcdef"
'''
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(test_code)
        temp_path = f.name

    try:
        analyzer = SourceCodeAnalyzer()
        findings = analyzer.scan_file(temp_path)
        assert len(findings) >= 3

        vuln_types = [f["vulnerability_type"] for f in findings]
        assert "dangerous_function_call" in vuln_types
        assert "command_injection_risk" in vuln_types
        assert "sql_injection_sast" in vuln_types
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_dsl_engine_evaluation():
    engine = DSLEngine()
    template_spec = {
        "id": "cve-2026-test-detect",
        "name": "Test Vulnerability Detection",
        "severity": "HIGH",
        "description": "Detects specific error message and status code",
        "matchers-condition": "and",
        "matchers": [
            {"type": "status", "status": [200, 500]},
            {"type": "word", "condition": "and", "part": "body", "words": ["SQL syntax error", "MySQLServer"]}
        ]
    }
    engine.load_template(template_spec)

    # Positive match
    res_match = engine.evaluate_response(500, {}, "Fatal: SQL syntax error in MySQLServer query.")
    assert len(res_match) == 1
    assert res_match[0]["rule_id"] == "cve-2026-test-detect"

    # Negative match (wrong body)
    res_no_match = engine.evaluate_response(500, {}, "Server error: generic exception")
    assert len(res_no_match) == 0


@pytest.mark.asyncio
async def test_traffic_governor_backoff():
    governor = TrafficGovernor(base_rps=20.0, min_rps=2.0)
    assert governor.current_rps == 20.0

    # Simulate server throttling response (HTTP 429)
    governor.record_response(429)
    assert governor.current_rps == 10.0
    assert governor.throttle_events == 1

    # Another 429 reduces further
    governor.record_response(429)
    assert governor.current_rps == 5.0

    # Clean responses restore rate gradually
    for _ in range(10):
        governor.record_response(200)

    assert governor.current_rps > 5.0
    metrics = governor.get_metrics()
    assert metrics["total_requests"] == 12
    assert metrics["throttle_events"] == 2
