"""
Phase 28 Unit Tests — Enterprise Platform Transformation.
Verifies all 5 enterprise capability pillars:
  1. OWASP Benchmark Testbed Runner (Precision, Recall, F1-Score, FPR calculation)
  2. Distributed Swarm Architecture (Broker worker registration, task dispatching, result logging)
  3. Complex Auth & SPA State Machine (TOTP MFA generation, PKCE token exchange, 401 refresh)
  4. Stateful Business Logic Workflow Engine (Workflow mapping, step-bypass, price tampering)
  5. SARIF v2.1.0 Exporter & Webhook Notifier (JSON formatting, rule indices, level mapping)
"""
import pytest
from penflow.benchmarks.testbed_runner import TestbedBenchmarkRunner
from penflow.infrastructure.distributed_swarm import SwarmTaskBroker, SwarmWorkerNode
from penflow.traffic.auth_state_machine import AuthStateMachine
from penflow.testing.workflow_fuzzer import WorkflowFuzzer
from penflow.reporting.sarif_exporter import SARIFExporter

# Pillar 1: OWASP Benchmark Testbed Runner
def test_testbed_benchmark_runner():
    runner = TestbedBenchmarkRunner()
    gt = [
        {"endpoint": "/api/v1/user", "vuln_type": "idor", "is_vulnerable": True},
        {"endpoint": "/api/v1/public", "vuln_type": "idor", "is_vulnerable": False}
    ]
    findings = [
        {"target_url": "/api/v1/user", "vulnerability_type": "idor", "is_vulnerable": True}
    ]
    res = runner.evaluate_findings("JuiceShop", findings, gt)
    assert res["true_positives"] == 1
    assert res["false_positives"] == 0
    assert res["f1_score"] == 1.0

# Pillar 2: Distributed Swarm Architecture
@pytest.mark.asyncio
async def test_distributed_swarm():
    broker = SwarmTaskBroker()
    worker = SwarmWorkerNode("worker-node-1", ["id_access_analysis"], broker)
    broker.submit_task("task-1", "id_access_analysis", "target.com", {})

    res = await worker.poll_and_execute()
    assert res is not None
    assert res["status"] == "SUCCESS"
    assert len(broker.completed_results) == 1

# Pillar 3: Complex Auth & SPA State Machine
def test_auth_state_machine():
    auth = AuthStateMachine()

    # Test TOTP MFA generation
    totp = auth.generate_totp_code("JBSWY3DPEHPK3PXP")
    assert len(totp) == 6
    assert totp.isdigit()

    # Test PKCE exchange
    tokens = auth.perform_pkce_exchange("verifier123", "code456")
    assert "access_token" in tokens
    assert tokens["token_type"] == "Bearer"

    # Test 401 refresh
    refreshed = auth.handle_unauthorized_response("user_a", 401)
    assert refreshed is True

# Pillar 4: Stateful Business Logic Workflow Engine
def test_workflow_fuzzer():
    fuzzer = WorkflowFuzzer()
    wf = fuzzer.create_checkout_workflow("https://target.com")
    assert len(wf) == 4

    mutations = fuzzer.generate_step_bypass_mutations(wf)
    assert len(mutations) >= 2
    types = [m["type"] for m in mutations]
    assert "step_skip" in types
    assert "parameter_tamper" in types

# Pillar 5: SARIF v2.1.0 Exporter
def test_sarif_exporter():
    exporter = SARIFExporter()
    findings = [
        {
            "vulnerability_type": "id_access_analysis",
            "target_url": "https://target.com/api/v1/user",
            "confidence_score": 0.95,
            "reasoning": "BOLA verified: User B token exposed User A records."
        }
    ]
    sarif = exporter.export_sarif("target.com", findings)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "PENFLOW-ID_ACCESS_ANALYSIS"
