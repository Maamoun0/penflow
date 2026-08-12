"""
Phase 37 Unit Tests — Week 3 & 4 Elite Intelligence & Reporting Engines.
Verifies:
  1. VulnerabilityChainEngine finding correlation & severity escalation.
  2. CVECorrelationEngine tech stack matching.
  3. ChangeDetectionEngine JS bundle hash diffing.
  4. ImpactScorer business impact calculations.
  5. HackerOneReportExporter markdown output generation.
  6. PassiveTrafficAnomalyDetector header/body disclosures.
"""
import pytest
from penflow.analysis.chain_builder import VulnerabilityChainEngine
from penflow.intelligence.cve_correlator import CVECorrelationEngine
from penflow.recon.change_detector import ChangeDetectionEngine
from penflow.reporting.impact_scorer import ImpactScorer
from penflow.reporting.hackerone_exporter import HackerOneReportExporter
from penflow.traffic.passive_anomaly_detector import PassiveTrafficAnomalyDetector


def test_chain_builder_engine():
    engine = VulnerabilityChainEngine()
    findings = [
        {"vulnerability_type": "ssrf", "target_url": "https://example.com/api/proxy"},
        {"vulnerability_type": "info_disclosure", "target_url": "https://example.com/meta-data/"}
    ]
    chains = engine.build_chains(findings)
    assert len(chains) == 1
    assert chains[0]["severity"] == "CRITICAL"
    assert chains[0]["chain_name"] == "SSRF to Cloud Metadata Credential Exfiltration"


def test_cve_correlator_engine():
    engine = CVECorrelationEngine()
    matches = engine.correlate(["Next.js 13.4.1", "Log4j 2.14.1"])
    assert len(matches) >= 2
    cve_ids = [m["cve_id"] for m in matches]
    assert "CVE-2021-44228" in cve_ids
    assert "CVE-2023-46298" in cve_ids


def test_change_detector_engine():
    engine = ChangeDetectionEngine()
    hist_hashes = {"app.js": engine.compute_hash("console.log('v1');")}
    curr_bundles = {"app.js": "console.log('v2');", "vendor.js": "console.log('v1');"}

    diff = engine.detect_js_changes(hist_hashes, curr_bundles)
    assert diff["has_changes"] is True
    assert "app.js" in diff["modified_bundles"]
    assert "vendor.js" in diff["new_bundles"]


def test_impact_scorer_and_h1_exporter():
    scorer = ImpactScorer()
    impact = scorer.evaluate_impact({"vulnerability_type": "idor"})
    assert "CWE-639" in impact["cwe"]

    exporter = HackerOneReportExporter()
    report = exporter.export_report({"vulnerability_type": "idor", "target_url": "https://example.com/api/user/1", "severity": "HIGH"})
    assert "Vulnerability Report: [HIGH] IDOR on https://example.com/api/user/1" in report
    assert "CVSS v3.1 Score" in report


def test_passive_traffic_anomaly_detector():
    detector = PassiveTrafficAnomalyDetector()
    headers = {"X-Internal-Server": "node-worker-01.internal"}
    body = "System Error: Traceback (most recent call last): File 'app.py', line 10"

    anomalies = detector.inspect_exchange("https://example.com/error", 500, headers, body)
    assert len(anomalies) >= 2
    types = [a["type"] for a in anomalies]
    assert "internal_header_leak" in types
    assert "stack_trace" in types
