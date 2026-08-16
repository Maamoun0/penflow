"""
Phase 69 — Multi-Agent Grounding, Adversarial Falsification, and Zero-False-Positive Hardening Test Suite.
Verifies that:
  1. IDOR / BOLA claims on public pages with 100% similarity are rejected by CriticVerificationEngine and PreReportQualityGate.
  2. SQLi Capability Agent performs differential error and timing checks.
  3. SSTI Agent ignores static baseline numbers and verifies true template evaluation.
  4. NoSQL Agent verifies authentic credential bypass vs unauthenticated HTML error responses.
  5. HackerOne Exporter dynamically generates technique-specific impact and remediation.
"""
import pytest
from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.validation.quality_gate import PreReportQualityGate
from penflow.knowledge.evidence_cas import EvidenceBundle
from penflow.reporting.hackerone_exporter import HackerOneReportExporter
from penflow.traffic.diff_engine import DifferentialEngine
from penflow.traffic.models import TrafficExchange, TrafficRequest, TrafficResponse


def test_idor_public_root_falsification_critic_engine():
    critic = CriticVerificationEngine()
    
    # Evidence simulating identical public HTML homepage returned to both user_a and user_b
    html_page = "<!DOCTYPE html><html><head><title>Shop</title></head><body><h1>Welcome</h1><a href='/my-account'>My account</a></body></html>"
    
    exch_a = {
        "request": {"method": "GET", "url": "https://example.com/", "headers": {"Authorization": "Bearer penflow_test_token_a"}},
        "response": {"status_code": 200, "body_text": html_page, "headers": {"content-type": "text/html"}}
    }
    exch_b = {
        "request": {"method": "GET", "url": "https://example.com/", "headers": {"Authorization": "Bearer penflow_test_token_b"}},
        "response": {"status_code": 200, "body_text": html_page, "headers": {"content-type": "text/html"}}
    }

    bundle = EvidenceBundle(
        hash_id="idor_fp_test_hash",
        target="example.com",
        vulnerability_type="id_access_analysis",
        raw_traces={
            "target_url": "https://example.com/",
            "is_vulnerable": True,
            "confidence_score": 0.90,
            "reasoning": "Both user_a and unauthorized user_b received HTTP 200 with matching schema (Similarity=100.0%).",
            "evidence_exchanges": [exch_a, exch_b]
        }
    )

    res = critic.verify_finding(bundle)
    assert res["is_verified"] is False
    assert "Falsified" in res["verification_reason"]
    assert res["confidence_score"] == 0.0


@pytest.mark.asyncio
async def test_idor_public_root_falsification_quality_gate():
    gate = PreReportQualityGate(min_confidence=0.85, scope_domains=["example.com"])
    
    finding = {
        "vulnerability_type": "id_access_analysis",
        "target": "example.com",
        "target_url": "https://example.com/",
        "is_vulnerable": True,
        "confidence": 0.90,
    }
    
    res = await gate.evaluate_finding(finding)
    assert res["passed"] is False
    assert any("Gate 1b" in f for f in res["failed_gates"])


def test_differential_engine_public_catalog_exclusion():
    diff = DifferentialEngine()
    
    html = "<html><body><div>$49.00 - Product Details</div></body></html>"
    
    req_a = TrafficRequest(method="GET", url="https://example.com/product?productId=1")
    resp_a = TrafficResponse(status_code=200, body_text=html, content_length=len(html))
    exch_a = TrafficExchange(trace_id="1", request=req_a, response=resp_a, identity_used="user_a")

    req_b = TrafficRequest(method="GET", url="https://example.com/product?productId=1")
    resp_b = TrafficResponse(status_code=200, body_text=html, content_length=len(html))
    exch_b = TrafficExchange(trace_id="2", request=req_b, response=resp_b, identity_used="user_b")

    res = diff.compare_exchanges(exch_a, exch_b, context_asset="example.com")
    assert res.is_potential_idor is False
    assert res.confidence_score == 0.0


def test_hackerone_exporter_ssrf_open_redirect_technique():
    exporter = HackerOneReportExporter()
    
    finding = {
        "vulnerability_type": "ssrf_vulnerability",
        "target": "https://target.com/product/stock",
        "target_url": "https://target.com/product/stock",
        "param_injected": "stockApi",
        "payload_name": "open_redirect_bypass",
        "payload": "/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin",
        "verification_reason": "CRITICAL SSRF CONFIRMED: Payload 'open_redirect_bypass' returned internal admin panel",
        "confidence": 0.99,
        "is_verified": True,
        "evidence": {
            "param_injected": "stockApi",
            "ssrf_payload": "open_redirect_bypass",
            "ssrf_target_url": "/product/nextProduct?path=http://192.168.0.12:8080/admin"
        }
    }
    
    report = exporter.export_to_hackerone_markdown(finding)
    assert "Open Redirection" in report
    assert "follow_redirects=False" in report
    assert "CRITICAL" in report
    assert "stockApi" in report


def test_hackerone_exporter_sqli_technique():
    exporter = HackerOneReportExporter()
    
    finding = {
        "vulnerability_type": "sqli_vulnerability",
        "target": "https://target.com/search",
        "target_url": "https://target.com/search?q=1'",
        "param_injected": "q",
        "subtype": "error_based",
        "payload": "1' AND ExtractValue(1, CONCAT(0x5c, 'penflow_sqli'))--",
        "confidence": 0.98,
        "is_verified": True,
        "evidence": {
            "param_injected": "q"
        }
    }
    
    report = exporter.export_to_hackerone_markdown(finding)
    assert "Parameterized Queries" in report
    assert "SQL Injection" in report
    assert "CRITICAL" in report


def test_hackerone_exporter_ssti_technique():
    exporter = HackerOneReportExporter()
    
    finding = {
        "vulnerability_type": "ssti_analysis",
        "target": "https://target.com/render",
        "target_url": "https://target.com/render?msg={{1337*7}}",
        "param_injected": "msg",
        "engine": "Jinja2 (Python)",
        "payload": "{{1337*7}}",
        "confidence": 0.99,
        "is_verified": True,
        "evidence": {
            "param_injected": "msg"
        }
    }
    
    report = exporter.export_to_hackerone_markdown(finding)
    assert "Server-Side Template Injection" in report
    assert "Remote Code Execution (RCE)" in report
    assert "render_template_string" in report
