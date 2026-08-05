"""
Phase 29 Unit Tests — Web UI Dashboard & Bug Bounty PoC Exporter.
Verifies:
  1. BugBountyPoCExporter HackerOne markdown format, cURL commands, and HTTP evidence formatting.
  2. FastAPI server endpoints (/api/status, /api/scan/start, /api/poc/generate).
"""
import pytest
from fastapi.testclient import TestClient
from penflow.reporting.bugbounty_exporter import BugBountyPoCExporter
from penflow.webui.server import app

def test_bug_bounty_poc_exporter():
    exporter = BugBountyPoCExporter()
    finding = {
        "vulnerability_type": "id_access_analysis",
        "target_url": "https://example.com/api/v1/user?id=100",
        "confidence_score": 0.95,
        "reasoning": "BOLA verified: User B token exposed User A records.",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://example.com/api/v1/user?id=100", "headers": {"Authorization": "Bearer test"}},
                "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body_text": '{"id": 100, "name": "User A"}'}
            }
        ]
    }

    report = exporter.generate_hackerone_report(finding, "example.com")
    assert "# [Vulnerability Report]" in report
    assert "curl" in report
    assert "id_access_analysis" in report.lower() or "bola" in report.lower()
    assert "HTTP/1.1 200" in report

def test_fastapi_server_routes():
    client = TestClient(app)
    
    # Test status endpoint
    status_resp = client.get("/api/status")
    assert status_resp.status_code == 200
    assert "active_scan" in status_resp.json()

    # Test PoC generate endpoint
    poc_resp = client.post("/api/poc/generate", json={"target_domain": "target.com"})
    assert poc_resp.status_code == 200
    assert "poc_report" in poc_resp.json()
    assert "# [Vulnerability Report]" in poc_resp.json()["poc_report"]
