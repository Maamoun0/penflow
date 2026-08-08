import pytest
import pytest_asyncio
from penflow.infrastructure.stealth_engine import StealthEngine
from penflow.reporting.evidence_quality import EvidenceQualityEngine
from penflow.recon.temporal_window import TemporalAttackWindowDetector

@pytest.mark.asyncio
async def test_stealth_engine():
    stealth = StealthEngine(min_delay_ms=10, max_delay_ms=20, enable_jitter=True)
    headers = stealth.get_stealth_headers("example.com")
    assert "User-Agent" in headers
    assert "Host" in headers
    assert headers["Host"] == "example.com"
    
    # Test rate limit handling
    stealth.handle_rate_limit(429)
    assert stealth.current_backoff_factor > 1.0

    await stealth.apply_jitter()

def test_evidence_quality_engine():
    quality = EvidenceQualityEngine()
    curl_cmd = quality.generate_minimized_curl(
        method="POST",
        url="https://example.com/api/users",
        headers={"Authorization": "Bearer token123", "Content-Type": "application/json"},
        data='{"admin": true}'
    )
    assert "curl" in curl_cmd
    assert "https://example.com/api/users" in curl_cmd
    assert "--data-raw" in curl_cmd

    score = quality.assess_reproducibility(successful_verifications=10, total_attempts=10)
    assert score == 100.0

    triage = quality.format_triage_pack({
        "vulnerability_type": "ssrf_redirect_chain",
        "target_url": "https://example.com/api/fetch",
        "severity": "critical"
    })
    assert "title" in triage
    assert "CRITICAL" in triage["title"]

def test_temporal_attack_window_detector():
    detector = TemporalAttackWindowDetector()
    
    # Initial snapshot
    first = detector.record_snapshot("https://example.com/api/status", 200, 1024, "nginx/1.20", 100.0)
    assert first is None

    # Status drift event
    drift = detector.record_snapshot("https://example.com/api/status", 500, 1024, "nginx/1.20", 200.0)
    assert drift is not None
    assert drift["event"] == "status_code_drift"
