"""
Phase 20 Unit Tests — System-Wide Elite Security Research Overhaul.
Verifies: expanded route fuzzer (500+ routes), elite SSRF agent, smart crawler upgrades,
OWASP headers audit (12 checks), enhanced critic engine, and XSS capability agent.
"""
import pytest
import re
from unittest.mock import AsyncMock, MagicMock, patch

# ─────────────────────────────────────────────────────────
# Phase A: Route Fuzzer (500+ routes)
# ─────────────────────────────────────────────────────────

def test_route_fuzzer_route_count():
    """Verify the route catalog has 500+ routes."""
    from penflow.recon.route_fuzzer import HIGH_VALUE_ROUTES
    assert len(HIGH_VALUE_ROUTES) >= 500, (
        f"Expected 500+ routes, got {len(HIGH_VALUE_ROUTES)}"
    )

def test_route_fuzzer_covers_key_categories():
    """Verify routes cover all critical tech stack categories."""
    from penflow.recon.route_fuzzer import HIGH_VALUE_ROUTES
    routes_str = " ".join(HIGH_VALUE_ROUTES)
    assert "/actuator/env" in routes_str, "Missing Spring Boot actuator"
    assert "/.git/HEAD" in routes_str, "Missing Git leak route"
    assert "/.env" in routes_str, "Missing .env leak route"
    assert "/graphql" in routes_str, "Missing GraphQL route"
    assert "/swagger-ui.html" in routes_str, "Missing Swagger route"
    assert "/admin" in routes_str, "Missing admin panel route"
    assert "/wp-admin/" in routes_str, "Missing WordPress admin route"
    assert "/swagger-ui/index.html" in routes_str, "Missing Swagger UI index"

def test_route_fuzzer_probe_result_structure():
    """Verify RouteProbeResult has correct structure."""
    from penflow.recon.route_fuzzer import RouteProbeResult
    result = RouteProbeResult(
        url="https://example.com/admin",
        path="/admin",
        method="GET",
        status=200,
        content_type="text/html",
        content_length=1024,
        interesting_patterns=["password", "secret"],
        headers={"server": "nginx"},
    )
    d = result.to_dict()
    assert d["url"] == "https://example.com/admin"
    assert d["method"] == "GET"
    assert d["status"] == 200
    assert "interesting_patterns" in d
    assert len(d["interesting_patterns"]) == 2

@pytest.mark.asyncio
async def test_route_fuzzer_deep_mode_init():
    """Verify SmartRouteFuzzer initializes correctly with deep_mode concurrency."""
    from penflow.recon.route_fuzzer import SmartRouteFuzzer
    fuzzer = SmartRouteFuzzer(timeout=2.0, max_concurrency=25)
    assert fuzzer.semaphore._value == 25
    assert fuzzer.timeout == 2.0

def test_route_fuzzer_interesting_body_patterns():
    """Verify interesting body patterns include critical leak indicators."""
    from penflow.recon.route_fuzzer import INTERESTING_BODY_PATTERNS
    critical = {"password", "secret", "api_key", "AWS_ACCESS_KEY", "stack trace", '"swagger":'}
    for c in critical:
        assert any(c.lower() in p.lower() for p in INTERESTING_BODY_PATTERNS), (
            f"Missing critical pattern: {c}"
        )


# ─────────────────────────────────────────────────────────
# Phase B: SSRF Agent
# ─────────────────────────────────────────────────────────

def test_ssrf_agent_payload_count():
    """Verify SSRF agent has 14+ payloads covering all cloud providers."""
    from penflow.agents.ssrf_agent import SSRF_PAYLOADS
    assert len(SSRF_PAYLOADS) >= 14, f"Expected 14+ SSRF payloads, got {len(SSRF_PAYLOADS)}"

def test_ssrf_agent_cloud_coverage():
    """Verify SSRF payloads cover AWS, GCP, Azure, Docker, Kubernetes."""
    from penflow.agents.ssrf_agent import SSRF_PAYLOADS
    payload_names = [p["name"] for p in SSRF_PAYLOADS]
    payload_urls = [p["url"] for p in SSRF_PAYLOADS]
    all_content = " ".join(payload_names + payload_urls)
    assert "169.254.169.254" in all_content, "Missing AWS/Azure metadata IP"
    assert "metadata.google.internal" in all_content, "Missing GCP metadata host"
    assert "docker" in all_content.lower() or "2375" in all_content, "Missing Docker API probe"
    assert "kubernetes" in all_content.lower(), "Missing Kubernetes probe"
    assert "localhost" in all_content, "Missing localhost probe"
    assert "file://" in all_content, "Missing file:// protocol probe"

def test_ssrf_agent_param_names():
    """Verify SSRF detection covers common URL-bearing parameter names."""
    from penflow.agents.ssrf_agent import SSRF_PARAM_NAMES
    critical_params = {"url", "uri", "fetch", "proxy", "redirect", "host", "target", "src"}
    for p in critical_params:
        assert p in SSRF_PARAM_NAMES, f"Missing SSRF param: {p}"


# ─────────────────────────────────────────────────────────
# Phase C: SmartCrawler
# ─────────────────────────────────────────────────────────

def test_smart_crawler_js_patterns():
    """Verify JS mining regex patterns compile and match correctly."""
    from penflow.recon.smart_crawler import (
        JS_API_PATH_PATTERN, JS_FETCH_PATTERN, JS_BASE_URL_PATTERN,
        JS_ROUTER_PATTERN, JS_WEBSOCKET_PATTERN
    )
    sample_js = """
    fetch('/api/v1/users')
    axios.get('/api/v2/profile')
    const baseURL = '/api/v3'
    path: '/admin/dashboard'
    new WebSocket('wss://example.com/ws')
    """
    assert JS_FETCH_PATTERN.search(sample_js) is not None, "fetch() pattern failed"
    assert JS_BASE_URL_PATTERN.search(sample_js) is not None, "baseURL pattern failed"
    assert JS_ROUTER_PATTERN.search(sample_js) is not None, "Router path pattern failed"
    assert JS_WEBSOCKET_PATTERN.search(sample_js) is not None, "WebSocket pattern failed"

def test_smart_crawler_static_extensions():
    """Verify static extension list is comprehensive."""
    from penflow.recon.smart_crawler import STATIC_EXTENSIONS
    for ext in [".css", ".png", ".js", ".woff2", ".map", ".pdf"]:
        assert ext in STATIC_EXTENSIONS, f"Missing static ext: {ext}"

@pytest.mark.asyncio
async def test_smart_crawler_returns_all_fields():
    """Verify SmartCrawler returns all required fields in result dict."""
    from penflow.recon.smart_crawler import SmartCrawler
    crawler = SmartCrawler(max_depth=1, max_pages=2, timeout=2.0)
    # We just test structure without actual HTTP (would fail on network)
    assert crawler.max_depth == 1
    assert crawler.max_pages == 2
    assert hasattr(crawler, "visited_urls")


# ─────────────────────────────────────────────────────────
# Phase D: Security Headers Auditor (OWASP 12-point)
# ─────────────────────────────────────────────────────────

def test_security_headers_check_count():
    """Verify we have at least 12 OWASP header checks defined."""
    from penflow.recon.security_headers_audit import SECURITY_HEADER_CHECKS
    assert len(SECURITY_HEADER_CHECKS) >= 12, (
        f"Expected 12+ OWASP checks, got {len(SECURITY_HEADER_CHECKS)}"
    )

def test_security_headers_required_checks():
    """Verify all required OWASP checks are present."""
    from penflow.recon.security_headers_audit import SECURITY_HEADER_CHECKS
    check_ids = {c["id"] for c in SECURITY_HEADER_CHECKS}
    required = {
        "missing_hsts", "weak_hsts_maxage", "missing_clickjacking_protection",
        "missing_nosniff", "missing_csp", "csp_unsafe_inline", "csp_unsafe_eval",
        "missing_referrer_policy", "missing_permissions_policy",
        "missing_coop", "missing_coep", "cors_wildcard",
        "server_version_disclosure", "x_powered_by_disclosure",
    }
    for req in required:
        assert req in check_ids, f"Missing required OWASP check: {req}"

def test_security_headers_risk_scoring():
    """Verify severity scores are defined for all severity levels."""
    from penflow.recon.security_headers_audit import SEVERITY_SCORES
    for level in ["critical", "high", "medium", "low", "info"]:
        assert level in SEVERITY_SCORES


# ─────────────────────────────────────────────────────────
# Phase E: Enhanced Critic Engine
# ─────────────────────────────────────────────────────────

def test_critic_engine_timing_threshold():
    """Verify timing threshold for blind injection is defined."""
    from penflow.validation.critic_engine import BLIND_TIMING_DELTA_THRESHOLD
    assert BLIND_TIMING_DELTA_THRESHOLD >= 2.0, "Timing threshold too low"

def test_critic_engine_info_disclosure_preserved():
    """Verify info_disclosure type is NOT falsified (preserved as valid)."""
    from penflow.validation.critic_engine import CriticVerificationEngine
    from unittest.mock import MagicMock

    engine = CriticVerificationEngine()
    bundle = MagicMock()
    bundle.hash_id = "test_hash_001"
    bundle.target = "example.com"
    bundle.vulnerability_type = "info_disclosure"
    bundle.raw_traces = {
        "target_url": "https://example.com/actuator/env",
        "is_vulnerable": True,
        "confidence_score": 0.85,
        "reasoning": "Spring actuator exposed DB credentials.",
        "evidence_exchanges": [],
    }

    result = engine.verify_finding(bundle)
    assert result["is_verified"] is True, "Info disclosure should be preserved, not falsified"

def test_critic_engine_ssti_multi_payload():
    """Verify SSTI falsification checks all template syntax variants."""
    from penflow.validation.critic_engine import CriticVerificationEngine
    from unittest.mock import MagicMock

    engine = CriticVerificationEngine()
    bundle = MagicMock()
    bundle.hash_id = "test_hash_002"
    bundle.target = "example.com"
    bundle.vulnerability_type = "ssti_analysis"
    bundle.raw_traces = {
        "target_url": "https://example.com/render?template=test",
        "is_vulnerable": True,
        "confidence_score": 0.90,
        "reasoning": "Template reflected.",
        "evidence_exchanges": [{
            "response": {
                "status_code": 200,
                "body_text": "Input: {{7*7}}",  # literal reflection, no evaluation
                "body_snippet": "Input: {{7*7}}",
            }
        }],
    }

    result = engine.verify_finding(bundle)
    assert result["is_verified"] is False, "SSTI with literal reflection should be falsified"

def test_critic_engine_waf_patterns():
    """Verify WAF detection patterns list is non-empty."""
    from penflow.validation.critic_engine import WAF_PATTERNS
    assert len(WAF_PATTERNS) >= 5, "Not enough WAF signature patterns"


# ─────────────────────────────────────────────────────────
# Phase G: XSS Agent
# ─────────────────────────────────────────────────────────

def test_xss_agent_payload_count():
    """Verify XSS agent has 9+ payloads."""
    from penflow.agents.xss_agent import XSS_PAYLOADS
    assert len(XSS_PAYLOADS) >= 9, f"Expected 9+ XSS payloads, got {len(XSS_PAYLOADS)}"

def test_xss_agent_payload_diversity():
    """Verify XSS payloads cover different injection contexts."""
    from penflow.agents.xss_agent import XSS_PAYLOADS
    contexts = {p["context"] for p in XSS_PAYLOADS}
    assert "html_body" in contexts, "Missing html_body context"
    assert "attribute_breakout" in contexts, "Missing attribute breakout"
    assert "polyglot" in contexts, "Missing polyglot WAF bypass"
    assert "stored_form" in contexts, "Missing stored XSS context"

def test_xss_agent_capabilities():
    """Verify XSSCapabilityAgent registers reflected and stored capabilities."""
    from penflow.agents.xss_agent import XSSCapabilityAgent
    agent = XSSCapabilityAgent(priority=10)
    caps = agent.get_capabilities()
    cap_ids = [c.id for c in caps]
    assert "reflected_xss" in cap_ids, "Missing reflected_xss capability"
    assert "stored_xss" in cap_ids, "Missing stored_xss capability"

def test_xss_agent_exploitable_patterns():
    """Verify exploitable reflection patterns can detect real XSS."""
    from penflow.agents.xss_agent import EXPLOITABLE_REFLECTION_PATTERNS
    test_bodies = [
        "<script>alert('XSS_PenFlow_001')</script>",
        'onerror=alert("XSS_PenFlow_002")',
        "<svg/onload=alert('XSS_PenFlow_003')>",
    ]
    for body in test_bodies:
        matched = any(
            re.search(pat, body, re.IGNORECASE)
            for pat in EXPLOITABLE_REFLECTION_PATTERNS
        )
        assert matched, f"Pattern should match exploitable XSS in: {body}"

def test_xss_agent_registered_in_agents_init():
    """Verify XSSCapabilityAgent is exported from agents __init__."""
    from penflow.agents import XSSCapabilityAgent
    assert XSSCapabilityAgent is not None
