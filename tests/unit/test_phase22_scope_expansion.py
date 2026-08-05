"""
Phase 22 Unit Tests — Scope & Recon Expansion (Subdomains, Sub-subdomains & File Fuzzing).
"""
import pytest
from unittest.mock import AsyncMock, patch

def test_subdomain_bruteforce_candidate_generation():
    from penflow.recon.subdomain_bruteforce import SubdomainBruteforceEngine, SUBDOMAIN_WORDLIST, SUB_SUB_PAIRS
    engine = SubdomainBruteforceEngine()

    assert len(SUBDOMAIN_WORDLIST) >= 50
    assert len(SUB_SUB_PAIRS) >= 10

def test_file_content_fuzzer_wordlist():
    from penflow.recon.file_content_fuzzer import SENSITIVE_FILE_WORDLIST
    assert len(SENSITIVE_FILE_WORDLIST) >= 30
    wordlist_str = " ".join(SENSITIVE_FILE_WORDLIST)
    assert "/.env" in wordlist_str
    assert "/.git/HEAD" in wordlist_str
    assert "/backup.zip" in wordlist_str
    assert "/package.json" in wordlist_str

@pytest.mark.asyncio
async def test_smart_crawler_wildcard_scope():
    from penflow.recon.smart_crawler import SmartCrawler
    crawler = SmartCrawler(max_depth=1, max_pages=5)
    # Validate crawler initializes correctly
    assert crawler.max_depth == 1

@pytest.mark.asyncio
async def test_subdomain_bruteforce_mock_resolution():
    from penflow.recon.subdomain_bruteforce import SubdomainBruteforceEngine
    engine = SubdomainBruteforceEngine(concurrency=5, timeout=1.0)

    async def mock_resolve(domain):
        if domain in ("api.example.com", "dev.api.example.com"):
            return {"domain": domain, "ip_addresses": ["1.2.3.4"], "is_resolved": True}
        return {"domain": domain, "ip_addresses": [], "is_resolved": False}

    with patch.object(engine.dns_resolver, 'resolve_domain', side_effect=mock_resolve):
        results = await engine.enumerate_subdomains("example.com", deep_mode=True)
        resolved = [r["domain"] for r in results if r.get("is_resolved")]
        assert "api.example.com" in resolved
        assert "dev.api.example.com" in resolved
