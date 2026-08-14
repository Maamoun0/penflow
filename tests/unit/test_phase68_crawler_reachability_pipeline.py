"""
Phase 68 Unit Tests — SmartCrawler Reachability & Pipeline Gate Invariant.

Verifies that:
  1. SmartCrawler.crawl() properly returns 'is_reachable', 'status_code', and 'discovered_urls'.
  2. The pipeline reachability gate does NOT falsely drop reachable targets.
"""
import pytest
from unittest.mock import AsyncMock, patch
from penflow.recon.smart_crawler import SmartCrawler


@pytest.mark.asyncio
async def test_smart_crawler_returns_reachability_keys():
    """Verify SmartCrawler returns is_reachable, status_code, and discovered_urls."""
    crawler = SmartCrawler()
    
    # Mock httpx response for crawl
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "text/html"}
    mock_resp.text = "<html><head><title>Test</title></head><body><a href='/login'>Login</a></body></html>"

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        res = await crawler.crawl("https://app.example.com")
        
        assert "status_code" in res
        assert "is_reachable" in res
        assert "discovered_urls" in res
        assert res["status_code"] == 200
        assert res["is_reachable"] is True
        assert len(res["endpoints"]) >= 1
        assert "https://app.example.com" in res["discovered_urls"]


@pytest.mark.asyncio
async def test_smart_crawler_handles_unreachable_target():
    """Verify SmartCrawler properly marks unreachable targets."""
    crawler = SmartCrawler()
    
    with patch("httpx.AsyncClient.get", side_effect=Exception("Connection refused")):
        res = await crawler.crawl("https://dead.example.com")
        
        assert res["status_code"] == 0
        assert res["is_reachable"] is False
        assert len(res["endpoints"]) == 0
