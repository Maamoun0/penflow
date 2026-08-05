import pytest
from penflow.recon.smart_crawler import SmartCrawler
from penflow.recon.tech_fingerprint import TechnologyFingerprintEngine

@pytest.mark.asyncio
async def test_smart_crawler_and_tech_fingerprint():
    crawler = SmartCrawler(max_depth=1, max_pages=3)
    res = await crawler.crawl("https://example.com")
    
    assert "domain" in res
    assert len(res["endpoints"]) > 0

    fp_engine = TechnologyFingerprintEngine()
    fp_res = await fp_engine.fingerprint("https://example.com")
    
    assert "url" in fp_res
    assert isinstance(fp_res["technologies"], list)
