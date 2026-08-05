import pytest
from penflow.testing.payload_engine import PayloadTemplateEngine
from penflow.recon.smart_crawler import SmartCrawler
from penflow.recon.route_fuzzer import SmartRouteFuzzer

def test_payload_engine_deep_mode():
    engine_standard = PayloadTemplateEngine(deep_mode=False)
    engine_deep = PayloadTemplateEngine(deep_mode=True)
    assert engine_standard.deep_mode is False
    assert engine_deep.deep_mode is True

@pytest.mark.asyncio
async def test_deep_crawler_configuration():
    crawler_deep = SmartCrawler(max_depth=4, max_pages=100, timeout=2.0)
    assert crawler_deep.max_depth == 4
    assert crawler_deep.max_pages == 100

@pytest.mark.asyncio
async def test_deep_route_fuzzer_configuration():
    fuzzer_deep = SmartRouteFuzzer(timeout=2.0, max_concurrency=25)
    assert fuzzer_deep.semaphore._value == 25
