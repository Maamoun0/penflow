import pytest
from penflow.recon.route_fuzzer import SmartRouteFuzzer
from penflow.recon.smart_crawler import SmartCrawler
from penflow.reporting.report_generator import MarkdownReportGenerator
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.planning.execution_plan import ExecutionPlan

@pytest.mark.asyncio
async def test_smart_route_fuzzer():
    fuzzer = SmartRouteFuzzer(timeout=2.0)
    # Test fuzzing against a mock URL
    discovered = await fuzzer.fuzz("https://example.com")
    assert isinstance(discovered, list)

@pytest.mark.asyncio
async def test_smart_crawler_js_mined_routes():
    crawler = SmartCrawler(max_depth=1, max_pages=2, timeout=2.0)
    res = await crawler.crawl("https://example.com")
    assert "endpoints" in res
    assert "forms" in res
    assert "js_files" in res
    assert "mined_js_routes" in res

@pytest.mark.asyncio
async def test_raw_http_report_generator():
    ks = KnowledgeStore()
    plan = ExecutionPlan()
    rep_gen = MarkdownReportGenerator()

    mock_finding = {
        "vulnerability_type": "nosql_injection",
        "evidence": {
            "target_url": "https://target.com/api/v1/search",
            "evidence_exchanges": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://target.com/api/v1/search",
                        "headers": {"Content-Type": "application/json"},
                        "body": '{"username": {"$ne": null}}'
                    },
                    "response": {
                        "status_code": 200,
                        "headers": {"Content-Type": "application/json"},
                        "body_text": '{"status": "authenticated"}'
                    }
                }
            ]
        }
    }

    report = rep_gen.generate_report("target.com", ks, plan, [mock_finding])
    assert "HTTP Evidence" in report
    assert "POST https://target.com/api/v1/search HTTP/1.1" in report
    assert "HTTP/1.1 200" in report
    assert '{"username": {"$ne": null}}' in report
