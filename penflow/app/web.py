"""
PenFlow Web Interface.

Provides a FastAPI server to run PenFlow from a simple HTML/JS UI.
"""
import asyncio
from typing import List, Optional
from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from penflow.core.orchestrator import Orchestrator
from penflow.core.context import ExecutionContext
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.knowledge.evidence_cas import EvidenceCAS
from penflow.recon.smart_crawler import SmartCrawler
from penflow.capabilities.registry import CapabilityRegistry
from penflow.capabilities.resolver import CapabilityResolver
from penflow.capabilities.result import normalize_agent_result
from penflow.agents.base.registry_loader import RegistryLoader
from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.validation.quality_gate import PreReportQualityGate
from penflow.reporting.report_generator import MarkdownReportGenerator
from penflow.infrastructure.logger import get_logger
from penflow.traffic.proxy_engine import ProxyConfig
import os

logger = get_logger("penflow.web")

app = FastAPI(title="PenFlow API", description="PenFlow Vulnerability Research API")

# Serve static files (HTML, JS, CSS)
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

class ScanRequest(BaseModel):
    target: str
    proxy: Optional[str] = None
    deep_mode: bool = False
    enabled_agents: Optional[List[str]] = None


async def execute_scan(target_domain: str, proxy_url: Optional[str] = None, enabled_agents: Optional[List[str]] = None) -> str:
    """Executes the pipeline and returns the markdown report."""
    logger.info(f"[WebAPI] Starting scan against '{target_domain}'")
    proxy_cfg = ProxyConfig(http_proxy=proxy_url, https_proxy=proxy_url) if proxy_url else None
    knowledge_store = KnowledgeStore()
    registry = CapabilityRegistry()

    agent_instances = RegistryLoader.instantiate_all_agents()
    for agent in agent_instances:
        if enabled_agents and agent.name.lower() not in [a.lower() for a in enabled_agents]:
            continue
        registry.register_provider(agent)

    exec_ctx = ExecutionContext(target=target_domain)
    crawler = SmartCrawler()
    obs = await crawler.crawl(target_domain)
    exec_ctx.add_observation(obs)

    cap_ctx = CapabilityExecutionContext(
        asset=target_domain,
        knowledge_store=knowledge_store,
        proxy_config=proxy_cfg,
        observations=exec_ctx.observations
    )

    cap_resolver = CapabilityResolver(registry)
    all_caps = registry.list_all_capabilities()

    raw_results = []
    for cap in all_caps:
        providers = cap_resolver.resolve(cap.id)
        for provider in providers:
            try:
                res = await provider.execute(cap.id, cap_ctx)
                norm_res = normalize_agent_result(res)
                raw_results.append(norm_res)
            except Exception as e:
                logger.error(f"[WebAPI] Error executing agent '{provider.name}': {e}")

    critic = CriticVerificationEngine()
    quality_gate = PreReportQualityGate(min_confidence=0.85, scope_domains=[target_domain])

    verified_findings = []
    for res in raw_results:
        if res.get("is_vulnerable"):
            bundle = EvidenceCAS().store_evidence(target=target_domain, vuln_type=res.get("vulnerability_type", "audit"), raw_traces=res)
            crit_res = critic.verify_finding(bundle)
            if crit_res["is_verified"]:
                verified_findings.append(crit_res)

    admitted_findings = await quality_gate.filter_findings(verified_findings)
    reporter = MarkdownReportGenerator()
    return reporter.generate_markdown_report(target_domain, admitted_findings)


@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open(os.path.join(STATIC_DIR, "index.html"), "r", encoding="utf-8") as f:
        return f.read()

@app.get("/api/agents")
async def list_agents():
    classes = RegistryLoader.discover_and_register_all()
    return {"agents": [cls.__name__ for cls in classes]}

@app.post("/api/scan")
async def trigger_scan(request: ScanRequest):
    # For a simple UX, we await the scan synchronously so the UI can wait and show the report.
    # In a full-scale app, this should be a background task returning a job ID.
    report_md = await execute_scan(
        target_domain=request.target,
        proxy_url=request.proxy,
        enabled_agents=request.enabled_agents
    )
    return {"status": "success", "report": report_md}

def start_server(port: int = 8000):
    import uvicorn
    logger.info(f"Starting PenFlow Web UI on http://localhost:{port}")
    uvicorn.run("penflow.app.web:app", host="127.0.0.1", port=port, log_level="info")
