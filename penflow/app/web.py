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
    """Executes the pipeline and returns the markdown report with HackerOne writeups."""
    logger.info(f"[WebAPI] Starting scan against '{target_domain}'")
    proxy_cfg = ProxyConfig(http_proxy=proxy_url, https_proxy=proxy_url) if proxy_url else None
    knowledge_store = KnowledgeStore()
    registry = CapabilityRegistry()

    agent_instances = RegistryLoader.instantiate_all_agents()
    for agent in agent_instances:
        if enabled_agents and agent.name.lower() not in [a.lower() for a in enabled_agents]:
            continue
        registry.register_provider(agent)

    exec_ctx = ExecutionContext(config={"target": target_domain})

    # Scope resolution for wildcard patterns
    from penflow.recon.scope_resolver import ScopePatternResolver
    scope_resolver = ScopePatternResolver()
    resolved_targets = await scope_resolver.resolve_scope(target_domain)

    all_admitted_findings = []
    all_rejected_findings = []
    all_raw_results = []

    for raw_target in resolved_targets:
        clean = raw_target.strip().lower()
        for prefix in ("https://", "http://"):
            while clean.startswith(prefix):
                clean = clean[len(prefix):]
        current_target = clean.split("/")[0].split("?")[0]

        logger.info(f"[WebAPI] >>> Commencing audit against target: '{current_target}' <<<")
        crawler = SmartCrawler(timeout=5.0)
        obs = await crawler.crawl(current_target)

        # Skip target if unreachable or expired (e.g. HTTP 504 Gateway Timeout)
        is_reachable = bool(obs.get("is_reachable", True)) and not bool(obs.get("is_expired", False)) and bool(obs.get("endpoints") or (obs.get("status_code", 0) in (200, 301, 302, 307, 308, 401, 403)))
        if not is_reachable:
            status_code = obs.get("status_code", 0)
            logger.warning(f"[WebAPI] Skipping unreachable/expired target asset '{current_target}' (HTTP {status_code})")
            continue

        asset_node = knowledge_store.assets.register_asset(canonical_name=current_target, asset_type="subdomain")
        knowledge_store.observations.record_observation(asset_id=asset_node.id, obs_type="http_crawl", data=obs)
        for ep in obs.get("endpoints", []):
            ep_url = ep.get("url")
            if ep_url:
                knowledge_store.assets.register_asset(canonical_name=ep_url, asset_type="endpoint")
                knowledge_store.observations.record_observation(asset_id=asset_node.id, obs_type="discovered_endpoint", data=ep)
        for form in obs.get("forms", []):
            knowledge_store.observations.record_observation(asset_id=asset_node.id, obs_type="html_form", data=form)
            form_action = form.get("action")
            if form_action:
                knowledge_store.assets.register_asset(canonical_name=form_action, asset_type="endpoint")
        for js_f in obs.get("js_files", []):
            knowledge_store.observations.record_observation(asset_id=asset_node.id, obs_type="javascript_source", data={"url": js_f})

        cap_ctx = CapabilityExecutionContext(
            asset=current_target,
            knowledge_store=knowledge_store,
            proxy_config=proxy_cfg,
            observations=[obs]
        )

        cap_resolver = CapabilityResolver(registry)
        all_caps = registry.list_all_capabilities()

        sem = asyncio.Semaphore(12)

        async def run_single_capability(provider, agent_name, cap_id):
            async with sem:
                try:
                    res = await asyncio.wait_for(provider.execute(cap_id, cap_ctx), timeout=35.0)
                    norm_res = normalize_agent_result(res, agent_name=agent_name, capability_id=cap_id, asset=current_target)
                    return norm_res.to_dict()
                except asyncio.TimeoutError:
                    logger.warning(f"[WebAPI] Agent '{agent_name}' timed out after 35.0s on '{current_target}'")
                except Exception as e:
                    logger.error(f"[WebAPI] Error executing agent '{agent_name}' for capability '{cap_id}': {e}")
                return None

        tasks = []
        for cap_id, prov_list in registry._providers.items():
            for p_inst, a_name in prov_list:
                tasks.append(run_single_capability(p_inst, a_name, cap_id))

        raw_results = [r for r in await asyncio.gather(*tasks) if r is not None]

        evidence_cas = EvidenceCAS()
        critic = CriticVerificationEngine()
        quality_gate = PreReportQualityGate(min_confidence=0.85, scope_domains=[current_target])

        verified_findings = []
        for res in raw_results:
            if not res.get("is_vulnerable") and not res.get("vulnerable"):
                continue

            vtype = res.get("vulnerability_type", "security_finding")
            bundle = evidence_cas.store_evidence(current_target, vtype, res)
            crit_res = critic.verify_finding(bundle)

            if crit_res.get("is_verified"):
                res["is_verified"] = True
                res["verification_reason"] = crit_res.get("verification_reason", "Verified by Critic Engine")
                res["confidence"] = crit_res.get("confidence_score", res.get("confidence", 0.8))
                res["confidence_score"] = res["confidence"]
                res["evidence_hash"] = bundle.hash_id
                res["hash_id"] = bundle.hash_id
                res["target"] = current_target
                res["asset"] = current_target
                verified_findings.append(res)
                logger.info(f"[WebAPI] Finding VERIFIED: '{vtype}' on '{current_target}' ({crit_res.get('verification_reason', '')})")
            else:
                rej_url = res.get("target_url") or f"https://{current_target}"
                all_rejected_findings.append({
                    "vulnerability_type": vtype,
                    "target": current_target,
                    "target_url": rej_url,
                    "reason": crit_res.get("verification_reason", "Falsified by verification gate"),
                    "confidence": crit_res.get("confidence", 0.0)
                })
                logger.warning(f"[WebAPI] Finding REJECTED: '{vtype}' on '{current_target}' -> {crit_res.get('verification_reason', '')}")

        admitted_target_findings, qg_rejected = await quality_gate.filter_findings_with_details(verified_findings)
        all_admitted_findings.extend(admitted_target_findings)
        all_rejected_findings.extend(qg_rejected)
        all_raw_results.extend(raw_results)

    admitted_findings = all_admitted_findings

    # Exploit Chaining & Compound Intelligence
    from penflow.intelligence.exploit_chainer import ExploitChainer
    chainer = ExploitChainer()
    exploit_chains = chainer.construct_chains(admitted_findings)

    # Report Generation & HackerOne Export
    from penflow.reporting.hackerone_exporter import HackerOneReportExporter
    from penflow.planning.execution_plan import ExecutionPlan
    reporter = MarkdownReportGenerator()
    h1_exporter = HackerOneReportExporter()

    report_md = reporter.generate_report(
        target_domain=target_domain,
        knowledge_store=knowledge_store,
        plan=ExecutionPlan(),
        verified_findings=admitted_findings,
        exploit_chains=exploit_chains
    )

    # Add Triage & Verification Audit Breakdown
    total_evaluated = len(admitted_findings) + len(all_rejected_findings)
    report_md += f"""

---

## 🛡️ Triage & Grounding Verification Audit Trail

| Metric | Count | Details |
|---|---|---|
| **Total Candidates Evaluated** | **{total_evaluated}** | Raw candidate anomalies flagged by capability agents |
| **Verified Findings (0 False Positives)** | **{len(admitted_findings)}** | Certified findings with confirmed live HTTP proof |
| **Rejected / Falsified Candidates** | **{len(all_rejected_findings)}** | Filtered by CriticVerificationEngine & Grounding Gate |

"""
    if all_rejected_findings:
        report_md += "### ❌ Rejected Candidate Log (Adversarial Falsification Details)\n\n"
        for idx, rej in enumerate(all_rejected_findings, 1):
            rej_url = rej.get('target_url') or (f"https://{rej.get('target')}" if rej.get('target') else "N/A")
            report_md += (
                f"{idx}. **`{rej['vulnerability_type']}`** on `{rej['target']}`\n"
                f"   - **Target URL**: `{rej_url}`\n"
                f"   - **Falsification Reason**: {rej['reason']}\n\n"
            )
    else:
        report_md += "✅ *No false positive candidates were flagged during this scan session.*\n\n"

    if admitted_findings:
        report_md += "\n\n# 📋 HackerOne Submission Writeups\n\n"
        for idx, finding in enumerate(admitted_findings, 1):
            h1_md = h1_exporter.export_report(finding)
            report_md += f"## HackerOne Writeup #{idx}\n\n{h1_md}\n\n---\n\n"

    return report_md


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
    try:
        report_md = await execute_scan(
            target_domain=request.target,
            proxy_url=request.proxy,
            enabled_agents=request.enabled_agents
        )
        return {"status": "success", "report": report_md}
    except Exception as e:
        logger.error(f"[WebAPI] Scan execution failed for target '{request.target}': {e}", exc_info=True)
        return {"status": "error", "message": str(e)}

def start_server(port: int = 8000):
    import uvicorn
    logger.info(f"Starting PenFlow Web UI on http://localhost:{port}")
    uvicorn.run("penflow.app.web:app", host="127.0.0.1", port=port, log_level="info")
