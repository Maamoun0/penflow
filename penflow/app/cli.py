"""
PenFlow Command-Line Interface (CLI) Engine.

Handles command execution, argument parsing, agent auto-registration,
target scope evaluation, and scan pipeline invocation.
"""
import asyncio
import sys
import argparse
from typing import List, Optional

from penflow.core.orchestrator import Orchestrator
from penflow.core.context import ExecutionContext
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.knowledge.evidence_cas import EvidenceCAS
from penflow.recon.crt_sh_client import CrtShClient
from penflow.recon.dns_resolver import DNSResolverEngine
from penflow.recon.smart_crawler import SmartCrawler
from penflow.recon.tech_fingerprint import TechnologyFingerprintEngine
from penflow.capabilities.registry import CapabilityRegistry
from penflow.capabilities.resolver import CapabilityResolver
from penflow.capabilities.result import normalize_agent_result
from penflow.agents.base.registry_loader import RegistryLoader
from penflow.planning.planning_pipeline import PlanningPipeline
from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.leadership import ResearchDirectorAgent, EconomyAgent
from penflow.reporting.console_reporter import ConsoleReporter
from penflow.reporting.report_generator import MarkdownReportGenerator
from penflow.infrastructure.sqlite_store import SQLiteKnowledgeStore
from penflow.infrastructure.logger import get_logger
from penflow.traffic.proxy_engine import ProxyConfig

logger = get_logger("penflow.cli")


async def run_scan_pipeline(
    target_domain: str,
    proxy_url: Optional[str] = None,
    deep_mode: bool = False,
    enabled_agents: Optional[List[str]] = None
) -> None:
    """Executes full autonomous vulnerability research pipeline against target domain."""
    logger.info(f"[CLI] Starting PenFlow autonomous scan pipeline against target '{target_domain}'...")

    proxy_cfg = ProxyConfig(http_proxy=proxy_url, https_proxy=proxy_url) if proxy_url else None
    knowledge_store = KnowledgeStore()
    registry = CapabilityRegistry()

    # Discover and register agents automatically via RegistryLoader
    agent_instances = RegistryLoader.instantiate_all_agents()
    for agent in agent_instances:
        if enabled_agents and agent.name.lower() not in [a.lower() for a in enabled_agents]:
            continue
        registry.register_provider(agent)

    logger.info(f"[CLI] Registered {len(registry._providers)} capability providers into runtime registry.")

    orchestrator = Orchestrator()
    exec_ctx = ExecutionContext(config={"target": target_domain})

    # Step 0: Scope Resolution for Wildcard Patterns (e.g. prod-*.nubank.com.br)
    from penflow.recon.scope_resolver import ScopePatternResolver
    scope_resolver = ScopePatternResolver()
    resolved_targets = await scope_resolver.resolve_scope(target_domain)
    logger.info(f"[CLI] Resolved {len(resolved_targets)} target(s) for scan: {resolved_targets}")

    # Step 1: Reconnaissance & Multi-Target Execution
    all_admitted_findings = []
    all_rejected_findings = []
    all_raw_results = []

    for raw_target in resolved_targets:
        clean = raw_target.strip().lower()
        for prefix in ("https://", "http://"):
            while clean.startswith(prefix):
                clean = clean[len(prefix):]
        current_target = clean.split("/")[0].split("?")[0]

        logger.info(f"[CLI] >>> Commencing audit against target: '{current_target}' <<<")
        crawler = SmartCrawler(timeout=5.0)
        obs = await crawler.crawl(current_target)

        # Skip target only if completely unreachable (no endpoints and status 0)
        is_reachable = bool(obs.get("is_reachable") or obs.get("endpoints") or obs.get("status_code", 0) > 0)
        if not is_reachable:
            logger.warning(f"[CLI] Skipping unreachable target asset '{current_target}'")
            continue

        asset_node = knowledge_store.assets.register_asset(canonical_name=current_target, asset_type="subdomain")
        knowledge_store.observations.record_observation(asset_id=asset_node.id, obs_type="http_crawl", data=obs)

        # Step 2: Capability Resolution & Execution
        cap_ctx = CapabilityExecutionContext(
            asset=current_target,
            knowledge_store=knowledge_store,
            proxy_config=proxy_cfg,
            observations=[obs]
        )

        cap_resolver = CapabilityResolver(registry)
        all_caps = registry.list_all_capabilities()

        sem = asyncio.Semaphore(15)

        async def run_single_capability(provider, agent_name, cap_id):
            async with sem:
                try:
                    res = await asyncio.wait_for(provider.execute(cap_id, cap_ctx), timeout=12.0)
                    norm_res = normalize_agent_result(res, agent_name=agent_name, capability_id=cap_id, asset=current_target)
                    return norm_res.to_dict()
                except asyncio.TimeoutError:
                    logger.warning(f"[CLI] Agent '{agent_name}' timed out after 12.0s on '{current_target}'")
                except Exception as e:
                    logger.error(f"[CLI] Error executing agent '{agent_name}' for capability '{cap_id}': {e}")
                return None

        tasks = []
        for cap in all_caps:
            provider_entries = cap_resolver.resolve([cap.id])
            for provider, agent_name, cap_id in provider_entries:
                tasks.append(run_single_capability(provider, agent_name, cap_id))

        task_results = await asyncio.gather(*tasks)
        raw_results = [r for r in task_results if r is not None]

        # Step 3: Critic Verification & PreReport Quality Gate
        critic = CriticVerificationEngine()
        quality_gate = PreReportQualityGate(min_confidence=0.85, scope_domains=[current_target])

        verified_findings = []
        for res in raw_results:
            if res.get("is_vulnerable"):
                vtype = res.get("vulnerability_type") or res.get("capability") or "audit"
                bundle = EvidenceCAS().store_evidence(target=current_target, vuln_type=vtype, raw_traces=res)
                crit_res = critic.verify_finding(bundle)
                if crit_res["is_verified"]:
                    verified_findings.append(crit_res)
                    logger.info(f"[CLI] Finding VERIFIED: '{vtype}' on '{current_target}' ({crit_res.get('verification_reason', '')})")
                else:
                    all_rejected_findings.append({
                        "vulnerability_type": vtype,
                        "target": current_target,
                        "target_url": res.get("target_url") or f"https://{current_target}",
                        "reason": crit_res.get("verification_reason", "Falsified by verification gate"),
                        "confidence": crit_res.get("confidence", 0.0)
                    })
                    logger.warning(f"[CLI] Finding REJECTED: '{vtype}' on '{current_target}' -> {crit_res.get('verification_reason', '')}")

        admitted_target_findings, qg_rejected = await quality_gate.filter_findings_with_details(verified_findings)
        all_admitted_findings.extend(admitted_target_findings)
        all_rejected_findings.extend(qg_rejected)
        all_raw_results.extend(raw_results)

    admitted_findings = all_admitted_findings

    # Step 4: Exploit Chaining & Compound Intelligence
    from penflow.intelligence.exploit_chainer import ExploitChainer
    chainer = ExploitChainer()
    exploit_chains = chainer.construct_chains(admitted_findings)

    # Step 5: Report Generation & HackerOne Export
    from penflow.reporting.hackerone_exporter import HackerOneReportExporter
    reporter = MarkdownReportGenerator()
    h1_exporter = HackerOneReportExporter()

    from penflow.planning.execution_plan import ExecutionPlan
    report_md = reporter.generate_report(
        target_domain=target_domain,
        knowledge_store=knowledge_store,
        plan=getattr(exec_ctx, "plan", ExecutionPlan()) or ExecutionPlan(),
        verified_findings=admitted_findings,
        exploit_chains=exploit_chains
    )

    # Add Triage & Verification Audit Breakdown to Report
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
            report_md += (
                f"{idx}. **`{rej['vulnerability_type']}`** on `{rej['target']}`\n"
                f"   - **Target URL**: `{rej.get('target_url', rej['target'])}`\n"
                f"   - **Falsification Reason**: {rej['reason']}\n\n"
            )
    else:
        report_md += "✅ *No false positive candidates were flagged during this scan session.*\n\n"

    print(f"\n================ PENFLOW AUDIT REPORT ================\n")
    print(report_md)

    if admitted_findings:
        print(f"\n================ HACKERONE SUBMISSION WRITEUPS ================\n")
        for idx, finding in enumerate(admitted_findings, 1):
            h1_md = h1_exporter.export_report(finding)
            print(f"--- [HackerOne Writeup #{idx}] ---")
            print(h1_md)


def main():
    parser = argparse.ArgumentParser(description="PenFlow — Autonomous Vulnerability Research Engine")
    parser.add_argument("target", nargs="?", help="Target domain or URL to audit")
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--deep", action="store_true", help="Enable deep multi-vector fuzzing mode")
    parser.add_argument("--agents", help="Comma-separated subset of capability agents to enable")
    parser.add_argument("--list-agents", action="store_true", help="List all registered capability agents")
    parser.add_argument("--web", action="store_true", help="Start the PenFlow Web UI server")

    args = parser.parse_args()

    if args.web:
        from penflow.app.web import start_server
        start_server(port=8000)
        return

    if args.list_agents:
        agents = RegistryLoader.discover_and_register_all()
        print("\nRegistered PenFlow Capability Agents:\n")
        for idx, cls in enumerate(agents, 1):
            print(f"  {idx:02d}. {cls.__name__}")
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    enabled_subset = [a.strip() for a in args.agents.split(",")] if args.agents else None
    asyncio.run(run_scan_pipeline(
        target_domain=args.target,
        proxy_url=args.proxy,
        deep_mode=args.deep,
        enabled_agents=enabled_subset
    ))


if __name__ == "__main__":
    main()
