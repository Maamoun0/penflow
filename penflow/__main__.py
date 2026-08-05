import asyncio
import sys
from typing import Optional
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
from penflow.agents import (
    GraphQLCapabilityAgent,
    IDORCapabilityAgent,
    BFLACapabilityAgent,
    MassAssignmentCapabilityAgent,
    RaceConditionCapabilityAgent,
    OAuthJWTCapabilityAgent,
    CORSCapabilityAgent,
    SSRFCapabilityAgent,
    NoSQLSQLiCapabilityAgent,
    SSTIRCECapabilityAgent,
    InfoDisclosureCapabilityAgent,
    RateLimitCapabilityAgent,
    OpenRedirectCapabilityAgent,
    SecurityConfigCapabilityAgent,
    XSSCapabilityAgent,
    HTTPSmugglingCapabilityAgent,
    SubdomainTakeoverCapabilityAgent,
    ParameterDiscoveryCapabilityAgent,
)
from penflow.planning.planning_pipeline import PlanningPipeline
from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.leadership import ResearchDirectorAgent, EconomyAgent
from penflow.reporting.console_reporter import ConsoleReporter
from penflow.reporting.report_generator import MarkdownReportGenerator
from penflow.infrastructure.sqlite_store import SQLiteKnowledgeStore
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.cli")

from penflow.traffic.proxy_engine import ProxyConfig

async def run_scan(target_domain: str, proxy_url: Optional[str] = None, deep_mode: bool = False) -> None:
    mode_str = "DEEP AUTONOMOUS RESEARCH MODE" if deep_mode else "STANDARD FAST RECON MODE"
    print(f"\n[+] Starting PenFlow Production Security Research Swarm Scan: {target_domain} [{mode_str}]")
    if proxy_url:
        print(f"[*] Interception Proxy Enabled: {proxy_url}")
    
    proxy_cfg = ProxyConfig(http_proxy=proxy_url) if proxy_url else None
    
    # 1. System Initialization
    sqlite_db = SQLiteKnowledgeStore()
    knowledge_store = KnowledgeStore()
    evidence_cas = EvidenceCAS()
    critic_engine = CriticVerificationEngine()
    orchestrator = Orchestrator(max_workers=8 if deep_mode else 4)
    
    await orchestrator.start()
    dns_engine = DNSResolverEngine()
    crawler = SmartCrawler(max_depth=4 if deep_mode else 1, max_pages=100 if deep_mode else 5)
    tech_engine = TechnologyFingerprintEngine()
    from penflow.recon.route_fuzzer import SmartRouteFuzzer
    from penflow.recon.security_headers_audit import SecurityHeadersAuditor
    route_fuzzer = SmartRouteFuzzer(max_concurrency=25 if deep_mode else 10)
    headers_auditor = SecurityHeadersAuditor()

    # 2. Register Capability Agents in Registry
    capability_registry = CapabilityRegistry()
    specialist_agents = [
        GraphQLCapabilityAgent(priority=10),
        IDORCapabilityAgent(priority=10),
        BFLACapabilityAgent(priority=10),
        MassAssignmentCapabilityAgent(priority=10),
        RaceConditionCapabilityAgent(priority=10),
        OAuthJWTCapabilityAgent(priority=10),
        CORSCapabilityAgent(priority=10),
        SSRFCapabilityAgent(priority=10),
        NoSQLSQLiCapabilityAgent(priority=10),
        SSTIRCECapabilityAgent(priority=10),
        InfoDisclosureCapabilityAgent(priority=10),
        RateLimitCapabilityAgent(priority=10),
        OpenRedirectCapabilityAgent(priority=10),
        SecurityConfigCapabilityAgent(priority=10),
        XSSCapabilityAgent(priority=10),
        HTTPSmugglingCapabilityAgent(priority=10),
        SubdomainTakeoverCapabilityAgent(priority=10),
        ParameterDiscoveryCapabilityAgent(priority=10),
    ]

    for agent in specialist_agents:
        for cap in agent.get_capabilities():
            capability_registry.register_capability(cap, agent, agent.name)

    capability_resolver = CapabilityResolver(capability_registry)

    # 3. Define Async Recon Task Handler
    async def handle_recon_task(ctx: ExecutionContext) -> None:
        payload = ctx.logger.extra.get("payload", {}) if hasattr(ctx.logger, "extra") else {}
        target_sub = payload.get("subdomain", target_domain)

        knowledge_store.assets.register_asset(canonical_name=target_sub, asset_type="subdomain")
        sqlite_db.save_asset(asset_id=target_sub, target_domain=target_domain, asset_value=target_sub, asset_type="subdomain")
        
        # Real DNS Resolution
        dns_res = await dns_engine.resolve_domain(target_sub)
        obs_rec = knowledge_store.observations.record_observation(
            asset_id=target_sub,
            obs_type="dns_record",
            data=dns_res
        )
        sqlite_db.save_observation(obs_id=obs_rec.id, asset_id=target_sub, obs_type="dns_record", data=dns_res)
        
        # Smart Crawling, Route Fuzzing, File Fuzzing & Tech Fingerprinting
        crawl_res = await crawler.crawl(f"https://{target_sub}")
        fuzz_res = await route_fuzzer.fuzz(f"https://{target_sub}")
        tech_res = await tech_engine.fingerprint(f"https://{target_sub}")
        audit_res = await headers_auditor.audit_url(f"https://{target_sub}")

        from penflow.recon.file_content_fuzzer import FileContentFuzzer
        file_fuzzer = FileContentFuzzer(concurrency=15 if deep_mode else 10)
        file_fuzz_res = await file_fuzzer.fuzz_files(f"https://{target_sub}", deep_mode=deep_mode)

        from penflow.recon.openapi_parser import OpenAPIParser
        openapi_parser = OpenAPIParser()
        openapi_eps = await openapi_parser.discover_and_parse(f"https://{target_sub}")

        knowledge_store.observations.record_observation(asset_id=target_sub, obs_type="crawl_results", data=crawl_res)
        knowledge_store.observations.record_observation(asset_id=target_sub, obs_type="route_fuzz_results", data={"endpoints": fuzz_res})
        knowledge_store.observations.record_observation(asset_id=target_sub, obs_type="file_fuzz_results", data={"files": file_fuzz_res})
        knowledge_store.observations.record_observation(asset_id=target_sub, obs_type="tech_fingerprint", data=tech_res)
        knowledge_store.observations.record_observation(asset_id=target_sub, obs_type="security_headers", data=audit_res)

        # Dynamically register all discovered endpoints from crawl results, file fuzzing, and OpenAPI specs
        from penflow.recon.endpoint_classifier import EndpointClassifier
        classifier = EndpointClassifier()
        classified_eps = classifier.classify_from_crawl(crawl_res) + openapi_eps
        for cep in classified_eps:
            ep_obs = knowledge_store.observations.record_observation(
                asset_id=target_sub,
                obs_type="endpoint_discovered",
                data=cep.to_dict()
            )
            sqlite_db.save_observation(
                obs_id=ep_obs.id, asset_id=target_sub,
                obs_type="endpoint_discovered", data=cep.to_dict()
            )

    orchestrator.register_task_handler("recon_task", handle_recon_task)

    # 4. Multi-level Subdomain & Sub-subdomain Discovery (CRT.sh + Brute-force)
    crt_client = CrtShClient()
    print(f"[*] Fetching Certificate Transparency logs from crt.sh for '{target_domain}'...")
    crt_subdomains = await crt_client.fetch_subdomains(target_domain)

    from penflow.recon.subdomain_bruteforce import SubdomainBruteforceEngine
    brute_engine = SubdomainBruteforceEngine(concurrency=25 if deep_mode else 15)
    print(f"[*] Running multi-level Subdomain & Sub-subdomain Brute-force Engine for '{target_domain}'...")
    brute_results = await brute_engine.enumerate_subdomains(target_domain, deep_mode=deep_mode)
    brute_subdomains = [r["domain"] for r in brute_results if r.get("is_resolved")]

    all_discovered_subdomains = sorted(list(set(crt_subdomains + brute_subdomains)))

    if not all_discovered_subdomains:
        all_discovered_subdomains = [target_domain]

    subdomain_cap = 20 if deep_mode else 10
    subdomains_to_scan = all_discovered_subdomains[:subdomain_cap]
    print(f"[*] Total Discovered Subdomains & Sub-subdomains: {len(all_discovered_subdomains)}. Scheduling top {len(subdomains_to_scan)} across Orchestrator WorkerPool...")

    tasks = []
    for sub in subdomains_to_scan:
        t = orchestrator.create_task(task_type="recon_task", payload={"subdomain": sub}, priority=5, timeout=30.0 if deep_mode else 15.0)
        tasks.append(t)
        await orchestrator.submit_task(t)

    # Wait for completion
    while True:
        completed = sum(1 for t in tasks if t.status.value in ["COMPLETED", "FAILED", "CANCELLED"])
        if completed == len(tasks):
            break
        await asyncio.sleep(0.05)

    # 5. Planning & Reasoning Engine Cycle governed by ResearchDirectorAgent
    print("[*] Triggering ResearchDirectorAgent Strategic Planning & Economy Control...")
    economy_agent = EconomyAgent()
    director_agent = ResearchDirectorAgent(knowledge_store, economy_agent=economy_agent)
    execution_plan = director_agent.evaluate_target_strategy(target_domain)

    # 6. Resolve Capabilities and Execute Agents
    verified_findings = []
    print("[*] Resolving required capabilities against Capability Agents...")

    # Collect all observations for the target to pass to agents
    all_observations = []
    for obs_record in knowledge_store.observations.get_all():
        all_observations.append({
            "id": obs_record.id,
            "asset_id": obs_record.asset_id,
            "type": obs_record.observation_type,
            "data": obs_record.data,
            "timestamp": obs_record.timestamp
        })

    if execution_plan.required_capabilities:
        resolved = capability_resolver.resolve(execution_plan.required_capabilities)

        # Build endpoint-agent mapping from EndpointClassifier for targeted injection
        from penflow.recon.endpoint_classifier import EndpointClassifier
        ep_classifier = EndpointClassifier()
        all_crawl_data = {"endpoints": [], "forms": []}
        all_tech_hints: list = []
        for obs in all_observations:
            if obs.get("type") == "crawl_results" and isinstance(obs.get("data"), dict):
                all_crawl_data["endpoints"].extend(obs["data"].get("endpoints", []))
                all_crawl_data["forms"].extend(obs["data"].get("forms", []))
            if obs.get("type") == "tech_fingerprint" and isinstance(obs.get("data"), dict):
                all_tech_hints.extend(ep_classifier.classify_from_tech(obs["data"]))

        classified_eps = ep_classifier.classify_from_crawl(all_crawl_data)
        agent_mapping = ep_classifier.get_agent_mapping(classified_eps, all_tech_hints)

        print(f"[*] Endpoint-Agent mapping: {len(classified_eps)} endpoints → {len(agent_mapping)} capability targets")

        async def run_single_agent(agent_inst, agent_name, cap_id, idx, total):
            relevant_obs = [o for o in all_observations if o.get("type") in
                           ("endpoint_discovered", "crawl_results", "tech_fingerprint",
                            "route_fuzz_results", "security_headers")]
            cap_ctx = CapabilityExecutionContext(
                asset=target_domain,
                knowledge_store=knowledge_store,
                proxy_config=proxy_cfg,
                observations=relevant_obs,
                shared_cache={
                    "deep_mode": deep_mode,
                    "endpoint_mapping": agent_mapping.get(cap_id, []),
                    "classified_endpoints": [ep.to_dict() for ep in classified_eps],
                }
            )
            print(f"[{idx}/{total}] Running agent: {agent_name} → {cap_id}")
            agent_res = await agent_inst.execute(cap_id, cap_ctx)
            bundle = evidence_cas.store_evidence(
                target=target_domain,
                vuln_type=cap_id,
                raw_traces=agent_res.get("evidence", {})
            )
            crit_res = await critic_engine.verify_finding_async(bundle, cap_ctx)
            knowledge_store.experience.record_scan_result(cap_id, crit_res["is_verified"])
            return crit_res

        # Execute all agents in parallel via asyncio.gather
        total_agents = len(resolved)
        agent_coroutines = [
            run_single_agent(agent_inst, agent_name, cap_id, idx + 1, total_agents)
            for idx, (agent_inst, agent_name, cap_id) in enumerate(resolved)
        ]
        all_results = await asyncio.gather(*agent_coroutines, return_exceptions=True)
        for res in all_results:
            if isinstance(res, dict) and res.get("is_verified"):
                verified_findings.append(res)

    # 7. Render Swarm Dashboard, Console Plan & Generate Markdown Report File
    from penflow.reporting.dashboard import SwarmDashboard
    dashboard = SwarmDashboard()
    dashboard.render_live_summary(target_domain, knowledge_store, execution_plan, economy_agent=economy_agent, verified_findings=verified_findings)
    
    report_gen = MarkdownReportGenerator()
    report_md = report_gen.generate_report(target_domain, knowledge_store, execution_plan, verified_findings=verified_findings)
    report_file = report_gen.save_report(target_domain, report_md)

    from penflow.reporting.sarif_exporter import SARIFExporter
    sarif_exp = SARIFExporter()
    sarif_data = sarif_exp.export_sarif(target_domain, verified_findings)
    sarif_file = sarif_exp.save_sarif_file(target_domain, sarif_data)
    print(f"[+] SARIF v2.1.0 Report generated and saved to: {sarif_file}")
    print(f"[+] Markdown Report successfully generated and saved to: {report_file}\n")

    await orchestrator.stop()

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m penflow scan <target_domain> [--proxy <proxy_url>] [--deep]")
        print("  python -m penflow learn [writeups_directory_path]")
        print("  python -m penflow train [writeups_directory_path]")
        print("  python -m penflow daemon [--interval <seconds>]")
        print("  python -m penflow ui [--port 8000]")
        print("  python -m penflow poc <target_domain>")
        print("  python -m penflow sast <directory_path>")
        print("  python -m penflow sarif <target_domain>")
        print("  python -m penflow benchmark")
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == "sast":
        target_dir = sys.argv[2] if len(sys.argv) > 2 else "."
        from penflow.analysis.ast_scanner import SourceCodeAnalyzer
        analyzer = SourceCodeAnalyzer()
        print(f"\n[+] Running PenFlow Hybrid SAST Code Analysis on '{target_dir}' ...")
        res = analyzer.scan_directory(target_dir)
        print(f"    - Files Scanned: {res['files_scanned']}")
        print(f"    - Total Findings: {res['total_findings']}")
        print(f"    - Critical: {res['critical_count']} | High: {res['high_count']} | Medium: {res['medium_count']}\n")
        for f in res['findings'][:10]:
            print(f"    [{f['severity']}] {f['vulnerability_type']} @ {f['file']}:{f['line']} -> {f['description']}")
        print()
    elif cmd == "ui":
        port = 8000
        if "--port" in sys.argv:
            idx = sys.argv.index("--port")
            if idx + 1 < len(sys.argv):
                port = int(sys.argv[idx + 1])
        import uvicorn
        print(f"\n[+] Starting PenFlow Enterprise Web UI Dashboard on http://localhost:{port} ...\n")
        uvicorn.run("penflow.webui.server:app", host="0.0.0.0", port=port, reload=False)
    elif cmd == "poc":
        target = sys.argv[2] if len(sys.argv) > 2 else "example.com"
        from penflow.reporting.bugbounty_exporter import BugBountyPoCExporter
        exporter = BugBountyPoCExporter()
        poc = exporter.generate_hackerone_report({"vulnerability_type": "id_access_analysis", "target_url": f"https://{target}/api/v1/user?id=100"}, target)
        print(f"\n{poc}\n")
    elif cmd == "benchmark":
        from penflow.benchmarks.testbed_runner import TestbedBenchmarkRunner
        runner = TestbedBenchmarkRunner()
        mock_gt = [{"endpoint": "/api/v1/user", "vuln_type": "idor", "is_vulnerable": True}]
        mock_findings = [{"target_url": "/api/v1/user", "vulnerability_type": "idor", "is_vulnerable": True}]
        res = runner.evaluate_findings("OWASP Juice Shop Testbed", mock_findings, mock_gt)
        print(f"\n[+] OWASP Benchmark Evaluation Completed!")
        print(f"    - F1-Score: {res['f1_score']}")
        print(f"    - Precision: {res['precision']}")
        print(f"    - Recall: {res['recall']}")
        print(f"    - False Positive Rate: {res['false_positive_rate']}\n")
    elif cmd == "sarif":
        target = sys.argv[2] if len(sys.argv) > 2 else "example.com"
        from penflow.reporting.sarif_exporter import SARIFExporter
        sarif_exp = SARIFExporter()
        sarif_data = sarif_exp.export_sarif(target, [])
        sarif_file = sarif_exp.save_sarif_file(target, sarif_data)
        print(f"[+] SARIF File generated: {sarif_file}")
    elif cmd == "daemon":
        interval = 10.0
        if "--interval" in sys.argv:
            idx = sys.argv.index("--interval")
            if idx + 1 < len(sys.argv):
                interval = float(sys.argv[idx + 1])
        from penflow.intelligence.continuous_learner import ContinuousLearnerDaemon
        daemon = ContinuousLearnerDaemon(interval_seconds=interval)
        try:
            asyncio.run(daemon.start_daemon_loop())
        except KeyboardInterrupt:
            print("\n[-] Continuous Learning Daemon stopped by user.")
    elif cmd in ("learn", "train"):
        dir_path = sys.argv[2] if len(sys.argv) > 2 else "data/writeups"
        from penflow.intelligence.writeup_loader import WriteupIngestionEngine
        engine = WriteupIngestionEngine()
        res = engine.ingest_directory(dir_path)
        print(f"\n[+] PenFlow Continuous Learning Completed!")
        print(f"    - Ingested Writeups: {res['ingested_count']}")
        print(f"    - Generated Tactical Rules: {res['rules_generated']}")
        print(f"    - Saved Rules Manifest: {res.get('rules_file')}\n")
    elif cmd == "scan":
        target = sys.argv[2] if len(sys.argv) > 2 else "example.com"
        proxy = None
        deep = "--deep" in sys.argv
        if "--proxy" in sys.argv:
            idx = sys.argv.index("--proxy")
            if idx + 1 < len(sys.argv):
                proxy = sys.argv[idx + 1]
        asyncio.run(run_scan(target, proxy_url=proxy, deep_mode=deep))
    else:
        target = cmd
        deep = "--deep" in sys.argv
        asyncio.run(run_scan(target, deep_mode=deep))

if __name__ == "__main__":
    main()
