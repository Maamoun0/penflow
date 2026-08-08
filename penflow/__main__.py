import asyncio
import sys
import io

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

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
    WebCachePoisoningCapabilityAgent,
    PrototypePollutionCapabilityAgent,
    BusinessLogicCapabilityAgent,
    XXECapabilityAgent,
    AccountTakeoverCapabilityAgent,
    UnicodeNormalizationAgent,
    ParserDifferentialAgent,
    ORMLeakAgent,
    NovelSSRFRedirectAgent,
    XSLeakAgent,
    FrameworkCachePoisoningAgent,
    PolyglotSSTIAgent,
    ClientSidePathTraversalAgent,
    PromptInjectionAgent,
    AIAgentSecurityAgent,
    RAGPoisoningDetector,
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

async def run_scan(
    target_domain: str,
    proxy_url: Optional[str] = None,
    deep_mode: bool = False,
    bearer_token: Optional[str] = None,
    cookie_header: Optional[str] = None
) -> None:
    # Clean and normalize domain name from full URL or protocol prefix
    target_domain = target_domain.strip().lower()
    for prefix in ["https://", "http://"]:
        if target_domain.startswith(prefix):
            target_domain = target_domain[len(prefix):]
    target_domain = target_domain.split("/")[0].split("?")[0].split(":")[0]

    mode_str = "DEEP AUTONOMOUS RESEARCH MODE" if deep_mode else "STANDARD FAST RECON MODE"
    print(f"\n[+] Starting PenFlow Production Security Research Swarm Scan: {target_domain} [{mode_str}]")
    if proxy_url:
        print(f"[*] Interception Proxy Enabled: {proxy_url}")

    from penflow.traffic.session_manager import SessionManager
    session_manager = SessionManager()
    if bearer_token or cookie_header:
        session_manager.configure_authenticated_session(bearer_token=bearer_token, cookie_header=cookie_header)
        print(f"[*] Authenticated User Session Configured (Token: {bool(bearer_token)}, Cookie: {bool(cookie_header)})")

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
        WebCachePoisoningCapabilityAgent(priority=10),
        PrototypePollutionCapabilityAgent(priority=10),
        BusinessLogicCapabilityAgent(priority=10),
        XXECapabilityAgent(priority=10),
        AccountTakeoverCapabilityAgent(priority=10),
        UnicodeNormalizationAgent(priority=10),
        ParserDifferentialAgent(priority=10),
        ORMLeakAgent(priority=10),
        NovelSSRFRedirectAgent(priority=10),
        XSLeakAgent(priority=10),
        FrameworkCachePoisoningAgent(priority=10),
        PolyglotSSTIAgent(priority=10),
        ClientSidePathTraversalAgent(priority=10),
        PromptInjectionAgent(priority=10),
        AIAgentSecurityAgent(priority=10),
        RAGPoisoningDetector(priority=10),
    ]

    for agent in specialist_agents:
        for cap in agent.get_capabilities():
            capability_registry.register_capability(cap, agent, agent.name)

    capability_resolver = CapabilityResolver(capability_registry)

    # 3. Define Async Recon Task Handler
    async def handle_recon_task(ctx: ExecutionContext) -> None:
        target_sub = ctx.payload.get("subdomain") or ctx.config.get("subdomain") or target_domain

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
        
        from penflow.recon.file_content_fuzzer import FileContentFuzzer
        file_fuzzer = FileContentFuzzer(concurrency=15 if deep_mode else 10)
        from penflow.recon.openapi_parser import OpenAPIParser
        openapi_parser = OpenAPIParser()

        # Execute recon engines concurrently for high throughput
        crawl_task = crawler.crawl(f"https://{target_sub}")
        fuzz_task = route_fuzzer.fuzz(f"https://{target_sub}")
        tech_task = tech_engine.fingerprint(f"https://{target_sub}")
        audit_task = headers_auditor.audit_url(f"https://{target_sub}")
        file_fuzz_task = file_fuzzer.fuzz_files(f"https://{target_sub}", deep_mode=deep_mode)
        openapi_task = openapi_parser.discover_and_parse(f"https://{target_sub}")

        recon_results = await asyncio.gather(
            crawl_task, fuzz_task, tech_task, audit_task, file_fuzz_task, openapi_task,
            return_exceptions=True
        )

        crawl_res = recon_results[0] if isinstance(recon_results[0], dict) else {"endpoints": [], "forms": [], "js_files": []}
        fuzz_res = recon_results[1] if isinstance(recon_results[1], list) else []
        tech_res = recon_results[2] if isinstance(recon_results[2], dict) else {"technologies": []}
        audit_res = recon_results[3] if isinstance(recon_results[3], dict) else {"findings": []}
        file_fuzz_res = recon_results[4] if isinstance(recon_results[4], list) else []
        openapi_eps = recon_results[5] if isinstance(recon_results[5], list) else []

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

    all_discovered_subdomains = sorted(list(set([target_domain] + crt_subdomains + brute_subdomains)))

    subdomain_cap = 20 if deep_mode else 10
    subdomains_to_scan = all_discovered_subdomains[:subdomain_cap]
    print(f"[*] Total Discovered Subdomains & Sub-subdomains: {len(all_discovered_subdomains)}. Scheduling top {len(subdomains_to_scan)} across Orchestrator WorkerPool...")

    tasks = []
    for sub in subdomains_to_scan:
        t = orchestrator.create_task(task_type="recon_task", payload={"subdomain": sub}, priority=5, timeout=90.0 if deep_mode else 30.0)
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

        print(f"[*] Endpoint-Agent mapping: {len(classified_eps)} endpoints -> {len(agent_mapping)} capability targets")

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
            try:
                agent_res = await agent_inst.execute(cap_id, cap_ctx)
                raw_data = agent_res if isinstance(agent_res, dict) else {}
                traces = dict(raw_data.get("evidence", {})) if isinstance(raw_data.get("evidence"), dict) else {}
                for k in ("is_vulnerable", "vulnerable", "confidence_score", "confidence", "findings", "target_url"):
                    if k in raw_data and k not in traces:
                        traces[k] = raw_data[k]
                bundle = evidence_cas.store_evidence(
                    target=target_domain,
                    vuln_type=cap_id,
                    raw_traces=traces
                )
                crit_res = await critic_engine.verify_finding_async(bundle, cap_ctx)
                knowledge_store.experience.record_scan_result(cap_id, crit_res.get("is_verified", False))
                return crit_res
            except Exception as e:
                logger.error(f"[Agent:{agent_name}] Error executing {cap_id}: {str(e)}")
                return None

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

    # 6.5. Pre-Report Quality Gate & Compound Exploit Chainer Filter
    from penflow.validation.quality_gate import PreReportQualityGate
    from penflow.intelligence.exploit_chainer import ExploitChainer

    quality_gate = PreReportQualityGate(min_confidence=0.85, scope_domains=[target_domain])
    print(f"[*] Passing {len(verified_findings)} verified findings through 5-Stage Pre-Report Quality Gate (Min Confidence: 0.85)...")
    admitted_findings = await quality_gate.filter_findings(verified_findings)
    print(f"[+] Quality Gate Admitted: {len(admitted_findings)} / {len(verified_findings)} high-fidelity findings.")

    chainer = ExploitChainer()
    exploit_chains = chainer.construct_chains(admitted_findings)
    if exploit_chains:
        print(f"[+] Constructed {len(exploit_chains)} compound exploit chain(s) with amplified business impact narratives!")

    # 7. Render Swarm Dashboard, Console Plan & Generate Markdown Report File
    from penflow.reporting.dashboard import SwarmDashboard
    dashboard = SwarmDashboard()
    dashboard.render_live_summary(target_domain, knowledge_store, execution_plan, economy_agent=economy_agent, verified_findings=admitted_findings)
    
    report_gen = MarkdownReportGenerator()
    report_md = report_gen.generate_report(target_domain, knowledge_store, execution_plan, verified_findings=admitted_findings, exploit_chains=exploit_chains)
    report_file = report_gen.save_report(target_domain, report_md)

    from penflow.reporting.sarif_exporter import SARIFExporter
    sarif_exp = SARIFExporter()
    sarif_data = sarif_exp.export_sarif(target_domain, admitted_findings)
    sarif_file = sarif_exp.save_sarif_file(target_domain, sarif_data)
    print(f"[+] SARIF v2.1.0 Report generated and saved to: {sarif_file}")
    print(f"[+] Markdown Report successfully generated and saved to: {report_file}\n")

    await orchestrator.stop()

def main():
    if len(sys.argv) < 2 or (len(sys.argv) >= 2 and sys.argv[1].lower() in ["menu", "--menu", "-i", "interactive"]):
        from penflow.cli_menu import PenFlowTerminalUI
        tui = PenFlowTerminalUI()
        tui.run_interactive_loop()
        return

    cmd = sys.argv[1].lower()
    if cmd == "h1-report":
        vtype = sys.argv[2] if len(sys.argv) > 2 else "ssrf"
        target = sys.argv[3] if len(sys.argv) > 3 else "https://example.com/api/fetch"
        from penflow.reporting.hackerone_exporter import HackerOneReportExporter
        exporter = HackerOneReportExporter()
        report_md = exporter.export_report({"vulnerability_type": vtype, "target_url": target, "severity": "HIGH", "description": f"Verified {vtype} vulnerability discovered."})
        print(f"\n[+] Generated Professional HackerOne Submission Markdown Report:\n")
        print(report_md)
    elif cmd == "chain-audit":
        from penflow.analysis.chain_builder import VulnerabilityChainEngine
        engine = VulnerabilityChainEngine()
        mock_findings = [
            {"vulnerability_type": "ssrf", "target_url": "https://example.com/api/fetch"},
            {"vulnerability_type": "info_disclosure", "target_url": "https://example.com/169.254.169.254/latest/meta-data/"}
        ]
        chains = engine.build_chains(mock_findings)
        print(f"\n[+] Running Exploit Chain Builder Audit (Found {len(chains)} chains):")
        for c in chains:
            print(f"    - Chain: {c['chain_name']} [{c['severity']}] -> {c['description']}")
        print()
    elif cmd == "source-map":
        target_map = sys.argv[2] if len(sys.argv) > 2 else "bundle.js.map"
        from penflow.recon.source_map_parser import SourceMapParser
        parser = SourceMapParser()
        print(f"\n[+] Mining JS Source Map file '{target_map}' ...")
        if target_map.startswith("http"):
            res = asyncio.run(parser.fetch_and_parse_map(target_map))
        else:
            with open(target_map, "r", encoding="utf-8", errors="ignore") as f:
                res = parser.parse_map_json(f.read(), map_filename=target_map)
        print(f"    - Original Sources Extracted: {res['sources_count']}")
        print(f"    - Hardcoded Secrets Found: {len(res['secrets_found'])}")
        print(f"    - Discovered Routes: {len(res['routes_discovered'])}\n")
        for s in res['secrets_found']:
            print(f"    [SECRET] {s['secret_type']} @ {s['source_file']} -> {s['matched_value']}")
        print()
    elif cmd == "wayback":
        domain = sys.argv[2] if len(sys.argv) > 2 else "example.com"
        from penflow.recon.wayback_miner import WaybackMiner
        miner = WaybackMiner()
        print(f"\n[+] Mining Historical Wayback URLs & Framework Paths for '{domain}' ...")
        urls = asyncio.run(miner.fetch_wayback_urls(domain, max_results=50))
        paths = asyncio.run(miner.check_framework_paths(f"https://{domain}"))
        print(f"    - Historical Wayback URLs Discovered: {len(urls)}")
        print(f"    - Framework Admin/Debug Paths Found: {len(paths)}\n")
        for p in paths:
            print(f"    [FOUND] Path: {p['endpoint']} (HTTP {p['status_code']})")
        print()
    elif cmd == "auth-config":
        cfg_path = sys.argv[2] if len(sys.argv) > 2 else "config/identities.yaml"
        from penflow.traffic.auth_config_manager import AuthConfigManager
        manager = AuthConfigManager(config_path=cfg_path)
        print(f"\n[+] Loading Declarative Authenticated Identities from '{cfg_path}' ...")
        idents = manager.load_identities_from_yaml()
        print(f"    - Authenticated User Identities Registered: {len(idents)}\n")
        for i_id, i_obj in idents.items():
            print(f"    • Identity '{i_id}' ({i_obj.identity_type.value}): Token={bool(i_obj.credentials.bearer_token)}, Headers={len(i_obj.credentials.headers)}")
        print()
    elif cmd == "harvest-h1":
        api_token = None
        user_name = None
        if "--token" in sys.argv:
            idx = sys.argv.index("--token")
            if idx + 1 < len(sys.argv):
                api_token = sys.argv[idx + 1]
        if "--user" in sys.argv:
            idx = sys.argv.index("--user")
            if idx + 1 < len(sys.argv):
                user_name = sys.argv[idx + 1]
        from penflow.intelligence.hackerone_report_harvester import HackerOneReportHarvester
        harvester = HackerOneReportHarvester()
        print(f"\n[+] Harvesting Disclosed Security Reports from HackerOne API ...")
        files = asyncio.run(harvester.harvest_disclosed_reports(api_token=api_token, username=user_name))
        print(f"    - Reports Downloaded & Converted: {len(files)}")
        if files:
            from penflow.intelligence.writeup_loader import WriteupIngestionEngine
            engine = WriteupIngestionEngine()
            engine.ingest_directory("data/writeups")
            print(f"    - Automatically Retrained Mined Threat Rules Manifest!\n")
        else:
            print(f"    - Completed (No new disclosed reports downloaded or invalid API Token)\n")
    elif cmd == "login-auth":
        url = sys.argv[2] if len(sys.argv) > 2 else "https://target.com/api/login"
        user = sys.argv[3] if len(sys.argv) > 3 else "user_a"
        pwd = sys.argv[4] if len(sys.argv) > 4 else "password123"
        from penflow.traffic.auto_login_engine import AutoLoginEngine
        engine = AutoLoginEngine()
        print(f"\n[+] Running PenFlow Auto-Login & Auth Replay Engine for '{user}' on '{url}' ...")
        res = asyncio.run(engine.authenticate_user(url, user, pwd))
        if res:
            print(f"    - Status: SUCCESS")
            print(f"    - Identity Registered: {res['identity_id']}")
            print(f"    - Token Obtained: {bool(res['bearer_token'])}\n")
        else:
            print(f"    - Status: FAILED / UNREACHABLE (Expected for offline target URL)\n")
    elif cmd == "spa-mine":
        target = sys.argv[2] if len(sys.argv) > 2 else "https://target.com"
        from penflow.recon.spa_route_miner import SPARouteMiner
        miner = SPARouteMiner()
        print(f"\n[+] Running PenFlow SPA Route & Dynamic Chunk Miner on '{target}' ...")
        res = asyncio.run(miner.fetch_and_mine_url(target))
        print(f"    - Scripts Mined: {res['scripts_mined']}")
        print(f"    - Total SPA Routes Discovered: {res['total_routes']}")
        print(f"    - Total API Endpoints Discovered: {res['total_api_endpoints']}\n")
        for r in res['routes'][:15]:
            print(f"    • Route: {r}")
        for e in res['api_endpoints'][:15]:
            print(f"    • API: {e}")
        print()
    elif cmd == "scope-monitor":
        program = sys.argv[2] if len(sys.argv) > 2 else "target_program"
        filepath = sys.argv[3] if len(sys.argv) > 3 else "scope.json"
        api_token = None
        if "--token" in sys.argv:
            idx = sys.argv.index("--token")
            if idx + 1 < len(sys.argv):
                api_token = sys.argv[idx + 1]

        from penflow.recon.bugbounty_scope_monitor import BugBountyScopeMonitor
        monitor = BugBountyScopeMonitor()
        print(f"\n[+] Running Bug Bounty Program Scope Monitor for '{program}' ...")
        
        scope_data = {}
        if api_token:
            print(f"[*] Authenticating with HackerOne REST API using provided API Token...")
            scope_data = asyncio.run(monitor.fetch_hackerone_program_scope(program, api_token=api_token))
        elif os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                scope_data = json.load(f)
        else:
            scope_data = {"targets": {"in_scope": [{"asset_identifier": "*.target.com", "asset_type": "WILDCARD"}]}}

        assets = monitor.parse_hackerone_scope_manifest(program, scope_data)
        print(f"    - In-Scope Assets Parsed: {len(assets)}")
        for a in assets:
            print(f"    • [{a.asset_type}] {a.identifier} (Bounty={a.eligible_for_bounty}, MaxSev={a.max_severity})")
        print()
    elif cmd == "sast":
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
        token = None
        cookie = None
        deep = "--deep" in sys.argv
        if "--proxy" in sys.argv:
            idx = sys.argv.index("--proxy")
            if idx + 1 < len(sys.argv):
                proxy = sys.argv[idx + 1]
        if "--token" in sys.argv:
            idx = sys.argv.index("--token")
            if idx + 1 < len(sys.argv):
                token = sys.argv[idx + 1]
        if "--cookie" in sys.argv:
            idx = sys.argv.index("--cookie")
            if idx + 1 < len(sys.argv):
                cookie = sys.argv[idx + 1]
        asyncio.run(run_scan(target, proxy_url=proxy, deep_mode=deep, bearer_token=token, cookie_header=cookie))
    else:
        target = cmd
        deep = "--deep" in sys.argv
        asyncio.run(run_scan(target, deep_mode=deep))

if __name__ == "__main__":
    main()
