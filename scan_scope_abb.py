"""
PenFlow Multi-Target Scope Scanner
===================================
Runs PenFlow against all ABB/Sensorfact targets and aggregates results.
"""
import asyncio
import sys
import io
import json
import os
from datetime import datetime

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

# ─────────────────────────────────────────────────
# FULL SCOPE LIST
# ─────────────────────────────────────────────────
SCOPE = [
    "workpackage-collaboration.abb.com",
    "tunnelgateway.eu.mybuildings.abb.com",
    "tunnelgateway.cn.mybuildings.abb.com",
    "shorturl.abb.com",
    "sensorfact.tools",
    "sensorfact.pt",
    "sensorfact.pl",
    "sensorfact.nl",
    "sensorfact.it",
    "sensorfact.fr",
    "sensorfact.fi",
    "sensorfact.eu",
    "sensorfact.es",
    "sensorfact.energy",
    "sensorfact.dk",
    "sensorfact.de",
    "sensorfact.cz",
    "sensorfact.com",
    "sensorfact.co.uk",
    "sensorfact.cloud",
    "sensorfact.ch",
    "sensorfact.be",
    "sensorfact.at",
    "sandboxlb.cloudintegration.abb.com",
    "salestool.ch.abb.com",
    "rfat.abb.com",
    "resources.news.e.abb.com",
    "resources.library.abb.com",
    "resource.evcharging.abb.com.cn",
    "resi-commercial.abb.com.cn",
    "request.abb.com.cn",
    "reportphishing.abb.com",
    "reporting.digital.motion.abb.com.cn",
    "remoteservices.abb.com",
    "remotemonitoring.drives.abb.com.cn",
    "remotemonitoring.drives.abb.com",
    "remote.app-control.mybuildings.abb.com",
    "remote-service.motion.abb.com.cn",
    "remote-expertise.powertrain.abb.com",
    "redirect.abb.com",
    "receiver.remotemonitoring.drives.abb.com",
    "receiver-drives.abb.com.cn",
    "re460monitoring.traction.abb.com",
    "rdp.oms.abb.com",
    "rcm.motors.abb.com.cn",
    "rbook.abb.com",
    "rancher.electrificationtools.abb.com",
    "raise-remoteassistance.abb.com",
    "rab-eu.rap.abb.com",
    "ra-workitem.cloudintegration.abb.com",
    "quotations.abb.com",
    "qrcode.motion.abb.com.cn",
    "qms.lmg.motion.abb.com.cn",
    "qbox.ch.abb.com",
    "qa-lp-global-plm.abb.com",
    "pwbw-digital-ci01.abilityplatform02.abb.com.cn",
    "pulpandpaper-industrial-automation-service.abb.com",
    "publish.library.abb.com",
    "pt.inside.abb.com",
    "psa.abb.com.br",
    "ps.abb.com",
    "provisioner.collaboration.abb.com",
    "provident-fund.in.abb.com",
    "protrack.in.abb.com",
    "protection.datacare.abb.com",
    "proservice.mybuildings.abb.com",
    "projecttimeentry.industrial-automation-service.abb.com",
    "projectspace.abb.com",
    "projects.drives.abb.com.cn",
    "products.mo.cloudintegration.abb.com",
    "products.electrificationtools.abb.com",
    "products.abb.com",
    "productid.abb.com",
    "prod.spine.abb.com",
    "procure.abb.com",
    "processindustry-care.abb.com",
    "prntrelay1.baldor.abb.com",
    "printrelay.baldor.abb.com",
    "printing-service.ch.abb.com",
    "preview-analytics.factory-tour-stotz-kontakt.abb.com",
    "pre-prod.sitemanager.ability.abb.com.cn",
    "pr.abb.com",
    "powertrain.smartsensor.abb.com.cn",
    "powertrain.abb.com.cn",
    "powertrain.abb.com",
    "powertalk.campaigns.abb.com",
    "powersource-configurator.abb.com",
    "powershop.elis.abb.com",
    "powerbi.smarterpro.abb.com",
    "portal.buildings-maintenance.abb.com.cn",
    "portal.backoffice.buildings-maintenance.abb.com.cn",
    "portal-cr04.abilityplatform02.abb.com.cn",
    "portal-cr03.abilityplatform02.abb.com.cn",
    "portal-cr02.abilityplatform02.abb.com.cn",
    "portal-cr02.abilityplatform01.abb.com.cn",
    "portal-cr01.abilityplatform02.abb.com.cn",
    "polaris.iam.motion.abb.com",
    "pnpabilityoi.genix.abb.com",
    "pms.drives.abb.com.cn",
    "pm.daas.abb.com.cn",
]

# ─────────────────────────────────────────────────
# IMPORTS
# ─────────────────────────────────────────────────
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
    GraphQLCapabilityAgent, IDORCapabilityAgent, BFLACapabilityAgent,
    MassAssignmentCapabilityAgent, RaceConditionCapabilityAgent,
    OAuthJWTCapabilityAgent, CORSCapabilityAgent, SSRFCapabilityAgent,
    NoSQLSQLiCapabilityAgent, SSTIRCECapabilityAgent,
    InfoDisclosureCapabilityAgent, RateLimitCapabilityAgent,
    OpenRedirectCapabilityAgent, SecurityConfigCapabilityAgent,
    XSSCapabilityAgent, HTTPSmugglingCapabilityAgent,
    SubdomainTakeoverCapabilityAgent, ParameterDiscoveryCapabilityAgent,
    WebCachePoisoningCapabilityAgent, PrototypePollutionCapabilityAgent,
    BusinessLogicCapabilityAgent, XXECapabilityAgent,
    AccountTakeoverCapabilityAgent,
)
from penflow.planning.planning_pipeline import PlanningPipeline
from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.leadership import ResearchDirectorAgent, EconomyAgent
from penflow.reporting.console_reporter import ConsoleReporter
from penflow.reporting.report_generator import MarkdownReportGenerator
from penflow.infrastructure.sqlite_store import SQLiteKnowledgeStore
from penflow.infrastructure.logger import get_logger
from penflow.traffic.proxy_engine import ProxyConfig

logger = get_logger("penflow.scope_scanner")

# ─────────────────────────────────────────────────
# GLOBAL RESULTS AGGREGATOR
# ─────────────────────────────────────────────────
ALL_FINDINGS = []
SCAN_SUMMARY = {
    "scan_started": datetime.now().isoformat(),
    "total_targets": len(SCOPE),
    "scanned": 0,
    "live_targets": 0,
    "dead_targets": 0,
    "total_findings": 0,
    "findings_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    "findings_by_type": {},
    "target_results": []
}


async def scan_single_target(target: str, proxy_url: Optional[str] = None, deep_mode: bool = False) -> dict:
    """Scan a single target and return findings."""
    target = target.strip().lower()
    for prefix in ["https://", "http://"]:
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0].split("?")[0].split(":")[0]

    print(f"\n{'='*70}")
    print(f"  [SCANNING] {target}")
    print(f"{'='*70}")

    target_result = {
        "target": target,
        "status": "scanned",
        "live": False,
        "technologies": [],
        "findings": [],
        "endpoints_discovered": 0,
        "scan_time": datetime.now().isoformat()
    }

    try:
        from penflow.traffic.session_manager import SessionManager
        session_manager = SessionManager()
        proxy_cfg = ProxyConfig(http_proxy=proxy_url) if proxy_url else None

        sqlite_db = SQLiteKnowledgeStore()
        knowledge_store = KnowledgeStore()
        evidence_cas = EvidenceCAS()
        critic_engine = CriticVerificationEngine()
        orchestrator = Orchestrator(max_workers=4)
        await orchestrator.start()

        dns_engine = DNSResolverEngine()
        crawler = SmartCrawler(max_depth=2, max_pages=30)
        tech_engine = TechnologyFingerprintEngine()

        from penflow.recon.route_fuzzer import SmartRouteFuzzer
        from penflow.recon.security_headers_audit import SecurityHeadersAuditor
        from penflow.recon.file_content_fuzzer import FileContentFuzzer
        from penflow.recon.openapi_parser import OpenAPIParser
        from penflow.recon.endpoint_classifier import EndpointClassifier

        route_fuzzer = SmartRouteFuzzer(max_concurrency=10)
        headers_auditor = SecurityHeadersAuditor()
        file_fuzzer = FileContentFuzzer(concurrency=10)
        openapi_parser = OpenAPIParser()

        # ── DNS Resolution ──────────────────────────────
        dns_res = await dns_engine.resolve_domain(target)
        knowledge_store.assets.register_asset(canonical_name=target, asset_type="subdomain")
        sqlite_db.save_asset(asset_id=target, target_domain=target, asset_value=target, asset_type="subdomain")

        if dns_res and (dns_res.get("is_resolved") or dns_res.get("ip_addresses")):
            target_result["live"] = True
            print(f"  [+] LIVE - DNS resolved: {dns_res.get('ip_addresses', [])}")
        else:
            print(f"  [-] DEAD/UNREACHABLE - No DNS records found")
            target_result["status"] = "dead"
            await orchestrator.stop()
            return target_result

        # ── Concurrent Recon ────────────────────────────
        recon_results = await asyncio.gather(
            crawler.crawl(f"https://{target}"),
            route_fuzzer.fuzz(f"https://{target}"),
            tech_engine.fingerprint(f"https://{target}"),
            headers_auditor.audit_url(f"https://{target}"),
            file_fuzzer.fuzz_files(f"https://{target}", deep_mode=deep_mode),
            openapi_parser.discover_and_parse(f"https://{target}"),
            return_exceptions=True
        )

        crawl_res    = recon_results[0] if isinstance(recon_results[0], dict) else {"endpoints": [], "forms": [], "js_files": []}
        fuzz_res     = recon_results[1] if isinstance(recon_results[1], list) else []
        tech_res     = recon_results[2] if isinstance(recon_results[2], dict) else {"technologies": []}
        audit_res    = recon_results[3] if isinstance(recon_results[3], dict) else {"findings": []}
        file_fuzz_res= recon_results[4] if isinstance(recon_results[4], list) else []
        openapi_eps  = recon_results[5] if isinstance(recon_results[5], list) else []

        target_result["technologies"] = tech_res.get("technologies", [])

        classifier = EndpointClassifier()
        classified_eps = classifier.classify_from_crawl(crawl_res) + openapi_eps
        target_result["endpoints_discovered"] = len(classified_eps) + len(fuzz_res)

        print(f"  [*] Technologies: {target_result['technologies']}")
        print(f"  [*] Endpoints discovered: {target_result['endpoints_discovered']}")
        print(f"  [*] Files found: {len(file_fuzz_res)}")

        # ── Capability Registry Setup ────────────────────
        capability_registry = CapabilityRegistry()
        specialist_agents = [
            GraphQLCapabilityAgent(priority=10), IDORCapabilityAgent(priority=10),
            BFLACapabilityAgent(priority=10), MassAssignmentCapabilityAgent(priority=10),
            RaceConditionCapabilityAgent(priority=10), OAuthJWTCapabilityAgent(priority=10),
            CORSCapabilityAgent(priority=10), SSRFCapabilityAgent(priority=10),
            NoSQLSQLiCapabilityAgent(priority=10), SSTIRCECapabilityAgent(priority=10),
            InfoDisclosureCapabilityAgent(priority=10), RateLimitCapabilityAgent(priority=10),
            OpenRedirectCapabilityAgent(priority=10), SecurityConfigCapabilityAgent(priority=10),
            XSSCapabilityAgent(priority=10), HTTPSmugglingCapabilityAgent(priority=10),
            SubdomainTakeoverCapabilityAgent(priority=10), ParameterDiscoveryCapabilityAgent(priority=10),
            WebCachePoisoningCapabilityAgent(priority=10), PrototypePollutionCapabilityAgent(priority=10),
            BusinessLogicCapabilityAgent(priority=10), XXECapabilityAgent(priority=10),
            AccountTakeoverCapabilityAgent(priority=10),
        ]
        for agent in specialist_agents:
            for cap in agent.get_capabilities():
                capability_registry.register_capability(cap, agent, agent.name)

        # ── Planning ─────────────────────────────────────
        planning = PlanningPipeline(knowledge_store=knowledge_store)
        try:
            planning.run_planning_cycle(target_domain=target)
        except Exception as e:
            logger.debug(f"[Planning] Non-critical planning error: {e}")

        # ── Capability Execution ──────────────────────────
        cap_ctx = CapabilityExecutionContext(
            asset=target,                    # bare domain — agents add https:// themselves
            knowledge_store=knowledge_store,
            session_manager=session_manager,
            proxy_config=proxy_cfg,
        )
        # Store recon data in shared cache so agents can access it
        cap_ctx.shared_cache["target_domain"] = target
        cap_ctx.shared_cache["base_url"] = f"https://{target}"
        cap_ctx.shared_cache["technologies"] = tech_res.get("technologies", [])
        cap_ctx.shared_cache["dynamic_endpoints"] = [
            ep.to_dict() if hasattr(ep, "to_dict") else ep for ep in classified_eps[:50]
        ]
        cap_ctx.shared_cache["fuzz_endpoints"] = fuzz_res[:50]

        raw_findings = []
        # Iterate over all registered capability IDs using _providers (the correct internal dict)
        all_cap_ids = list(capability_registry._providers.keys())
        print(f"  [*] Running {len(all_cap_ids)} security capability checks...")

        for cap_id in all_cap_ids:
            providers = capability_registry.get_providers(cap_id)
            if not providers:
                continue
            agent_obj, agent_name = providers[0]  # Take best (first) provider
            try:
                result = await agent_obj.execute(cap_id, cap_ctx)
                if result and isinstance(result, dict):
                    finds = result.get("findings", [])
                    if finds:
                        print(f"    → [{cap_id}] returned {len(finds)} finding(s)")
                    raw_findings.extend(finds)
            except Exception as e:
                logger.debug(f"Agent {cap_id} error: {e}")

        # ── Critic Verification ───────────────────────────
        verified_findings = []
        for f in raw_findings:
            verdict = await critic_engine.verify(f, cap_ctx)
            if verdict.get("confirmed", False):
                f["critic_score"] = verdict.get("confidence", 0)
                f["target"] = target
                verified_findings.append(f)

        # ── Security Headers Quick Findings ──────────────
        if audit_res.get("findings"):
            for hf in audit_res["findings"]:
                hf["target"] = target
                hf["source"] = "security_headers"
                verified_findings.append(hf)

        # ── File Exposure Findings ────────────────────────
        if file_fuzz_res:
            for ff in file_fuzz_res:
                verified_findings.append({
                    "target": target,
                    "vulnerability_type": "sensitive_file_exposure",
                    "severity": "HIGH",
                    "target_url": ff.get("url", ""),
                    "description": f"Sensitive file exposed: {ff.get('path', '')} (Status: {ff.get('status_code', '?')})",
                    "source": "file_fuzzer"
                })

        # ── Subdomain Takeover via DNS ────────────────────
        if dns_res.get("cname") and not dns_res.get("a_records"):
            cname_val = dns_res.get("cname", "")
            dangling_keywords = ["github", "heroku", "netlify", "vercel", "s3.amazonaws", "azurewebsites", "fastly", "pantheon"]
            for kw in dangling_keywords:
                if kw in cname_val.lower():
                    verified_findings.append({
                        "target": target,
                        "vulnerability_type": "subdomain_takeover",
                        "severity": "CRITICAL",
                        "target_url": f"https://{target}",
                        "description": f"Potential subdomain takeover: CNAME points to '{cname_val}' which may be unclaimed",
                        "source": "dns_analysis"
                    })

        target_result["findings"] = verified_findings
        print(f"  [+] Verified findings: {len(verified_findings)}")

        if verified_findings:
            for vf in verified_findings:
                sev = vf.get("severity", "INFO").upper()
                vtype = vf.get("vulnerability_type", "unknown")
                url = vf.get("target_url", "")
                print(f"    ⚠  [{sev}] {vtype} → {url}")

        await orchestrator.stop()

    except Exception as e:
        print(f"  [ERROR] Exception scanning {target}: {e}")
        target_result["status"] = "error"
        target_result["error"] = str(e)

    return target_result


async def run_full_scope_scan():
    print("\n" + "="*70)
    print("  PENFLOW — FULL SCOPE SCAN: ABB / SENSORFACT TARGETS")
    print(f"  Total targets: {len(SCOPE)}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)

    RESUME_FROM = 56  # Skip already-completed targets (0-indexed)

    for i, target in enumerate(SCOPE, 1):
        if i <= RESUME_FROM:
            print(f"\n[{i}/{len(SCOPE)}] [SKIP] {target} (already scanned)")
            SCAN_SUMMARY["scanned"] += 1
            SCAN_SUMMARY["dead_targets"] += 1  # approximate for skipped
            continue

        print(f"\n[{i}/{len(SCOPE)}]", end="")
        try:
            result = await asyncio.wait_for(
                scan_single_target(target, deep_mode=False),
                timeout=300  # 5 minutes max per target
            )
        except asyncio.TimeoutError:
            print(f"  [TIMEOUT] {target} exceeded 5 min limit — skipping")
            result = {"target": target, "status": "timeout", "live": False, "findings": [], "endpoints_discovered": 0}

        SCAN_SUMMARY["scanned"] += 1
        if result.get("live"):
            SCAN_SUMMARY["live_targets"] += 1
        else:
            SCAN_SUMMARY["dead_targets"] += 1

        for f in result.get("findings", []):
            ALL_FINDINGS.append(f)
            SCAN_SUMMARY["total_findings"] += 1
            sev = f.get("severity", "INFO").upper()
            if sev in SCAN_SUMMARY["findings_by_severity"]:
                SCAN_SUMMARY["findings_by_severity"][sev] += 1
            vtype = f.get("vulnerability_type", "unknown")
            SCAN_SUMMARY["findings_by_type"][vtype] = SCAN_SUMMARY["findings_by_type"].get(vtype, 0) + 1

        SCAN_SUMMARY["target_results"].append(result)

        # Small delay between targets to avoid rate limiting
        await asyncio.sleep(1)

    # ─────────────────────────────────────────────────
    # GENERATE FINAL REPORT
    # ─────────────────────────────────────────────────
    SCAN_SUMMARY["scan_ended"] = datetime.now().isoformat()

    report_path = os.path.join(
        os.path.dirname(__file__),
        "reports",
        f"abb_sensorfact_scope_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    )
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    with open(report_path, "w", encoding="utf-8") as rpt:
        rpt.write(f"# PenFlow Security Research Report\n")
        rpt.write(f"## ABB / Sensorfact Scope — Full Scan\n\n")
        rpt.write(f"**Scan Date:** {SCAN_SUMMARY['scan_started']}\n")
        rpt.write(f"**Total Targets:** {SCAN_SUMMARY['total_targets']}\n")
        rpt.write(f"**Live Targets:** {SCAN_SUMMARY['live_targets']}\n")
        rpt.write(f"**Dead/Unreachable:** {SCAN_SUMMARY['dead_targets']}\n")
        rpt.write(f"**Total Verified Findings:** {SCAN_SUMMARY['total_findings']}\n\n")

        rpt.write("## Findings by Severity\n\n")
        rpt.write("| Severity | Count |\n|---|---|\n")
        for sev, cnt in SCAN_SUMMARY["findings_by_severity"].items():
            if cnt > 0:
                rpt.write(f"| {sev} | {cnt} |\n")

        rpt.write("\n## Findings by Type\n\n")
        rpt.write("| Vulnerability Type | Count |\n|---|---|\n")
        for vtype, cnt in sorted(SCAN_SUMMARY["findings_by_type"].items(), key=lambda x: -x[1]):
            rpt.write(f"| {vtype} | {cnt} |\n")

        rpt.write("\n---\n\n")
        rpt.write("## Detailed Findings\n\n")

        # Sort findings by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(ALL_FINDINGS, key=lambda x: sev_order.get(x.get("severity", "INFO").upper(), 5))

        for idx, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "INFO").upper()
            vtype = f.get("vulnerability_type", "unknown")
            target = f.get("target", "")
            url = f.get("target_url", "")
            desc = f.get("description", "")
            evidence = f.get("evidence", "")
            impact = f.get("impact", "")

            rpt.write(f"### [{idx}] [{sev}] {vtype}\n\n")
            rpt.write(f"- **Target:** `{target}`\n")
            rpt.write(f"- **URL:** `{url}`\n")
            rpt.write(f"- **Description:** {desc}\n")
            if impact:
                rpt.write(f"- **Impact:** {impact}\n")
            if evidence:
                rpt.write(f"- **Evidence:**\n```\n{evidence}\n```\n")
            rpt.write(f"\n---\n\n")

        rpt.write("\n## Per-Target Summary\n\n")
        rpt.write("| # | Target | Live | Endpoints | Findings |\n|---|---|---|---|---|\n")
        for i, tr in enumerate(SCAN_SUMMARY["target_results"], 1):
            live_str = "✅" if tr.get("live") else "❌"
            eps = tr.get("endpoints_discovered", 0)
            fcount = len(tr.get("findings", []))
            rpt.write(f"| {i} | `{tr['target']}` | {live_str} | {eps} | {fcount} |\n")

    # Also save raw JSON
    json_path = report_path.replace(".md", ".json")
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(SCAN_SUMMARY, jf, indent=2, ensure_ascii=False, default=str)

    print("\n\n" + "="*70)
    print("  PENFLOW SCOPE SCAN — COMPLETE")
    print("="*70)
    print(f"  Total Targets Scanned : {SCAN_SUMMARY['scanned']}")
    print(f"  Live                  : {SCAN_SUMMARY['live_targets']}")
    print(f"  Dead/Unreachable      : {SCAN_SUMMARY['dead_targets']}")
    print(f"  Total Findings        : {SCAN_SUMMARY['total_findings']}")
    print()
    print("  Severity Breakdown:")
    for sev, cnt in SCAN_SUMMARY["findings_by_severity"].items():
        if cnt > 0:
            print(f"    - {sev:10s}: {cnt}")
    print()
    print(f"  Markdown Report: {report_path}")
    print(f"  JSON Report    : {json_path}")
    print("="*70)


if __name__ == "__main__":
    asyncio.run(run_full_scope_scan())
