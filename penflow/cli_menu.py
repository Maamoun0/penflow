"""
Interactive Terminal UI (TUI) Dashboard for PenFlow.
Authored by Ahmed Maamoun.

Provides a rich, interactive menu interface in CMD / Terminal, eliminating the need to memorize CLI parameters.
"""
import sys
import asyncio
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.tui")
console = Console()


class PenFlowTerminalUI:
    """
    Interactive TUI Dashboard guiding users through all PenFlow operations seamlessly.
    """

    def display_header(self):
        console.clear()
        title_panel = Panel(
            "[bold cyan]🔥 PenFlow v38.0 — Autonomous Security Research & Recon Engine[/bold cyan]\n"
            "[dim]Created & Tailored for Ahmed Maamoun | Bug Bounty Intelligence System[/dim]",
            title="[bold yellow]⚡ COMMAND DASHBOARD ⚡[/bold yellow]",
            subtitle="[dim]Select an option from the menu below[/dim]",
            border_style="magenta"
        )
        console.print(title_panel)

    def display_menu(self):
        table = Table(title="Available Operations", show_header=True, header_style="bold green")
        table.add_column("Option", style="bold yellow", justify="center", width=8)
        table.add_column("Operation Name", style="bold white", width=35)
        table.add_column("Description", style="dim cyan")

        table.add_row("1", "🚀 Full Target Scan", "Run autonomous recon & security agents on a target domain")
        table.add_row("2", "🔐 Authenticated Identity Config", "Manage User A / User B login credentials and active sessions")
        table.add_row("3", "🕵️ JS Source Maps & Secret Mining", "Extract source code and hardcoded secrets from .js.map files")
        table.add_row("4", "📜 Historical Wayback & API Mining", "Discover historical URLs, endpoints, and framework admin paths")
        table.add_row("5", "🎯 Bug Bounty Scope Monitor", "Monitor HackerOne program scopes and alert on asset changes")
        table.add_row("6", "🧠 Threat Intel & Harvester", "Harvest disclosed HackerOne reports and retrain threat rules")
        table.add_row("7", "📝 HackerOne Submission Generator", "Generate professional markdown writeups for bug bounty reports")
        table.add_row("8", "🔗 Exploit Vulnerability Chain Audit", "Synthesize multi-finding exploit chains and escalate severity")
        table.add_row("9", "🖥️ Launch Web UI Dashboard", "Open live web browser GUI dashboard & real-time terminal stream")
        table.add_row("0", "🚪 Exit PenFlow", "Close interactive terminal dashboard")

        console.print(table)
        console.print()

    def run_interactive_loop(self):
        while True:
            self.display_header()
            self.display_menu()

            choice = Prompt.ask("[bold yellow]Enter your choice[/bold yellow]", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"], default="1")

            if choice == "0":
                console.print("[bold red]Exiting PenFlow. Happy Bug Hunting, Ahmed![/bold red]")
                break
            elif choice == "1":
                self._handle_full_scan()
            elif choice == "2":
                self._handle_auth_config()
            elif choice == "3":
                self._handle_source_map()
            elif choice == "4":
                self._handle_wayback()
            elif choice == "5":
                self._handle_scope_monitor()
            elif choice == "6":
                self._handle_harvester()
            elif choice == "7":
                self._handle_h1_report()
            elif choice == "8":
                self._handle_chain_audit()
            elif choice == "9":
                self._handle_web_ui()

            console.print("\n[dim]Press Enter to return to main menu...[/dim]")
            input()

    def _handle_full_scan(self):
        target = Prompt.ask("[bold green]Enter Target Domain (e.g. target.com)[/bold green]")
        if not target:
            return
        deep_mode = Confirm.ask("[bold green]Enable Deep Autonomous Research Mode?[/bold green]", default=False)
        bearer = Prompt.ask("[bold green]Optional Bearer Token (Press Enter to skip)[/bold green]", default="")
        cookie = Prompt.ask("[bold green]Optional Cookie Header (Press Enter to skip)[/bold green]", default="")

        console.print(f"\n[bold green][+] Launching Swarm Scan on target '{target}'...[/bold green]\n")
        from penflow.__main__ import run_scan
        asyncio.run(run_scan(
            target_domain=target,
            deep_mode=deep_mode,
            bearer_token=bearer if bearer else None,
            cookie_header=cookie if cookie else None
        ))

    def _handle_auth_config(self):
        cfg_path = Prompt.ask("[bold green]Config YAML Path[/bold green]", default="config/identities.yaml")
        from penflow.traffic.auth_config_manager import AuthConfigManager
        manager = AuthConfigManager(config_path=cfg_path)
        idents = manager.load_identities_from_yaml()
        console.print(f"\n[bold green][+] Loaded {len(idents)} User Identities successfully![/bold green]")
        for i_id, i_obj in idents.items():
            console.print(f"  • {i_id} ({i_obj.identity_type.value}): Token={bool(i_obj.credentials.bearer_token)}")

    def _handle_source_map(self):
        target_map = Prompt.ask("[bold green]Enter .js.map File Path or URL[/bold green]", default="bundle.js.map")
        from penflow.recon.source_map_parser import SourceMapParser
        parser = SourceMapParser()
        console.print(f"\n[bold green][+] Mining Source Map '{target_map}'...[/bold green]")
        if target_map.startswith("http"):
            res = asyncio.run(parser.fetch_and_parse_map(target_map))
        else:
            try:
                with open(target_map, "r", encoding="utf-8", errors="ignore") as f:
                    res = parser.parse_map_json(f.read(), map_filename=target_map)
            except Exception as e:
                console.print(f"[bold red]Error reading file: {e}[/bold red]")
                return

        console.print(f"  - Extracted Sources: {res['sources_count']}")
        console.print(f"  - Secrets Found: {len(res['secrets_found'])}")
        console.print(f"  - Discovered Routes: {len(res['routes_discovered'])}")
        for s in res['secrets_found']:
            console.print(f"  [bold yellow][SECRET][/bold yellow] {s['secret_type']} @ {s['source_file']} -> {s['matched_value']}")

    def _handle_wayback(self):
        domain = Prompt.ask("[bold green]Enter Domain for Wayback Mining[/bold green]", default="example.com")
        from penflow.recon.wayback_miner import WaybackMiner
        miner = WaybackMiner()
        console.print(f"\n[bold green][+] Mining Historical URLs for '{domain}'...[/bold green]")
        urls = asyncio.run(miner.fetch_wayback_urls(domain, max_results=50))
        paths = asyncio.run(miner.check_framework_paths(f"https://{domain}"))
        console.print(f"  - Historical Wayback URLs Discovered: {len(urls)}")
        console.print(f"  - Framework Admin/Debug Paths Found: {len(paths)}")
        for p in paths:
            console.print(f"  [bold green][FOUND][/bold green] {p['endpoint']} (HTTP {p['status_code']})")

    def _handle_scope_monitor(self):
        program = Prompt.ask("[bold green]HackerOne Program Handle (e.g. saltosystems)[/bold green]", default="saltosystems")
        scope_file = Prompt.ask("[bold green]Scope JSON File Path (Press Enter for online API)[/bold green]", default="")
        token = Prompt.ask("[bold green]HackerOne API Token (Press Enter to use default token)[/bold green]", default="33q1v7mDNyz97kz2l1FXgZoM4H0CDB66hUH+8iFnliA=")
        
        from penflow.recon.bugbounty_scope_monitor import BugBountyScopeMonitor
        monitor = BugBountyScopeMonitor(api_token=token if token else None)
        console.print(f"\n[bold green][+] Monitoring Scope for HackerOne Program '{program}'...[/bold green]")
        res = asyncio.run(monitor.monitor_program_scope(program, scope_file=scope_file if scope_file else None))
        console.print(f"  - Program: {res['program_handle']}")
        console.print(f"  - In-Scope Assets: {len(res['in_scope_assets'])}")
        console.print(f"  - Scope Alerts: {len(res['alerts'])}")

    def _handle_harvester(self):
        token = Prompt.ask("[bold green]HackerOne API Token[/bold green]", default="33q1v7mDNyz97kz2l1FXgZoM4H0CDB66hUH+8iFnliA=")
        user = Prompt.ask("[bold green]HackerOne Public Username[/bold green]", default="a_maamoun")
        from penflow.intelligence.hackerone_report_harvester import HackerOneReportHarvester
        harvester = HackerOneReportHarvester()
        console.print(f"\n[bold green][+] Harvesting Disclosed Reports from HackerOne...[/bold green]")
        files = asyncio.run(harvester.harvest_disclosed_reports(api_token=token if token else None, username=user if user else None))
        console.print(f"  - Reports Downloaded & Retrained: {len(files)}")

    def _handle_h1_report(self):
        vtype = Prompt.ask("[bold green]Vulnerability Type (idor, ssrf, xss, etc.)[/bold green]", default="idor")
        target = Prompt.ask("[bold green]Target Vulnerable Endpoint URL[/bold green]", default="https://example.com/api/v1/user/2")
        from penflow.reporting.hackerone_exporter import HackerOneReportExporter
        exporter = HackerOneReportExporter()
        report_md = exporter.export_report({"vulnerability_type": vtype, "target_url": target, "severity": "HIGH", "description": f"Verified {vtype} vulnerability discovered."})
        console.print(f"\n[bold green][+] Generated HackerOne Markdown Report:[/bold green]\n")
        console.print(report_md)

    def _handle_chain_audit(self):
        from penflow.analysis.chain_builder import VulnerabilityChainEngine
        engine = VulnerabilityChainEngine()
        mock_findings = [
            {"vulnerability_type": "ssrf", "target_url": "https://example.com/api/fetch"},
            {"vulnerability_type": "info_disclosure", "target_url": "https://example.com/169.254.169.254/latest/meta-data/"}
        ]
        chains = engine.build_chains(mock_findings)
        console.print(f"\n[bold green][+] Synthesized Exploit Chains (Found {len(chains)}):[/bold green]")
        for c in chains:
            console.print(f"  - Chain: [bold yellow]{c['chain_name']}[/bold yellow] [{c['severity']}] -> {c['description']}")

    def _handle_web_ui(self):
        port = Prompt.ask("[bold green]Web Dashboard Port[/bold green]", default="8000")
        console.print(f"\n[bold green][+] Launching PenFlow Web GUI Dashboard on http://localhost:{port} ...[/bold green]\n")
        import uvicorn
        from penflow.ui.app import app
        uvicorn.run(app, host="127.0.0.1", port=int(port))
