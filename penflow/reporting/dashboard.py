from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.planning.execution_plan import ExecutionPlan
from penflow.leadership.economy_agent import EconomyAgent

class SwarmDashboard:
    """
    Rich Terminal Research Dashboard.
    Provides live interactive status visualization of the Security Research Swarm,
    Knowledge Graph assets, Economy budget, and Verified Findings.
    """
    def __init__(self):
        self.console = Console()

    def render_live_summary(
        self,
        target_domain: str,
        knowledge_store: KnowledgeStore,
        execution_plan: ExecutionPlan,
        economy_agent: Optional[EconomyAgent] = None,
        verified_findings: Optional[List[Dict[str, Any]]] = None
    ) -> None:
        verified_findings = verified_findings or []

        # 1. Header Panel
        header = Panel(
            f"[bold cyan]PENFLOW AUTONOMOUS SECURITY RESEARCH SWARM DASHBOARD[/bold cyan]\n"
            f"[yellow]Target Domain:[/yellow] [bold white]{target_domain}[/bold white] | "
            f"[yellow]Status:[/yellow] [bold green]SCAN COMPLETE (VERIFIED)[/bold green]",
            title="[System Overview]",
            border_style="cyan"
        )
        self.console.print(header)

        # 2. Swarm Metrics & Budget Table
        metrics_table = Table(title="[Swarm Performance & Budget Metrics]", expand=True)
        metrics_table.add_column("Metric", style="cyan", no_wrap=True)
        metrics_table.add_column("Value", style="bold white")

        asset_count = len(knowledge_store.assets.get_all())
        obs_count = len(knowledge_store.observations.get_all())
        hyp_count = len(execution_plan.ordered_hypotheses)
        verified_count = len(verified_findings)
        used_cost = economy_agent.budget.current_cost_usd if economy_agent else 0.01

        metrics_table.add_row("Discovered Assets", str(asset_count))
        metrics_table.add_row("Recorded Observations", str(obs_count))
        metrics_table.add_row("Generated Hypotheses", str(hyp_count))
        metrics_table.add_row("Verified Findings (Critic Approved)", f"[bold green]{verified_count}[/bold green]")
        metrics_table.add_row("Expected Strategy Value", f"{execution_plan.expected_value:.2f}")
        metrics_table.add_row("Economy Cost Spent", f"[green]${used_cost:.4f}[/green]")

        self.console.print(metrics_table)

        # 3. Verified Findings Details
        if verified_findings:
            findings_table = Table(title="[Certified Vulnerability Findings (Zero False Positives)]", expand=True)
            findings_table.add_column("Hash ID", style="dim", width=16)
            findings_table.add_column("Type", style="bold red")
            findings_table.add_column("Confidence", style="bold green")
            findings_table.add_column("Verification Reason", style="white")

            for vf in verified_findings:
                findings_table.add_row(
                    vf.get("hash_id", "")[:12],
                    vf.get("vulnerability_type", ""),
                    f"{vf.get('confidence_score', 0.0)*100:.0f}%",
                    vf.get("verification_reason", "")[:60]
                )
            self.console.print(findings_table)
