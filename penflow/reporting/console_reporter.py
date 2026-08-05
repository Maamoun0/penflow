from typing import Dict, Any, List
from penflow.planning.execution_plan import ExecutionPlan
from penflow.knowledge.knowledge_store import KnowledgeStore

class ConsoleReporter:
    """
    Renders structured execution plans, discovered assets, observations,
    and security hypotheses cleanly to the terminal console.
    """
    @staticmethod
    def render_plan(target_domain: str, knowledge_store: KnowledgeStore, plan: ExecutionPlan) -> None:
        print("\n" + "=" * 70)
        print(f"   PENFLOW AUTONOMOUS SECURITY RESEARCH REPORT: {target_domain.upper()}")
        print("=" * 70)

        assets = knowledge_store.assets.get_all()
        print(f"\n[+] DISCOVERED ASSETS ({len(assets)} Total):")
        for asset in assets:
            print(f"   * [{asset.asset_type.upper()}] {asset.canonical_name}")

        obs = knowledge_store.observations.get_all()
        print(f"\n[*] RAW OBSERVATIONS RECORDED ({len(obs)} Total):")
        for o in obs:
            print(f"   * {o.asset_id} -> [{o.observation_type}] {o.data}")

        print(f"\n[!] EXPLAINABLE SECURITY HYPOTHESES ({len(plan.ordered_hypotheses)} Total):")
        for i, h in enumerate(plan.ordered_hypotheses, 1):
            print(f"   [{i}] {h.title} (Priority: {h.priority}, Confidence: {h.confidence})")
            print(f"       Reason: {h.reason}")
            print(f"       Required Capabilities: {', '.join(h.required_capabilities) if h.required_capabilities else 'None'}")

        print(f"\n[=] EXECUTION PLAN METRICS:")
        print(f"   * Expected Value Score : {plan.expected_value}")
        print(f"   * Estimated Cost Score : {plan.estimated_cost}")
        print(f"   * Estimated Time (Sec) : {plan.estimated_runtime_seconds}")
        print(f"   * Required Capabilities: {', '.join(plan.required_capabilities) if h.required_capabilities else 'None'}")
        print("\n" + "=" * 70 + "\n")
