import pytest
import asyncio
from penflow.core.orchestrator import Orchestrator
from penflow.core.context import ExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.planning.planning_pipeline import PlanningPipeline

@pytest.mark.asyncio
async def test_orchestrator_worker_pool_phase1_integration():
    orchestrator = Orchestrator(max_workers=2)
    await orchestrator.start()
    
    knowledge_store = KnowledgeStore()
    executed_subdomains = []

    async def mock_recon_handler(ctx: ExecutionContext) -> None:
        sub = ctx.task_id
        executed_subdomains.append(sub)
        knowledge_store.assets.register_asset(canonical_name=f"{sub}.test.com", asset_type="subdomain")
        knowledge_store.observations.record_observation(
            asset_id=f"{sub}.test.com",
            obs_type="endpoint_discovered",
            data={"url": f"https://{sub}.test.com/graphql", "type": "graphql"}
        )

    orchestrator.register_task_handler("mock_recon", mock_recon_handler)

    task1 = orchestrator.create_task(task_type="mock_recon", payload={"subdomain": "sub1"})
    task2 = orchestrator.create_task(task_type="mock_recon", payload={"subdomain": "sub2"})

    await orchestrator.submit_task(task1)
    await orchestrator.submit_task(task2)

    while True:
        completed = sum(1 for t in [task1, task2] if t.status.value in ["COMPLETED", "FAILED"])
        if completed == 2:
            break
        await asyncio.sleep(0.05)

    metrics = await orchestrator.get_metrics()
    assert metrics["completed_tasks"] == 2
    assert len(knowledge_store.assets.get_all()) == 2
    
    pipeline = PlanningPipeline(knowledge_store)
    plan = pipeline.run_planning_cycle("test.com")
    assert len(plan.ordered_hypotheses) > 0

    await orchestrator.stop()
