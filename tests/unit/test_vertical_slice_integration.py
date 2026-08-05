import pytest
import os
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.recon.dns_resolver import DNSResolverEngine
from penflow.planning.planning_pipeline import PlanningPipeline
from penflow.infrastructure.sqlite_store import SQLiteKnowledgeStore

@pytest.mark.asyncio
async def test_end_to_end_vertical_slice(tmp_path):
    db_file = str(tmp_path / "test_penflow.db")
    sqlite_db = SQLiteKnowledgeStore(db_path=db_file)
    knowledge_store = KnowledgeStore()

    target_domain = "example.com"
    subdomains = ["example.com", "api.example.com", "graphql.example.com"]

    dns_engine = DNSResolverEngine()

    for sub in subdomains:
        knowledge_store.assets.register_asset(canonical_name=sub, asset_type="subdomain")
        sqlite_db.save_asset(asset_id=sub, target_domain=target_domain, asset_value=sub, asset_type="subdomain")

        res = await dns_engine.resolve_domain(sub)
        obs = knowledge_store.observations.record_observation(asset_id=sub, obs_type="dns_record", data=res)
        sqlite_db.save_observation(obs_id=obs.id, asset_id=sub, obs_type="dns_record", data=res)

        if "graphql" in sub:
            ep_obs = knowledge_store.observations.record_observation(
                asset_id=sub,
                obs_type="endpoint",
                data={"url": f"https://{sub}/graphql?id=10", "type": "graphql"}
            )
            sqlite_db.save_observation(obs_id=ep_obs.id, asset_id=sub, obs_type="endpoint", data={"url": f"https://{sub}/graphql?id=10", "type": "graphql"})

    pipeline = PlanningPipeline(knowledge_store)
    plan = pipeline.run_planning_cycle(target_domain)

    assert len(knowledge_store.assets.get_all()) == 3
    assert len(plan.ordered_hypotheses) > 0
    assert plan.expected_value > 0
    assert os.path.exists(db_file)
