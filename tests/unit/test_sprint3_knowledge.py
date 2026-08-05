import pytest
from penflow.knowledge.knowledge_store import KnowledgeStore

def test_asset_registry_deduplication_and_aliases():
    ks = KnowledgeStore()
    a1 = ks.assets.register_asset("api.company.com", "subdomain", {"env": "prod"})
    a2 = ks.assets.register_asset("API.company.com", "subdomain")
    
    assert a1.id == a2.id
    assert a1.metadata["env"] == "prod"

    ks.assets.add_alias(a1.id, "api-v1.company.com")
    by_alias = ks.assets.get_asset_by_name("api-v1.company.com")
    assert by_alias is not None
    assert by_alias.id == a1.id

def test_observation_store_immutability():
    ks = KnowledgeStore()
    obs = ks.observations.record_observation("asset_123", "http_response", {"status": 200, "server": "nginx"})
    
    assert obs.asset_id == "asset_123"
    assert obs.observation_type == "http_response"
    
    records = ks.observations.get_by_asset("asset_123")
    assert len(records) == 1

def test_evidence_store_cas_hashing():
    ks = KnowledgeStore()
    content = "GET /api/v1/user HTTP/1.1\r\nHost: target.local"
    artifact1 = ks.evidence.store_evidence(content, content_type="text/plain")
    artifact2 = ks.evidence.store_evidence(content, content_type="text/plain")

    assert artifact1.sha256 == artifact2.sha256
    assert ks.evidence.has_evidence(artifact1.sha256) is True

def test_knowledge_graph_and_relationships():
    ks = KnowledgeStore()
    subdomain = ks.graph.add_node("sub.target.com", "subdomain")
    endpoint = ks.graph.add_node("https://sub.target.com/graphql", "api_endpoint")

    edge = ks.graph.add_edge(subdomain.id, "HAS_ENDPOINT", endpoint.id)
    assert edge.relation_type == "HAS_ENDPOINT"

    related = ks.graph.query_related_assets("sub.target.com", relation_type="HAS_ENDPOINT")
    assert len(related) == 1
    assert related[0].canonical_name == "https://sub.target.com/graphql"

def test_memory_engine_storage():
    ks = KnowledgeStore()
    entry = ks.memory.store_memory("vulnerable_patterns", "IDOR_UUID", {"confidence": 0.95})
    assert entry.category == "vulnerable_patterns"

    memories = ks.memory.get_memories("vulnerable_patterns", key_filter="IDOR")
    assert len(memories) == 1

def test_timeline_engine():
    ks = KnowledgeStore()
    evt1 = ks.timeline.record_event("asset_1", "new_endpoint", "Added /api/v2")
    evt2 = ks.timeline.record_event("asset_1", "new_js", "Discovered main.js")

    history = ks.timeline.get_asset_timeline("asset_1")
    assert len(history) == 2
    assert history[0].event_type == "new_endpoint"

def test_search_and_index_engine():
    ks = KnowledgeStore()
    asset = ks.assets.register_asset("dev.app.com", "subdomain", {"technology": "React"})
    ks.index.index_term("technologies", "React", asset.id)

    # Full text search
    ft_res = ks.search.full_text_search("dev.app")
    assert len(ft_res) == 1

    # Tag search
    tag_res = ks.search.tag_search("technology", "React")
    assert len(tag_res) == 1

    # Tech index search
    tech_res = ks.search.technology_search("React")
    assert len(tech_res) == 1
