import pytest
from penflow.planning.rule_loader import DeclarativeRuleLoader
from penflow.planning.planning_rules import PlanningRuleEngine
from penflow.knowledge.asset_registry import AssetRegistry
from penflow.knowledge.relationships import RelationshipRegistry
from penflow.knowledge.knowledge_graph import KnowledgeGraph

def test_declarative_rule_loader_and_engine():
    loader = DeclarativeRuleLoader(rules_dir="config/rules")
    rules = loader.load_rules()
    assert len(rules) >= 4  # Loaded rules from YAML files

    engine = PlanningRuleEngine(rule_loader=loader)
    matched = engine.evaluate("Discovered graphql endpoint at /admin/graphql?id=10")
    
    assert len(matched) >= 2
    matched_ids = [r.rule_id for r in matched]
    assert "R_GRAPHQL_01" in matched_ids or "R_IDOR_01" in matched_ids

def test_knowledge_graph_multi_hop_traversal():
    assets = AssetRegistry()
    rel = RelationshipRegistry()
    graph = KnowledgeGraph(assets, rel)

    n1 = graph.add_node("company.com", "target")
    n2 = graph.add_node("api.company.com", "subdomain")
    n3 = graph.add_node("https://api.company.com/graphql", "endpoint")

    graph.add_edge(n1.id, "HAS_SUBDOMAIN", n2.id)
    graph.add_edge(n2.id, "EXPOSES_ENDPOINT", n3.id)

    traversed = graph.traverse_graph("company.com", max_depth=3)
    assert len(traversed["nodes"]) == 3
    assert len(traversed["edges"]) == 2
