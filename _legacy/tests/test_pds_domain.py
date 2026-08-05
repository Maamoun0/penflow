import pytest
from penflow.domain.models import (
    Knowledge, Technique, Playbook, Research, Pattern,
    Program, Target, Scope, Asset, Endpoint, Parameter, Identity, Session, Relationship,
    Goal, Plan, Task, Observation,
    Candidate, Finding, VerifiedFinding, Evidence,
    ExperiencePattern
)

def test_pds_v1_5_worlds_domain_models():
    # 1. Knowledge World
    tech = Technique(name="JWT Header Swap", category="Authorization")
    playbook = Playbook(name="GraphQL Security Playbook", techniques=[tech.id])
    assert playbook.name == "GraphQL Security Playbook"
    
    # 2. Target World
    target = Target(domain="app.company.com")
    endpoint = Endpoint(target_id=target.id, url="https://app.company.com/api/v1/user/101")
    rel = Relationship(source_id=endpoint.id, relation_type="USES_JWT", target_id="jwt_sec_1")
    assert rel.relation_type == "USES_JWT"
    
    # 3. Execution World
    goal = Goal(target_id=target.id, description="Audit BOLA on app.company.com")
    task = Task(goal_id=goal.id, agent_assigned="IDORSwarmAgent", task_type="BOLA_TEST")
    plan = Plan(goal_id=goal.id, tasks=[task])
    assert plan.tasks[0].agent_assigned == "IDORSwarmAgent"
    
    # 4. Result World
    candidate = Candidate(target_id=target.id, endpoint_id=endpoint.id, vuln_type="BOLA_IDOR", confidence=0.8)
    finding = Finding(candidate_id=candidate.id, target_id=target.id, vuln_type="BOLA_IDOR", confidence=0.95)
    verified = VerifiedFinding(finding_id=finding.id, target_id=target.id)
    assert verified.finding_id == finding.id
    
    # 5. Experience Layer
    exp = ExperiencePattern(tech_combination=["GraphQL", "JWT"], technique_name="JWT Header Swap", success_rate=0.78, times_tested=100, times_succeeded=78)
    assert exp.success_rate == 0.78
    assert exp.times_succeeded == 78
