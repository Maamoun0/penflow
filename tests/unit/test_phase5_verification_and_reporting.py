import pytest
from penflow.knowledge.evidence_cas import EvidenceCAS
from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.reporting.report_generator import MarkdownReportGenerator
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.planning.execution_plan import ExecutionPlan
from penflow.planning.hypothesis import Hypothesis

def test_evidence_cas_and_critic_verification():
    cas = EvidenceCAS()
    raw_traces = {"request": "GET /graphql?id=100", "response": "200 OK"}
    bundle = cas.store_evidence("target.com", "BOLA", raw_traces)
    
    assert bundle.hash_id is not None
    assert len(bundle.hash_id) == 64  # SHA-256 hash length

    retrieved = cas.get_evidence(bundle.hash_id)
    assert retrieved is not None
    assert retrieved.target == "target.com"

    critic = CriticVerificationEngine()
    vf = critic.verify_finding(bundle)
    
    assert vf["is_verified"] is True
    assert vf["confidence_score"] == 0.95

def test_markdown_report_generator(tmp_path):
    ks = KnowledgeStore()
    ks.assets.register_asset("api.target.com", "subdomain")
    
    plan = ExecutionPlan(
        ordered_hypotheses=[Hypothesis(title="Possible BOLA", confidence=0.8, priority=7.5)]
    )

    verified_findings = [{
        "hash_id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "target": "api.target.com",
        "vulnerability_type": "BOLA",
        "confidence_score": 0.95,
        "verification_reason": "Verified against HAR trace"
    }]

    generator = MarkdownReportGenerator()
    report_md = generator.generate_report("target.com", ks, plan, verified_findings)

    assert "PenFlow Security Research Report" in report_md
    assert "api.target.com" in report_md
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in report_md

    out_file = generator.save_report("target.com", report_md, output_dir=str(tmp_path))
    assert out_file.endswith(".md")
