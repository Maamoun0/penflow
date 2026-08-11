"""
End-to-End Pipeline Regression Unit Tests.
Verifies that secure mock targets yield 0 verified findings across Quality Gate filters.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock

from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.validation.quality_gate import PreReportQualityGate
from penflow.knowledge.evidence_cas import EvidenceBundle


@pytest.mark.asyncio
async def test_critic_engine_falsifies_unvulnerable_bundle():
    critic = CriticVerificationEngine()
    bundle = EvidenceBundle(
        hash_id="test_hash_01",
        vulnerability_type="jwt_security_analysis",
        target="example.com",
        raw_traces={
            "is_vulnerable": False,
            "confidence_score": 0.0,
            "reasoning": "Target correctly rejected forged JWT token with 401 Unauthorized."
        }
    )
    res = critic.verify_finding(bundle)
    assert res["is_verified"] is False


@pytest.mark.asyncio
async def test_quality_gate_filters_false_findings():
    gate = PreReportQualityGate(min_confidence=0.85, scope_domains=["example.com"])
    findings = [
        {
            "vulnerability_type": "jwt_security_analysis",
            "is_verified": False,
            "confidence": 0.0,
            "target_url": "https://example.com/api/v1/user/me"
        },
        {
            "vulnerability_type": "polyglot_ssti",
            "is_verified": True,
            "confidence": 0.40,  # Below 0.85 threshold
            "target_url": "https://example.com/search"
        }
    ]
    admitted = await gate.filter_findings(findings)
    assert len(admitted) == 0
