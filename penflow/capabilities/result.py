from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AgentExecutionResult:
    agent: str
    capability: str
    asset: str
    vulnerability_type: str = ""
    status: str = "COMPLETED"
    is_vulnerable: bool = False
    confidence_score: float = 0.0
    reasoning: str = ""
    target_url: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "agent": self.agent,
            "capability": self.capability,
            "asset": self.asset,
            "vulnerability_type": self.vulnerability_type,
            "is_vulnerable": self.is_vulnerable,
            "confidence_score": self.confidence_score,
            "reasoning": self.reasoning,
            "target_url": self.target_url,
            "findings": self.findings,
            "evidence": self.evidence,
            **self.metadata,
        }


CRITICAL_EVIDENCE_KEYS = (
    "is_vulnerable",
    "vulnerable",
    "confidence_score",
    "confidence",
    "reasoning",
    "vulnerability_type",
    "findings",
    "target_url",
    "_exchange_obj",
    "evidence_exchanges",
    "exploit_curl",
    "reproduction_steps",
)


def normalize_agent_result(
    raw_result: Any,
    *,
    agent_name: str,
    capability_id: str,
    asset: str,
) -> AgentExecutionResult:
    raw = raw_result if isinstance(raw_result, dict) else {}
    evidence = raw.get("evidence", {}) if isinstance(raw.get("evidence"), dict) else {}
    findings = raw.get("findings", []) if isinstance(raw.get("findings"), list) else []
    if not findings and isinstance(evidence.get("findings"), list):
        findings = evidence.get("findings", [])

    merged_evidence = dict(evidence)
    for key in CRITICAL_EVIDENCE_KEYS:
        if key in raw and key not in merged_evidence:
            merged_evidence[key] = raw[key]

    if findings and "findings" not in merged_evidence:
        merged_evidence["findings"] = findings

    # Extract exchanges from findings if not in merged_evidence
    if not merged_evidence.get("evidence_exchanges") and findings:
        derived_exchs = []
        for f in findings:
            if isinstance(f, dict):
                ex = f.get("exchange") or f.get("evidence_exchange") or f.get("_exchange_obj")
                if ex:
                    derived_exchs.append(ex)
                elif isinstance(f.get("evidence_exchanges"), list):
                    derived_exchs.extend(f.get("evidence_exchanges"))
        if derived_exchs:
            merged_evidence["evidence_exchanges"] = derived_exchs

    is_vulnerable = bool(
        raw.get("is_vulnerable", raw.get("vulnerable", merged_evidence.get("is_vulnerable", False)))
    )
    confidence_score = float(
        raw.get("confidence_score", raw.get("confidence", merged_evidence.get("confidence_score", 0.0))) or 0.0
    )
    reasoning = str(raw.get("reasoning", merged_evidence.get("reasoning", "")) or "")
    target_url = str(raw.get("target_url", merged_evidence.get("target_url", "")) or "")
    vulnerability_type = str(raw.get("vulnerability_type", merged_evidence.get("vulnerability_type", capability_id)) or capability_id)

    metadata = {
        key: value
        for key, value in raw.items()
        if key not in {"status", "agent", "capability", "asset", "vulnerability_type", "is_vulnerable", "vulnerable", "confidence_score", "confidence", "reasoning", "target_url", "findings", "evidence"}
    }

    # Ensure evidence_exchanges and _exchange_obj are top-level accessible in metadata if present in evidence
    if "evidence_exchanges" in merged_evidence and "evidence_exchanges" not in metadata:
        metadata["evidence_exchanges"] = merged_evidence["evidence_exchanges"]
    if "_exchange_obj" in merged_evidence and "_exchange_obj" not in metadata:
        metadata["_exchange_obj"] = merged_evidence["_exchange_obj"]

    return AgentExecutionResult(
        agent=str(raw.get("agent", agent_name)),
        capability=str(raw.get("capability", capability_id)),
        asset=str(raw.get("asset", asset)),
        vulnerability_type=vulnerability_type,
        status=str(raw.get("status", "COMPLETED")),
        is_vulnerable=is_vulnerable,
        confidence_score=confidence_score,
        reasoning=reasoning,
        target_url=target_url,
        findings=findings,
        evidence=merged_evidence,
        metadata=metadata,
    )

