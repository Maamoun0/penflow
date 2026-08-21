"""
GitHubLeaksAgent — Passive Secrets Leakage Specialist.

Simulates passive OSINT gathering by scanning common endpoints or external references
for leaked API keys, tokens, or credentials related to the target.
"""
from typing import List, Dict, Any
import re
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.recon.github_leaks")

class GitHubLeaksAgent(BaseCapabilityAgent):
    def __init__(self, priority: int = 15, **kwargs):
        super().__init__(agent_name="GitHubLeaksAgent", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="github_secrets_leak",
                name="Passive Secrets & OSINT Leakage",
                description="Scans public assets for leaked API keys, tokens, or credentials without exploiting the system.",
                version="1.0.0",
                tags=["recon", "passive", "osint", "secrets", "leaks"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[GitHubLeaksAgent] Executing passive leak check on asset '{context.asset}'")

        # In a real 2026 BB scenario, this would query GitHub API, Shodan, or grep.app
        # For PenFlow simulation, we check available observations and the base target for common leaked files (e.g. /.env.example or public js)
        
        http_client = context.get_http_client()
        target_url = context.asset if context.asset.startswith("http") else f"https://{context.asset}"
        
        test_urls = [
            f"{target_url}/.env.example",
            f"{target_url}/.git/config",
            f"{target_url}/js/app.js",
            f"{target_url}/api/swagger.json"
        ]

        findings = []
        is_vulnerable = False
        confidence = 0.0
        best_reasoning = "No passive OSINT leaks detected."

        secret_patterns = [
            (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
            (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
            (r"xox[baprs]-[0-9]{12,}-[0-9]{12,}-[a-zA-Z0-9]{24}", "Slack Token")
        ]

        for url in test_urls:
            try:
                exch = await http_client.send_as_identity(
                    identity_id="anonymous_guest",
                    method="GET",
                    url=url,
                    timeout=5.0
                )
                
                resp = exch.response
                if not resp or resp.status_code == 404:
                    continue
                
                body = resp.body_text or ""
                
                for pattern, secret_type in secret_patterns:
                    if re.search(pattern, body):
                        is_vulnerable = True
                        confidence = 0.95
                        reasoning = f"HIGH severity OSINT Leak [{secret_type}] found passively at {url}"
                        
                        if confidence > 0.0:
                            best_reasoning = reasoning

                        findings.append({
                            "vulnerability_type": "github_secrets_leak",
                            "severity": "HIGH",
                            "confidence": confidence,
                            "is_vulnerable": True,
                            "description": reasoning,
                            "target_url": url,
                            "secret_type": secret_type,
                            "_exchange_obj": exch.to_dict()
                        })
                        break
            except Exception as e:
                logger.debug(f"[GitHubLeaksAgent] Error scanning {url}: {e}")

        from penflow.capabilities.result import AgentExecutionResult
        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vulnerable,
            confidence_score=confidence if is_vulnerable else 0.0,
            reasoning=best_reasoning,
            target_url=target_url,
            findings=findings,
            evidence={
                "vulnerability_type": "github_secrets_leak",
                "findings": findings,
                "evidence_exchanges": [f.get("_exchange_obj", {}) for f in findings if f.get("_exchange_obj")]
            }
        ).to_dict()

