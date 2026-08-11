"""
AI Supply Chain Security Capability Agent for PenFlow.

Capabilities:
  - Exposed OAuth / CI/CD Credentials in AI Pipeline Configurations
  - Secret & API Key Leaks in Model Weights, Data Pipeline, & Artifact Stores
"""
import httpx
import re
from typing import Dict, Any, List, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.ai_supply_chain")


class AISupplyChainAgent(BaseCapabilityAgent):
    """
    Capability Agent detecting exposed OAuth tokens, HuggingFace tokens, OpenAI keys,
    and CI/CD credentials in AI supply chain artifacts and model endpoints.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="AISupplyChainAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="ai_supply_chain_security", name="AI Supply Chain Security", description="Detects exposed AI API keys, HuggingFace tokens, and CI/CD secrets in AI pipelines", priority=self.priority, tags=["ai", "supply_chain", "secrets", "tokens"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")

        http_client = context.get_http_client()
        config_urls = self._collect_ai_config_urls(context)

        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        secret_patterns = [
            (r'sk-[A-Za-z0-9]{32,}', "OpenAI Secret Key"),
            (r'hf_[A-Za-z0-9]{32,}', "HuggingFace Token"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token")
        ]

        for cfg_url in config_urls[:6]:
            try:
                exch = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=cfg_url)
                resp = exch.response
                if not resp or resp.status_code != 200:
                    continue

                text = resp.body_text or resp.body_snippet or ""
                exch_dict = exch.to_dict()

                for pat, secret_type in secret_patterns:
                    if re.search(pat, text):
                        curl_cmd = f"curl -i -s -k '{cfg_url}'"
                        reasoning = f"CRITICAL AI Supply Chain Leak [{secret_type}]: Exposed secret token detected in pipeline artifact '{cfg_url}'."

                        findings.append({
                            "vulnerability_type": "ai_supply_chain_security",
                            "secret_type": secret_type,
                            "target_url": cfg_url,
                            "severity": "CRITICAL",
                            "confidence": 0.96,
                            "is_vulnerable": True,
                            "exploit_curl": curl_cmd,
                            "reproduction_steps": self.poc_generator.generate_reproduction_steps(f"Exposed {secret_type}", cfg_url, curl_cmd),
                            "description": reasoning,
                            "_exchange_obj": exch_dict
                        })
                        evidence["ai_key_exposed"] = True
                        break
            except Exception as e:
                logger.debug(f"AI supply chain check error on {cfg_url}: {e}")

        is_vuln = len(findings) > 0
        from penflow.capabilities.result import AgentExecutionResult
        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vuln,
            confidence_score=0.96 if is_vuln else 0.0,
            reasoning=findings[0]["description"] if findings else "AI supply chain configurations verified without secret token exposure.",
            target_url=config_urls[0] if config_urls else f"https://{context.asset}",
            findings=findings,
            evidence={
                "ai_key_exposed": evidence.get("ai_key_exposed"),
                "findings": findings,
                "evidence_exchanges": [f.get("_exchange_obj", {}) for f in findings if f.get("_exchange_obj")]
            }
        ).to_dict()

    def _collect_ai_config_urls(self, context: CapabilityExecutionContext) -> List[str]:
        target = context.asset if hasattr(context, "asset") else "example.com"
        target_url = target if target.startswith("http") else f"https://{target}"
        urls = [
            f"{target_url}/.well-known/ai-plugin.json",
            f"{target_url}/api/v1/ai/config",
            f"{target_url}/model/metadata.json",
            f"{target_url}/.env"
        ]

        if hasattr(context, "observations") and context.observations:
            for obs in context.observations:
                data = obs.get("data", {}) if isinstance(obs, dict) else {}
                if isinstance(data, dict):
                    for ep in data.get("endpoints", []):
                        if isinstance(ep, dict) and ep.get("url"):
                            url = ep["url"]
                            if any(k in url.lower() for k in ["config", "plugin", "model", "metadata", "env", "manifest"]):
                                urls.append(url)

        return list(dict.fromkeys(urls))

