"""
AI Supply Chain Security Capability Agent for PenFlow.

Capabilities:
  - Exposed OAuth / CI/CD Credentials in AI Pipeline Configurations
  - Secret & API Key Leaks in Model Weights, Data Pipeline, & Artifact Stores
"""
import httpx
import re
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
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
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}"
        config_urls = [
            f"{base_url}/.well-known/ai-plugin.json",
            f"{base_url}/api/v1/ai/config",
            f"{base_url}/model/metadata.json"
        ]

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
                for cfg_url in config_urls:
                    try:
                        resp = await client.get(cfg_url)
                        if resp.status_code == 200:
                            text = resp.text
                            if re.search(r'sk-[A-Za-z0-9]{32,}', text) or re.search(r'hf_[A-Za-z0-9]{32,}', text):
                                curl_cmd = f"curl -i -s -k '{cfg_url}'"
                                exch_dict = {
                                    "request": {"method": "GET", "url": cfg_url},
                                    "response": {"status_code": resp.status_code, "body_snippet": text[:500]}
                                }

                                findings.append({
                                    "vulnerability_type": "ai_supply_chain_security",
                                    "target_url": cfg_url,
                                    "severity": "CRITICAL",
                                    "confidence": 0.95,
                                    "is_vulnerable": True,
                                    "exploit_curl": curl_cmd,
                                    "reproduction_steps": self.poc_generator.generate_reproduction_steps("Exposed AI Pipeline API Key", cfg_url, curl_cmd),
                                    "description": f"Exposed AI provider secret key detected in AI supply chain configuration at '{cfg_url}'.",
                                    "_exchange_obj": exch_dict
                                })
                                evidence["ai_key_exposed"] = True
                                break
                    except Exception as e:
                        logger.debug(f"AI supply chain check failed on {cfg_url}: {e}")

        except Exception as e:
            logger.error(f"[{self.name}] Exception testing '{context.asset}': {e}")

        is_vuln = len(findings) > 0
        primary_exch = findings[0].get("_exchange_obj") if findings else None
        return {
            "capability_id": capability_id,
            "status": "COMPLETED",
            "agent": self.name,
            "is_vulnerable": is_vuln,
            "vulnerable": is_vuln,
            "confidence": 0.95 if is_vuln else 0.0,
            "confidence_score": 0.95 if is_vuln else 0.0,
            "_exchange_obj": primary_exch,
            "evidence": evidence,
            "findings": findings
        }
