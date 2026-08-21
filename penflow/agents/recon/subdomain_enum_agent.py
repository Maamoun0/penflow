"""
SubdomainEnumerationAgent — Passive Subdomain Reconnaissance Specialist.

Queries Certificate Transparency (CT) logs (crt.sh) to passively enumerate subdomains
for a given target asset without touching the target's infrastructure directly.
"""
from typing import List, Dict, Any
import json
import urllib.parse
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.recon.subdomain_enum")

class SubdomainEnumerationAgent(BaseCapabilityAgent):
    def __init__(self, priority: int = 10, **kwargs):
        super().__init__(agent_name="SubdomainEnumerationAgent", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="subdomain_enumeration",
                name="Passive Subdomain Enumeration",
                description="Queries crt.sh to extract subdomains for the target base domain passively.",
                version="1.0.0",
                tags=["recon", "passive", "subdomains", "osint"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[SubdomainEnumerationAgent] Executing passive enum on asset '{context.asset}'")

        http_client = context.get_http_client()
        target_domain = self._extract_base_domain(context.asset)
        
        # crt.sh endpoint returning JSON
        crt_url = f"https://crt.sh/?q=%.{urllib.parse.quote(target_domain)}&output=json"

        subdomains = set()
        findings = []

        try:
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="GET",
                url=crt_url,
                timeout=15.0 # Give crt.sh some time, it can be slow
            )
            
            resp = exch.response
            if resp and resp.status_code == 200 and resp.body_text:
                try:
                    data = json.loads(resp.body_text)
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        # name_value can contain newlines for multiple SANs
                        for name in name_value.split("\n"):
                            clean_name = name.strip().lower()
                            if clean_name.endswith(target_domain) and not clean_name.startswith("*"):
                                subdomains.add(clean_name)
                except json.JSONDecodeError:
                    logger.warning(f"[SubdomainEnumerationAgent] Failed to parse JSON from crt.sh for {target_domain}")
        except Exception as e:
            logger.error(f"[SubdomainEnumerationAgent] Error querying crt.sh: {e}")

        is_vulnerable = False # Enumeration is not a vulnerability itself, but an observation
        confidence = 0.0
        reasoning = f"Discovered {len(subdomains)} subdomains passively via crt.sh."

        if subdomains:
            # We report this as an 'Informative' finding or simply store it in evidence
            findings.append({
                "vulnerability_type": "subdomain_enumeration",
                "severity": "INFORMATIVE",
                "confidence": 1.0,
                "is_vulnerable": False,
                "description": reasoning,
                "discovered_subdomains": list(subdomains),
                "target_url": context.asset
            })

        from penflow.capabilities.result import AgentExecutionResult
        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vulnerable,
            confidence_score=confidence,
            reasoning=reasoning,
            target_url=context.asset,
            findings=findings,
            evidence={
                "discovered_subdomains": list(subdomains)
            }
        ).to_dict()

    def _extract_base_domain(self, asset: str) -> str:
        # Simplistic approach to get base domain. In production, use tldextract.
        # Removes http/https and any paths
        clean = asset.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        parts = clean.split(".")
        if len(parts) > 2:
            return ".".join(parts[-2:])
        return clean

