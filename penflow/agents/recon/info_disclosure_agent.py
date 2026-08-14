"""
Information Disclosure & Sensitive Data Exposure Specialist Capability Agent for PenFlow.

Capabilities:
  1. Exposed Debug & Actuator Routes (/actuator/heapdump, /actuator/env, /_profiler/phpinfo)
  2. Version Control System & Environment Secrets (.git/HEAD, .env, db.sql)
  3. API Over-Fetching & PII Exposure (password_hash, ssn, reset_token in JSON bodies)
  4. Live API Keys & Credential Exfiltration (AWS, Stripe, Google, JWT, Private Keys)
"""
import re
from typing import List, Dict, Any, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.testing.payload_engine import PayloadTemplateEngine
from penflow.testing.response_analyzer import SemanticResponseAnalyzer
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.info_disclosure")


class InfoDisclosureCapabilityAgent(BaseCapabilityAgent):
    """
    Elite Information Disclosure & Sensitive Data Exposure Agent.
    Audits endpoints for exposed debug actuators, heapdumps, secrets, VCS leaks, and JSON PII over-fetching.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="InfoDisclosureCapabilityAgent", priority=priority)
        self.payload_engine = PayloadTemplateEngine()
        self.analyzer = SemanticResponseAnalyzer()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="info_disclosure",
                name="Exposed Debug & Sensitive Data Disclosure Engine",
                description="Scans for publicly accessible Spring Actuator routes (env, heapdump), Swagger/OpenAPI docs, .env secrets, .git leaks, and JSON PII over-fetching",
                priority=self.priority,
                tags=["info_disclosure", "actuator", "swagger", "misconfiguration", "pii", "git"]
            ),
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[InfoDisclosureCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        origin = f"https://{context.asset}"

        probes = self.payload_engine.generate_info_disclosure_probes(origin)

        findings: List[Dict[str, Any]] = []
        recorded_exchanges = []

        # 1. Debug & Management Probe Sweep
        for p in probes:
            try:
                exch = await http_client.send_as_identity(
                    identity_id="anonymous_guest",
                    method=p.method,
                    url=p.url,
                    headers=p.headers
                )
                recorded_exchanges.append(exch.to_dict())
                resp = exch.response

                if resp and resp.status_code == 200:
                    body = resp.body_text or ""
                    content_type = (resp.headers.get("content-type", "") if resp.headers else "").lower()
                    content_len = len(body)

                    # Soft-404 Validation: filter HTML pages claiming 404
                    if "text/html" in content_type:
                        body_sub = body[:1024].lower()
                        if any(err in body_sub for err in ["404 not found", "page not found", "does not exist"]):
                            continue

                    analysis = self.analyzer.analyze_response(resp.status_code, resp.headers, body)
                    findings_list = analysis.get("findings", [])

                    # Binary Heapdump Detection
                    is_heapdump = "/actuator/heapdump" in p.url and (
                        "octet-stream" in content_type or content_len > 100000 or "HPROF" in body[:100]
                    )

                    # Git Repository Disclosure Detection
                    is_git = "ref: refs/heads" in body or "/.git/HEAD" in p.url and "ref:" in body

                    # Environment Secret Leak Detection
                    has_env_secret = any(k in body for k in ["DB_PASSWORD", "SECRET_KEY", "AWS_ACCESS_KEY_ID", "SPRING_DATASOURCE"]) or any(
                        f.get("type") == "actuator_env_leak" for f in findings_list
                    )

                    # Swagger / OpenAPI Specification
                    has_swagger = ("swagger" in body.lower() or "openapi" in body.lower() or "paths" in body.lower()) and "{" in body

                    # Secrets & PII findings from analyzer
                    has_secrets = any(f.get("type") in [
                        "jwt_token", "api_key_generic", "aws_access_key", "aws_secret_key",
                        "private_key", "password_field", "stripe_api_key", "google_api_key",
                        "bcrypt_hash", "pii_overfetching"
                    ] for f in findings_list)

                    if is_heapdump or is_git or has_env_secret or has_secrets or (has_swagger and "application/json" in content_type):
                        severity = "CRITICAL" if (is_heapdump or is_git or has_env_secret or has_secrets) else "HIGH"
                        confidence = 0.98 if (is_heapdump or is_git) else 0.92

                        reasoning = (
                            f"CRITICAL Heapdump Leak: Raw memory dump exposed at '{p.url}'." if is_heapdump else
                            f"CRITICAL Git Disclosure: Source code repository metadata exposed at '{p.url}'." if is_git else
                            f"CRITICAL Environment Leak: Production secrets exposed at '{p.url}'." if has_env_secret else
                            f"{severity} Info Disclosure: Sensitive data/API specification disclosed at '{p.url}'."
                        )

                        findings.append({
                            "target_url": p.url,
                            "severity": severity,
                            "confidence": confidence,
                            "reasoning": reasoning,
                            "findings": findings_list,
                            "exchange": exch.to_dict()
                        })
            except Exception as e:
                logger.debug(f"[InfoDisclosureAgent] Probe error for {p.url}: {e}")

        # 2. JSON API Over-Fetching & PII Audit on Crawled Endpoints
        for data in context.get_observation_data():
            if isinstance(data, dict):
                body_sample = data.get("body_text", "") or str(data)
                analysis = self.analyzer.analyze_response(200, {}, body_sample)
                pii_leaks = [f for f in analysis.get("findings", []) if f.get("type") in ("pii_overfetching", "password_field", "bcrypt_hash")]
                if pii_leaks:
                    findings.append({
                        "target_url": data.get("url", origin),
                        "severity": "CRITICAL",
                        "confidence": 0.95,
                        "reasoning": f"CRITICAL PII Over-Fetching: Endpoint returned sensitive user fields ({pii_leaks[0].get('description')}).",
                        "findings": pii_leaks,
                        "exchange": {}
                    })

        confirmed = [f for f in findings if f.get("confidence", 0) >= 0.85]
        is_vuln = len(confirmed) > 0
        best = confirmed[0] if confirmed else (findings[0] if findings else {})

        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "asset": context.asset,
            "is_vulnerable": is_vuln,
            "confidence_score": best.get("confidence", 0.0),
            "evidence": {
                "origin": origin,
                "vulnerable_paths": [f.get("target_url") for f in findings if f.get("target_url")],
                "reasoning": best.get("reasoning", "All probed management/debug routes protected and no PII over-fetching detected."),
                "findings": findings,
                "evidence_exchanges": recorded_exchanges
            }
        }
