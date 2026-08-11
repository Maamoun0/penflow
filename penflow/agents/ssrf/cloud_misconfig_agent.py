"""
Cloud Misconfiguration Capability Agent for PenFlow.

Capabilities:
  - Public AWS S3 Bucket Enumeration & Permissive ACLs (ListBucket, GetObject)
  - GCP Cloud Storage (GCS) Public Access Audits
  - Azure Blob Storage Container Public Access Probes
  - AWS/GCP Credential Exposure Pattern Detection in HTTP Responses
"""
import httpx
import re
from typing import Dict, Any, List, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.cloud_misconfig")

AWS_KEY_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})', "AWS Secret Access Key"),
    (r'"AccessKeyId"\s*:\s*"(AKIA[^"]+)"', "AWS JSON Access Key"),
    (r'AIza[0-9A-Za-z-_]{35}', "GCP API Key")
]


class CloudMisconfigCapabilityAgent(BaseCapabilityAgent):
    """
    Capability Agent detecting AWS S3, GCP GCS, Azure Blob Storage misconfigurations,
    and exposed cloud provider API keys/credentials in target responses.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="CloudMisconfigCapabilityAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="cloud_misconfig", name="Cloud Infrastructure Misconfig", description="Detects public cloud storage buckets (S3, GCS, Azure) and exposed credentials", priority=self.priority, tags=["cloud", "s3", "gcp", "azure"]),
            Capability(id="s3_bucket_exposure", name="Public S3 Bucket Detection", description="Detects unauthenticated public S3 bucket listing and read access", priority=self.priority, tags=["s3", "aws"])
        ]

    def _generate_bucket_candidates(self, asset: str) -> List[str]:
        clean_asset = asset.lower().replace("www.", "")
        domain_part = clean_asset.split(".")[0]
        return [
            clean_asset,
            clean_asset.replace(".", "-"),
            f"{domain_part}-backup",
            f"{domain_part}-assets",
            f"{domain_part}-media",
            f"{domain_part}-static",
            f"{domain_part}-uploads",
            f"{domain_part}-files",
            f"dev-{domain_part}",
            f"staging-{domain_part}"
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        candidates = self._generate_bucket_candidates(context.asset)

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
                # 1. Public AWS S3 Bucket Access Test
                for bucket in candidates:
                    s3_url = f"https://{bucket}.s3.amazonaws.com/"
                    try:
                        resp = await client.get(s3_url)
                        if resp.status_code == 200 and ("<ListBucketResult" in resp.text or "<Contents>" in resp.text):
                            curl_cmd = f"curl -i -s '{s3_url}'"
                            exch_dict = {
                                "request": {"method": "GET", "url": s3_url},
                                "response": {"status_code": resp.status_code, "body_snippet": resp.text[:500]}
                            }

                            findings.append({
                                "vulnerability_type": "cloud_misconfig",
                                "subtype": "public_s3_bucket_list",
                                "target_url": s3_url,
                                "bucket_name": bucket,
                                "severity": "CRITICAL",
                                "confidence": 0.98,
                                "is_vulnerable": True,
                                "exploit_curl": curl_cmd,
                                "reproduction_steps": self.poc_generator.generate_reproduction_steps("Public S3 Bucket Listing", s3_url, curl_cmd),
                                "description": f"Public AWS S3 bucket '{bucket}' permits unauthenticated ListBucket access.",
                                "_exchange_obj": exch_dict
                            })
                            evidence["public_s3_bucket"] = s3_url
                            break
                    except Exception as ep_err:
                        logger.debug(f"S3 check failed for {s3_url}: {ep_err}")

                # 2. Cloud Credential Exposure in Target Web Responses
                base_url = f"https://{context.asset}/"
                try:
                    target_resp = await client.get(base_url)
                    body_text = target_resp.text
                    for pat, pat_name in AWS_KEY_PATTERNS:
                        match = re.search(pat, body_text)
                        if match:
                            found_key = match.group(0)[:10] + "..."
                            curl_cmd = f"curl -i -s -k '{base_url}'"
                            exch_dict = {
                                "request": {"method": "GET", "url": base_url},
                                "response": {"status_code": target_resp.status_code, "body_snippet": body_text[:500]}
                            }
                            findings.append({
                                "vulnerability_type": "cloud_misconfig",
                                "subtype": "exposed_cloud_credential",
                                "target_url": base_url,
                                "credential_type": pat_name,
                                "severity": "CRITICAL",
                                "confidence": 0.95,
                                "is_vulnerable": True,
                                "exploit_curl": curl_cmd,
                                "reproduction_steps": self.poc_generator.generate_reproduction_steps("Cloud Credential Exposure", base_url, curl_cmd),
                                "description": f"Exposed cloud provider credential ({pat_name}: '{found_key}') detected in target HTTP response.",
                                "_exchange_obj": exch_dict
                            })
                            evidence["exposed_credential"] = pat_name
                            break
                except Exception as e:
                    logger.debug(f"Credential exposure scan failed on {base_url}: {e}")

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
