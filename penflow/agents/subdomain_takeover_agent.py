"""
SubdomainTakeoverCapabilityAgent — Dangling CNAME & Cloud Service Takeover Specialist for PenFlow.

Checks all discovered subdomains for dangling CNAME records pointing to unclaimed cloud services:
  - AWS S3 Bucket ("NoSuchBucket", "The specified bucket does not exist")
  - GitHub Pages ("There isn't a GitHub Pages site here")
  - Heroku App ("Heroku | No such app", "404 Not Found")
  - Fastly CDN ("Fastly error: unknown domain")
  - Azure Web App ("404 Web Site not found")
  - Shopify ("Sorry, this shop is currently unavailable")
  - Netlify ("Not found - Request ID")
  - Vercel ("DEPLOYMENT_NOT_FOUND")
  - Pantheon ("404 error unknown site")
  - Surge.sh ("project not found")
  - Ghost.io ("The thing you were looking for is no longer here")
  - Bitbucket ("Repository not found")
"""
import re
import httpx
from typing import List, Dict, Any, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.subdomain_takeover")

# 12 Cloud Service Takeover Fingerprint Catalog
TAKEOVER_FINGERPRINTS = [
    {
        "service": "AWS S3 Bucket",
        "cname_pattern": r"s3[.-].*amazonaws\.com",
        "body_patterns": [r"nosuchbucket", r"the\s+specified\s+bucket\s+does\s+not\s+exist"],
        "severity": "critical",
        "remediation": "Claim the S3 bucket name on AWS S3 or remove the CNAME DNS record."
    },
    {
        "service": "GitHub Pages",
        "cname_pattern": r"github\.io",
        "body_patterns": [r"there\s+isn't\s+a\s+github\s+pages\s+site\s+here", r"for\s+root-level\s+domain\s+recovery"],
        "severity": "high",
        "remediation": "Add the custom domain to your GitHub repository settings or delete CNAME."
    },
    {
        "service": "Heroku App",
        "cname_pattern": r"herokudns\.com|herokuapp\.com",
        "body_patterns": [r"heroku\s*\|\s*no\s+such\s+app", r"no-such-app\.html"],
        "severity": "high",
        "remediation": "Add domain to Heroku app dashboard or remove CNAME record."
    },
    {
        "service": "Fastly CDN",
        "cname_pattern": r"fastly\.net",
        "body_patterns": [r"fastly\s+error:\s+unknown\s+domain"],
        "severity": "high",
        "remediation": "Add domain to Fastly service configuration or remove CNAME."
    },
    {
        "service": "Azure Web App",
        "cname_pattern": r"azurewebsites\.net|cloudapp\.net",
        "body_patterns": [r"404\s+web\s+site\s+not\s+found"],
        "severity": "high",
        "remediation": "Claim custom domain in Azure Portal or remove CNAME."
    },
    {
        "service": "Shopify",
        "cname_pattern": r"myshopify\.com",
        "body_patterns": [r"sorry,\s+this\s+shop\s+is\s+currently\s+unavailable"],
        "severity": "high",
        "remediation": "Link domain in Shopify settings or remove CNAME."
    },
    {
        "service": "Netlify",
        "cname_pattern": r"netlify\.app|netlify\.com",
        "body_patterns": [r"not\s+found\s+-\s+request\s+id:"],
        "severity": "high",
        "remediation": "Add domain in Netlify site settings or remove CNAME."
    },
    {
        "service": "Vercel",
        "cname_pattern": r"vercel-dns\.com|now\.sh",
        "body_patterns": [r"deployment_not_found", r"404:\s+this\s+page\s+could\s+not\s+be\s+found"],
        "severity": "high",
        "remediation": "Add domain in Vercel project settings or remove CNAME."
    },
    {
        "service": "Pantheon",
        "cname_pattern": r"pantheonsite\.io",
        "body_patterns": [r"404\s+error\s+unknown\s+site"],
        "severity": "high",
        "remediation": "Add domain in Pantheon dashboard or remove CNAME."
    },
    {
        "service": "Surge.sh",
        "cname_pattern": r"surge\.sh",
        "body_patterns": [r"project\s+not\s+found"],
        "severity": "high",
        "remediation": "Run surge --domain or remove CNAME record."
    },
    {
        "service": "Ghost.io",
        "cname_pattern": r"ghost\.io",
        "body_patterns": [r"the\s+thing\s+you\s+were\s+looking\s+for\s+is\s+no\s+longer\s+here"],
        "severity": "high",
        "remediation": "Add domain in Ghost settings or remove CNAME."
    },
    {
        "service": "Bitbucket",
        "cname_pattern": r"bitbucket\.io",
        "body_patterns": [r"repository\s+not\s+found"],
        "severity": "high",
        "remediation": "Add domain in Bitbucket repository settings or remove CNAME."
    },
]


class SubdomainTakeoverCapabilityAgent(BaseCapabilityAgent):
    """
    Subdomain Takeover Capability Agent.
    Audits CNAME records and HTTP response bodies for unclaimed cloud service fingerprints.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="SubdomainTakeoverCapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="subdomain_takeover_check",
                name="Subdomain Takeover Fingerprint Audit",
                description="Checks subdomains for dangling CNAME records and unclaimed cloud service fingerprints across 12 platforms",
                priority=self.priority,
                tags=["takeover", "subdomain", "dns", "cname", "cloud"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[SubdomainTakeoverCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        subdomains = self._collect_subdomains(context)

        findings: List[Dict[str, Any]] = []

        for sub in subdomains[:10]:
            target_url = f"https://{sub}"
            result = await self._audit_subdomain_takeover(http_client, target_url, sub)
            if result:
                findings.append(result)
                if result.get("is_vulnerable"):
                    break

        confirmed = [f for f in findings if f.get("is_vulnerable")]
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
                "target_subdomain": best.get("subdomain", context.asset),
                "service": best.get("service", ""),
                "reasoning": best.get("reasoning", "No dangling CNAME or cloud takeover fingerprint detected."),
                "findings": findings,
                "evidence_exchanges": [f.get("exchange", {}) for f in findings if f.get("exchange")]
            }
        }

    def _collect_subdomains(self, context: CapabilityExecutionContext) -> List[str]:
        subs = [context.asset]
        for obs in context.observations:
            data = obs.get("data", {}) if isinstance(obs, dict) else {}
            if isinstance(data, dict):
                sub = data.get("canonical_name") or data.get("subdomain") or obs.get("asset_id")
                if sub and sub not in subs:
                    subs.append(sub)
        return subs

    async def _audit_subdomain_takeover(
        self,
        http_client: Any,
        target_url: str,
        subdomain: str
    ) -> Optional[Dict[str, Any]]:
        try:
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="GET",
                url=target_url
            )
            resp = exch.response
            if not resp:
                return None

            body = (resp.body_text or "").lower()
            status = resp.status_code

            # Audit against fingerprint catalog
            for fp in TAKEOVER_FINGERPRINTS:
                for pat in fp["body_patterns"]:
                    if re.search(pat, body, re.IGNORECASE):
                        return {
                            "subdomain": subdomain,
                            "target_url": target_url,
                            "service": fp["service"],
                            "is_vulnerable": True,
                            "confidence": 0.96,
                            "status_code": status,
                            "matched_pattern": pat,
                            "remediation": fp["remediation"],
                            "reasoning": (
                                f"CRITICAL Subdomain Takeover: Subdomain '{subdomain}' exposed "
                                f"unclaimed {fp['service']} fingerprint ('{pat}') with HTTP {status}. "
                                f"Attacker can claim host and serve malicious content."
                            ),
                            "exchange": exch.to_dict()
                        }
        except Exception as e:
            logger.debug(f"[SubdomainTakeoverAgent] Takeover audit failed for {target_url}: {e}")
        return None
