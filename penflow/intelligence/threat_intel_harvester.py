"""
ThreatIntelFeedHarvester — Real-time Public Threat Intelligence & Advisory Harvester for PenFlow.

Fetches public security advisories, CVE disclosures, and threat feeds from open APIs
(e.g., CISA Known Exploited Vulnerabilities KEV catalog, GitHub Advisory Database, OWASP feeds)
and automatically converts them into structured security writeups in 'data/writeups/'.
"""
import os
import json
import httpx
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.threat_intel_harvester")

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class ThreatIntelFeedHarvester:
    """
    Automated Threat Intelligence & Advisory Harvester.
    Continuously pulls live CVE advisories and security research feeds from public sources,
    normalizes them into structured writeup markdown files, and feeds PenFlow's continuous learner.
    """

    def __init__(self, output_dir: str = "data/writeups", timeout: float = 10.0):
        self.output_dir = output_dir
        self.timeout = timeout
        os.makedirs(self.output_dir, exist_ok=True)

    async def fetch_cisa_kev_advisories(self, max_items: int = 50) -> List[Dict[str, Any]]:
        """Fetch live advisories from CISA Known Exploited Vulnerabilities (KEV) JSON feed."""
        logger.info(f"[ThreatIntelHarvester] Querying CISA KEV live advisory feed: {CISA_KEV_FEED_URL}")
        advisories: List[Dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                resp = await client.get(CISA_KEV_FEED_URL)
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulnerabilities", [])
                    logger.info(f"[ThreatIntelHarvester] Received {len(vulns)} advisories from CISA KEV feed.")
                    
                    for v in vulns[:max_items]:
                        cve_id = v.get("cveID", "")
                        vendor = v.get("vendorProject", "Generic")
                        product = v.get("product", "System")
                        vuln_name = v.get("vulnerabilityName", "Security Issue")
                        desc = v.get("shortDescription", "")
                        required_action = v.get("requiredAction", "")
                        date_added = v.get("dateAdded", "")

                        advisories.append({
                            "cve_id": cve_id,
                            "vendor": vendor,
                            "product": product,
                            "title": f"CISA KEV {cve_id}: {vuln_name}",
                            "description": desc,
                            "required_action": required_action,
                            "date_added": date_added,
                            "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else CISA_KEV_FEED_URL
                        })
        except Exception as e:
            logger.error(f"[ThreatIntelHarvester] Failed to fetch CISA KEV feed: {e}")

        return advisories

    def save_advisories_as_writeups(self, advisories: List[Dict[str, Any]]) -> int:
        """Converts raw threat intel advisories into structured PenFlow writeup markdown files."""
        saved_count = 0

        for adv in advisories:
            cve_id = adv.get("cve_id", "CVE_UNKNOWN").replace("-", "_").lower()
            filename = f"writeup_intel_{cve_id}.md"
            filepath = os.path.join(self.output_dir, filename)

            # Skip if already downloaded/exists
            if os.path.exists(filepath):
                continue

            vtype_guess = self._infer_vtype_from_text(adv.get("title", "") + " " + adv.get("description", ""))

            content = f"""# Live Threat Advisory: {adv.get('title')}

## Executive Summary
This advisory was dynamically harvested from live threat intelligence feeds ({adv.get('cve_id')}).

## Threat Details
- **CVE Identifier**: `{adv.get('cve_id')}`
- **Vendor / Product**: `{adv.get('vendor')} / {adv.get('product')}`
- **Disclosed Date**: `{adv.get('date_added')}`
- **Inferred Vulnerability Category**: `{vtype_guess}`

## Advisory Description
{adv.get('description')}

## Remediation & Mitigation Guidance
{adv.get('required_action')}

## References
- Source: {adv.get('source_url')}
"""
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)
                saved_count += 1
            except Exception as e:
                logger.error(f"[ThreatIntelHarvester] Error writing advisory file {filepath}: {e}")

        logger.info(f"[ThreatIntelHarvester] Successfully saved {saved_count} new live threat advisories to '{self.output_dir}'.")
        return saved_count

    def _infer_vtype_from_text(self, text: str) -> str:
        text_lower = text.lower()
        if "sql" in text_lower:
            return "sqli"
        elif "ssrf" in text_lower or "server-side request" in text_lower:
            return "ssrf"
        elif "command" in text_lower or "rce" in text_lower or "code execution" in text_lower:
            return "rce"
        elif "authorization" in text_lower or "bypass" in text_lower or "idor" in text_lower:
            return "idor"
        elif "disclosure" in text_lower or "leak" in text_lower or "exposure" in text_lower:
            return "info_disclosure"
        elif "deserialization" in text_lower:
            return "ssti"
        return "info_disclosure"
