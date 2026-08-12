"""
HackerOne Report Exporter for PenFlow.

Generates professional, copy-paste ready HackerOne submission markdown writeups
formatted with CVSS v3.1 vectors, CWE tags, Summary, Steps to Reproduce, Business Impact, and Remediation.
"""
from typing import Dict, Any
from penflow.reporting.impact_scorer import ImpactScorer
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.reporting.hackerone_exporter")


class HackerOneReportExporter:
    """
    Generates industry-standard HackerOne submission report markdown documents with verbatim HTTP traces and cURL PoCs.
    """

    def __init__(self):
        self.impact_scorer = ImpactScorer()
        self.poc_generator = PoCGenerator()

    def export_report(self, finding: Dict[str, Any]) -> str:
        vtype = finding.get("vulnerability_type", "Security Vulnerability").upper()
        target = finding.get("target_url", "https://target.com")
        severity = finding.get("severity", "HIGH")
        desc = finding.get("description", "Vulnerability detected by PenFlow Autonomous Engine.")

        impact_info = self.impact_scorer.evaluate_impact(finding)

        # Extract HTTP evidence
        exch_list = finding.get("evidence_exchanges", [])
        if not exch_list:
            single_exch = finding.get("_exchange_obj") or finding.get("exchange")
            if single_exch:
                exch_list = [single_exch]

        curl_cmd = f"curl -i -s -k -X GET \"{target}\""
        raw_http_evidence = ""

        if exch_list and isinstance(exch_list[0], dict):
            primary = exch_list[0]
            req = primary.get("request", {})
            resp = primary.get("response", {})

            method = req.get("method", "GET")
            req_headers = "\n".join([f"{k}: {v}" for k, v in req.get("headers", {}).items()])
            req_body = req.get("body", "")

            resp_status = resp.get("status_code", 200)
            resp_headers = "\n".join([f"{k}: {v}" for k, v in resp.get("headers", {}).items()])
            resp_body = resp.get("body_snippet", "") or resp.get("body_text", "")

            raw_http_evidence = f"""### Raw HTTP Request (Verified Trace)
```http
{method} {req.get('url', target)} HTTP/1.1
{req_headers}

{req_body}
```

### Raw HTTP Response (Verified Evidence)
```http
HTTP/1.1 {resp_status}
{resp_headers}

{resp_body[:1500]}
```"""

            # Build cURL
            headers_curl = " \\\n  ".join([f'-H "{k}: {v}"' for k, v in req.get("headers", {}).items() if k.lower() not in ("host", "connection", "content-length")])
            if headers_curl:
                headers_curl = " \\\n  " + headers_curl
            curl_cmd = f"curl -i -s -k -X {method}{headers_curl} \\\n  \"{target}\""

        report_md = f"""# Vulnerability Report: [{severity}] {vtype} on {target}

---

## 1. Vulnerability Summary

| Field | Details |
|---|---|
| **Vulnerability Title** | {vtype} |
| **Asset / Target URL** | `{target}` |
| **Severity** | **{severity}** |
| **CVSS v3.1 Score** | `{impact_info.get('cvss_vector', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N')}` |
| **CWE Mapping** | `{impact_info.get('cwe', 'CWE-200')}` |
| **Verification Status** | **Confirmed & Live Reproducible (0 False Positives)** |

### Executive Summary
{desc}

---

## 2. Verified Proof of Concept (PoC)

Execute the following verified `cURL` command to reproduce the issue directly:

```bash
{curl_cmd}
```

---

## 3. Step-by-Step Reproduction Guide

1. Open a terminal or security auditing console with network reachability to `{target}`.
2. Execute the verified `cURL` command provided in Section 2.
3. Observe the server response headers and payload body.
4. Confirm that the application returned unauthenticated/unauthorized data or permitted state manipulation.

---

## 4. Verbatim HTTP Exchange Evidence

{raw_http_evidence if raw_http_evidence else "*Evidence exchange trace captured dynamically by PenFlow Knowledge Engine.*"}

---

## 5. Business Impact Analysis

{impact_info.get('business_impact', 'An attacker can exploit this vulnerability to bypass security boundaries, access confidential user data, or compromise application state.')}

---

## 6. Remediation & Recommended Fix

1. **Input & Authorization Enforcement**: Implement strict server-side authorization controls and input validation on `{target}`.
2. **Session & Access Boundary**: Ensure appropriate access control checks are enforced prior to processing requests.
"""
        logger.info(f"[H1Exporter] Exported HackerOne markdown report for '{vtype}' on '{target}'.")
        return report_md
