"""
HackerOne & Bugcrowd Bug Bounty PoC Report Exporter for PenFlow.

Generates standardized vulnerability disclosure submission reports containing:
  - Summary & Executive Severity Breakdown
  - Exact Step-by-Step Reproduction Steps
  - Executable cURL Reproduction Commands
  - Raw HTTP Request/Response Evidence Pairs
  - Remediation Guidance
"""
from typing import List, Dict, Any, Optional
from penflow.reporting.cvss_calculator import CVSSCalculator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.reporting.bugbounty_exporter")


class BugBountyPoCExporter:
    """
    Generates ready-to-submit HackerOne/Bugcrowd vulnerability reports.
    """

    def __init__(self):
        self.cvss_calc = CVSSCalculator()

    def generate_hackerone_report(self, finding: Dict[str, Any], target_domain: str) -> str:
        """Convert a single verified finding into a submission-ready HackerOne report."""
        vtype = finding.get("vulnerability_type", finding.get("capability", "security_flaw"))
        target_url = finding.get("target_url", finding.get("target", target_domain))
        reasoning = finding.get("reasoning", "Vulnerability detected by PenFlow SROS.")

        metrics = self.cvss_calc.get_metrics_for(vtype)
        cvss = self.cvss_calc.calculate_score(metrics)

        # Build cURL command
        curl_cmd = self._build_curl_command(finding)

        lines = [
            f"# [Vulnerability Report] {cvss['severity']}: {vtype.replace('_', ' ').title()} on {target_url}",
            "",
            "## Summary",
            f"{reasoning}",
            "",
            "## Severity & CVSS Score",
            f"- **Severity Rating**: `{cvss['severity']}`",
            f"- **CVSS v3.1 Score**: `{cvss['base_score']}` / 10.0",
            f"- **CVSS Vector**: `{cvss['vector_string']}`",
            "",
            "## Vulnerability Details",
            f"- **Target URL**: `{target_url}`",
            f"- **Vulnerability Category**: `{vtype}`",
            f"- **Confidence Score**: `{finding.get('confidence_score', 0.95) * 100:.0f}%`",
            "",
            "## Steps to Reproduce",
            f"1. Open a terminal or HTTP client (e.g. cURL / Burp Suite Repeater).",
            f"2. Execute the following cURL command targeting `{target_url}`:",
            "",
            "```bash",
            f"{curl_cmd}",
            "```",
            "",
            "3. Observe the response status code and body containing evidence.",
            "",
            "## Evidence & Proof of Concept",
            ""
        ]

        # Add evidence exchanges if present
        evidence = finding.get("evidence", {})
        exchanges = finding.get("evidence_exchanges", []) or evidence.get("evidence_exchanges", [])
        if exchanges:
            for idx, ex in enumerate(exchanges[:2], 1):
                req = ex.get("request", {})
                resp = ex.get("response", {})
                lines.extend([
                    f"### Evidence Pair #{idx}",
                    "",
                    "**HTTP Request**:",
                    "```http",
                    f"{req.get('method', 'GET')} {req.get('url', target_url)} HTTP/1.1",
                    self._format_headers(req.get("headers", {})),
                    "",
                    f"{req.get('body_text', '')}",
                    "```",
                    "",
                    "**HTTP Response**:",
                    "```http",
                    f"HTTP/1.1 {resp.get('status_code', 200)}",
                    self._format_headers(resp.get("headers", {})),
                    "",
                    f"{resp.get('body_text', '')[:4000]}",
                    "```",
                    ""
                ])

        lines.extend([
            "## Impact Narrative",
            "An unauthorized attacker can exploit this flaw to compromise data confidentiality, integrity, or system boundaries.",
            "",
            "## Remediation Guidance",
            "Implement proper server-side input validation, authorization checks, and security controls.",
            "",
            "---",
            "*Report generated autonomously by PenFlow Bug Bounty Engine*"
        ])

        report_text = "\n".join(lines)
        logger.info(f"[BugBountyExporter] Generated HackerOne PoC report for '{vtype}' on '{target_url}'.")
        return report_text

    def _build_curl_command(self, finding: Dict[str, Any]) -> str:
        target_url = finding.get("target_url", finding.get("target", "https://example.com"))
        evidence = finding.get("evidence", {})
        exchanges = finding.get("evidence_exchanges", []) or evidence.get("evidence_exchanges", [])

        if exchanges and isinstance(exchanges[0], dict):
            req = exchanges[0].get("request", {})
            method = req.get("method", "GET")
            headers = req.get("headers", {})
            body = req.get("body_text", "")

            hdr_str = " ".join([f"-H '{k}: {v}'" for k, v in headers.items() if k.lower() not in ("host", "content-length")])
            data_str = f" -d '{body}'" if body and method in ("POST", "PUT", "PATCH") else ""
            return f"curl -X {method} {hdr_str}{data_str} '{target_url}'"

        return f"curl -i -s -k '{target_url}'"

    def _format_headers(self, headers: Dict[str, str]) -> str:
        if not isinstance(headers, dict):
            return ""
        return "\n".join([f"{k}: {v}" for k, v in headers.items()])
