from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from penflow.planning.execution_plan import ExecutionPlan
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.reporting.cvss_calculator import CVSSCalculator
from penflow.shared.utils import get_utc_timestamp, ensure_dir

class MarkdownReportGenerator:
    """
    Generates HackerOne/Bugcrowd-grade Markdown Security Assessment Reports.
    Includes CVSS v3.1 scoring, HTTP request/response pairs, step-by-step
    reproduction, impact analysis, and remediation guidance.
    """
    def __init__(self):
        self.cvss_calc = CVSSCalculator()

    def generate_markdown_report(self, target_domain: str, findings: List[Dict[str, Any]]) -> str:
        """Simple wrapper method to generate markdown report from a list of findings."""
        dummy_ks = KnowledgeStore()
        dummy_plan = ExecutionPlan()
        return self.generate_report(target_domain, dummy_ks, dummy_plan, findings)

    def generate_report(self, target_domain: str, knowledge_store: KnowledgeStore,
                        plan: ExecutionPlan, verified_findings: List[Dict[str, Any]],
                        exploit_chains: Optional[List[Any]] = None) -> str:
        # Sanitize target_domain
        clean_target = target_domain.strip()
        for prefix in ("https://", "http://"):
            while clean_target.startswith(prefix):
                clean_target = clean_target[len(prefix):]
        clean_target = clean_target.split("/")[0].split("?")[0]
        target_domain = clean_target

        assets = knowledge_store.assets.get_all()
        obs = knowledge_store.observations.get_all()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Count findings by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        finding_details = []
        for vf in verified_findings:
            metrics = self.cvss_calc.get_metrics_for(vf.get("vulnerability_type", ""))
            cvss = self.cvss_calc.calculate_score(metrics)
            severity_counts[cvss["severity"]] = severity_counts.get(cvss["severity"], 0) + 1
            finding_details.append((vf, cvss))

        report_lines = [
            f"# 🛡️ PenFlow Security Research Report",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Target** | `{target_domain}` |",
            f"| **Date** | `{timestamp}` |",
            f"| **Platform** | PenFlow SROS v1.0 |",
            f"| **Total Findings** | {len(verified_findings)} |",
            f"| **Critical** | {severity_counts['Critical']} |",
            f"| **High** | {severity_counts['High']} |",
            f"| **Medium** | {severity_counts['Medium']} |",
            f"| **Low** | {severity_counts['Low']} |",
            f"| **Informative** | {severity_counts.get('Info', 0)} |",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"PenFlow conducted an automated security assessment of **{target_domain}** "
            f"using multi-agent reconnaissance, hypothesis-driven testing, and adversarial "
            f"falsification verification.",
            "",
            f"- **{len(assets)} asset(s)** discovered and audited via Scope Resolution and Smart Crawling",
            f"- **{len(obs)} recon observation(s)** recorded across all target channels",
            f"- **{len(verified_findings)} certified finding(s)** verified through adversarial critic engine",
            "",
            "---",
            "",
        ]

        # ───── Exploit Chains Section ─────
        if exploit_chains is None:
            from penflow.intelligence.exploit_chainer import ExploitChainer
            chainer = ExploitChainer()
            exploit_chains = chainer.construct_chains(verified_findings)

        if exploit_chains:
            report_lines.extend([
                "## ⛓️ Compound Exploit Chains",
                "",
                "PenFlow automatically correlated verified findings to construct high-impact multi-stage attack scenarios:",
                ""
            ])
            for chain in exploit_chains:
                severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠"}.get(chain.composite_severity, "🟡")
                report_lines.extend([
                    f"### {severity_emoji} {chain.title}",
                    "",
                    f"**Composite Severity**: `{chain.composite_severity}`",
                    "",
                    "**Attack Flow Steps**:",
                    ""
                ])
                for step in chain.steps:
                    report_lines.append(f"{step['step']}. **Step {step['step']}**: {step['description']}")
                report_lines.extend([
                    "",
                    f"**Impact**: {chain.impact_narrative}",
                    "",
                    f"**Remediation**: {chain.remediation}",
                    "",
                    "---",
                    ""
                ])

        # ───── Findings Section ─────
        if finding_details:
            report_lines.append("## Verified Findings\n")

            from penflow.knowledge.vulnerability_kb import VulnerabilityKnowledgeBase
            vkb = VulnerabilityKnowledgeBase()

            for idx, (vf, cvss) in enumerate(finding_details, 1):
                meta = vkb.get_metadata(vf.get("vulnerability_type", ""))
                vuln_type = vf.get("vulnerability_type", "Unknown")

                severity_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(
                    cvss["severity"], "⚪")

                verification_reason = vf.get("verification_reason", "")
                evidence_quality = vf.get("evidence_quality", {}) if isinstance(vf.get("evidence_quality"), dict) else {}
                report_lines.extend([
                    f"### {severity_emoji} Finding #{idx}: {meta.title}",
                    "",
                    "| Attribute | Value |",
                    "|-----------|-------|",
                    f"| **Severity** | {cvss['severity']} |",
                    f"| **CVSS Score** | **{cvss['base_score']}** / 10.0 |",
                    f"| **CVSS Vector** | `{cvss['vector_string']}` |",
                    f"| **OWASP** | {meta.owasp_category} |",
                    f"| **CWE** | {meta.cwe_id} |",
                    f"| **Target** | `{vf.get('target', target_domain)}` |",
                    f"| **Evidence Hash** | `{vf.get('hash_id', 'N/A')}` |",
                    f"| **Confidence** | {vf.get('confidence_score', 0) * 100:.0f}% |",
                    f"| **Verification Status** | {'Verified by Critic Engine' if vf.get('is_verified') else 'Unverified'} |",
                    "",
                    "#### Description",
                    "",
                    f"{meta.description}",
                    "",
                    "#### Impact",
                    "",
                    self._generate_impact_statement(vuln_type, cvss),
                    "",
                ])

                if verification_reason:
                    report_lines.extend([
                        "#### Verification Notes",
                        "",
                        verification_reason,
                        "",
                    ])

                if evidence_quality:
                    quality_summary = ", ".join([
                        f"target_url={'yes' if evidence_quality.get('has_target_url') else 'no'}",
                        f"reasoning={'yes' if evidence_quality.get('has_reasoning') else 'no'}",
                        f"findings={'yes' if evidence_quality.get('has_findings') else 'no'}",
                        f"http_exchanges={'yes' if evidence_quality.get('has_evidence_exchanges') else 'no'}",
                    ])
                    report_lines.extend([
                        "#### Evidence Quality",
                        "",
                        f"`{quality_summary}`",
                        "",
                    ])

                report_lines.extend([
                    "#### Steps to Reproduce",
                    "",
                    self._generate_reproduction_steps(vf, vuln_type),
                    "",
                ])

                # HTTP Request/Response Evidence
                evidence = vf.get("evidence", {}) if isinstance(vf.get("evidence"), dict) else {}
                evidence_exchanges = evidence.get("evidence_exchanges", [])
                if evidence_exchanges and isinstance(evidence_exchanges, list):
                    report_lines.extend([
                        "#### HTTP Evidence",
                        "",
                    ])
                    for ex_idx, exch in enumerate(evidence_exchanges[:2], 1):
                        if isinstance(exch, dict):
                            req = exch.get("request", {})
                            resp = exch.get("response", {})
                            if req:
                                report_lines.extend([
                                    f"**Request {ex_idx}:**",
                                    "```http",
                                    f"{req.get('method', 'GET')} {req.get('url', '')} HTTP/1.1",
                                ])
                                for hk, hv in (req.get("headers", {}) or {}).items():
                                    report_lines.append(f"{hk}: {hv}")
                                if req.get("body"):
                                    report_lines.extend(["", req["body"]])
                                report_lines.extend(["```", ""])

                            if resp:
                                report_lines.extend([
                                    f"**Response {ex_idx}:**",
                                    "```http",
                                    f"HTTP/1.1 {resp.get('status_code', '?')}",
                                ])
                                for hk, hv in list((resp.get("headers", {}) or {}).items())[:10]:
                                    report_lines.append(f"{hk}: {hv}")
                                body_preview = (resp.get("body_text", "") or "")[:500]
                                if body_preview:
                                    report_lines.extend(["", body_preview])
                                report_lines.extend(["```", ""])

                # cURL PoC
                curl_poc = self._generate_curl_poc(vf, target_domain)
                if curl_poc:
                    report_lines.extend([
                        "#### Proof of Concept (cURL)",
                        "```bash",
                        curl_poc,
                        "```",
                        "",
                    ])

                # Remediation
                report_lines.extend([
                    "#### Remediation",
                    "",
                    f"{meta.remediation_guidance}",
                    "",
                    "---",
                    "",
                ])
        else:
            report_lines.extend([
                "## Findings",
                "",
                "> No verified vulnerabilities found in this assessment iteration.",
                "> This does not guarantee the absence of vulnerabilities.",
                "",
                "---",
                "",
            ])

        # ───── Reconnaissance Summary ─────
        report_lines.extend([
            "## Reconnaissance Summary",
            "",
            "### Discovered Assets",
            "| Asset | Type |",
            "|-------|------|",
        ])
        for a in assets[:50]:
            report_lines.append(f"| `{a.canonical_name}` | {a.asset_type} |")

        # ───── Hypotheses ─────
        report_lines.extend([
            "",
            "### Research Hypotheses",
            "| # | Hypothesis | Priority | Confidence | Capabilities |",
            "|---|-----------|----------|------------|-------------|",
        ])
        for idx, h in enumerate(plan.ordered_hypotheses[:20], 1):
            caps = ", ".join(h.required_capabilities[:3])
            report_lines.append(f"| {idx} | {h.title} | {h.priority} | {h.confidence:.0%} | {caps} |")

        report_lines.extend([
            "",
            "---",
            "",
            "## Methodology",
            "",
            "1. **Passive Reconnaissance**: Certificate Transparency logs, DNS resolution, technology fingerprinting",
            "2. **Active Crawling**: Endpoint discovery, form enumeration, JavaScript file mining",
            "3. **Endpoint Classification**: Dynamic mapping of discovered endpoints to vulnerability agents",
            "4. **Hypothesis-Driven Testing**: Priority-ranked security hypotheses with capability-based agent execution",
            "5. **Adversarial Verification**: Multi-layer falsification (static asset filter, soft-404 detection, active unauthenticated re-test)",
            "6. **Evidence Preservation**: SHA-256 content-addressable evidence bundles",
            "",
            "---",
            "",
            "*Report generated by PenFlow Security Research Operating System*",
        ])

        return "\n".join(report_lines)

    def _generate_impact_statement(self, vuln_type: str, cvss: Dict) -> str:
        """Generate impact statement based on vulnerability type."""
        impacts = {
            "id_access_analysis": "An attacker with low-privilege access can enumerate and access "
                                  "other users' data by manipulating object identifiers, leading to "
                                  "unauthorized data exposure of sensitive personal information.",
            "authorization": "Broken authorization controls allow an attacker to perform actions "
                            "or access resources beyond their intended privilege level, potentially "
                            "leading to full account takeover or data breach.",
            "bola_check": "Broken Object Level Authorization allows any authenticated user to access "
                          "other users' objects by tampering with resource identifiers in API calls.",
            "bfla_analysis": "Broken Function Level Authorization allows attackers to invoke "
                            "administrative or privileged functions, potentially compromising "
                            "the entire application's security model.",
            "graphql_introspection": "Exposed GraphQL introspection reveals the complete API schema "
                                     "including all types, queries, and mutations, enabling targeted attacks.",
            "mass_assignment_analysis": "Mass assignment vulnerability allows attackers to modify "
                                        "restricted fields (e.g., role, balance, permissions) by "
                                        "injecting additional parameters in requests.",
            "oauth_misconfiguration": "OAuth misconfiguration can lead to authorization code theft, "
                                      "token leakage, or account takeover through redirect manipulation.",
            "jwt_validation": "JWT validation bypass allows attackers to forge authentication tokens, "
                             "potentially achieving full authentication bypass or privilege escalation.",
            "cors_misconfiguration": "CORS misconfiguration allows attacker-controlled origins to read "
                                     "sensitive API responses, enabling cross-origin data theft.",
            "ssrf_analysis": "Server-Side Request Forgery allows an attacker to make the server "
                            "send requests to internal services, potentially accessing cloud metadata, "
                            "internal APIs, or sensitive infrastructure.",
            "race_condition_analysis": "Race condition allows an attacker to exploit time-of-check to "
                                       "time-of-use (TOCTOU) windows, potentially duplicating financial "
                                       "transactions or bypassing rate limits.",
            "nosql_injection": "NoSQL operator injection allows an attacker to bypass authentication logic, "
                               "extract sensitive records from document databases, or tamper with queries.",
            "sql_injection": "SQL injection in API parameters allows an attacker to extract entire database contents, "
                             "modify data, or execute administrative operations on the database server.",
            "ssti_analysis": "Server-Side Template Injection allows an attacker to execute arbitrary template directives "
                             "and achieve Remote Code Execution (RCE) on the underlying operating system.",
            "command_injection": "OS Command Injection allows an attacker to execute arbitrary shell commands with the "
                                 "privileges of the web application server process, leading to complete server takeover.",
            "rate_limit_bypass": "Rate limit bypass allows automated brute-force attacks, credential stuffing, and resource "
                                 "exhaustion by circumventing IP-based and path-based rate limiting controls.",
            "info_disclosure": "Exposed debug and actuator endpoints leak sensitive configuration variables, API keys, "
                               "database connection strings, and application topology to unauthorized users.",
            "open_redirect": "Open redirect vulnerabilities allow attackers to trick users into visiting malicious phishing "
                             "sites or redirect OAuth authorization codes and tokens to attacker-controlled servers.",
            "websocket_auth_flaw": "Cross-Site WebSocket Hijacking (CSWSH) allows malicious websites visited by an authenticated "
                                   "user to initiate unauthorized WebSocket connections and intercept bidirectional data.",
            "http_smuggling": "HTTP Request Smuggling allows attackers to bypass security filters, poison shared proxy caches, "
                              "and hijack other users' HTTP requests and credentials.",
        }
        base = impacts.get(vuln_type, "This vulnerability may allow unauthorized access or data exposure.")
        return f"{base}\n\n**CVSS Impact Subscore:** {cvss.get('impact_subscore', 'N/A')} | " \
               f"**Exploitability Subscore:** {cvss.get('exploitability_subscore', 'N/A')}"

    def _generate_reproduction_steps(self, finding: Dict, vuln_type: str) -> str:
        """Generate step-by-step reproduction instructions."""
        target = finding.get("target", "target.com")
        clean_target = target.strip()
        for prefix in ("https://", "http://"):
            while clean_target.startswith(prefix):
                clean_target = clean_target[len(prefix):]
        clean_target = clean_target.split("/")[0].split("?")[0]

        evidence = finding.get("evidence", {}) if isinstance(finding.get("evidence"), dict) else {}
        target_url = evidence.get("target_url") or finding.get("target_url") or f"https://{clean_target}/api/endpoint"
        while "https://https://" in target_url:
            target_url = target_url.replace("https://https://", "https://")
        while "http://http://" in target_url:
            target_url = target_url.replace("http://http://", "http://")
        if target_url.endswith("//"):
            target_url = target_url.rstrip("/")

        steps = {
            "id_access_analysis": [
                f"1. Authenticate as User A and note your session token",
                f"2. Access the target endpoint: `{target_url}`",
                f"3. Observe the response containing User A's data",
                f"4. Change the object identifier (e.g., `id=101` → `id=102`)",
                f"5. Observe that User B's data is returned without authorization check",
            ],
            "bfla_analysis": [
                f"1. Authenticate as a regular (non-admin) user",
                f"2. Identify admin-only endpoints via API documentation or introspection",
                f"3. Send request to the admin endpoint with regular user's token",
                f"4. Observe that the request succeeds without proper role verification",
            ],
            "mass_assignment_analysis": [
                f"1. Capture a legitimate profile update request",
                f"2. Add privileged fields to the request body (e.g., `\"role\": \"admin\"`)",
                f"3. Submit the modified request",
                f"4. Verify that the privileged field was accepted and applied",
            ],
            "nosql_injection": [
                f"1. Intercept request to `{target_url}` containing JSON parameters",
                f"2. Replace scalar value with MongoDB query operator (e.g. `\"password\": {{{{ \"$ne\": null }}}}`)",
                f"3. Forward request and observe authentication bypass or unconstrained data leakage",
            ],
            "sql_injection": [
                f"1. Send request to `{target_url}` with injection payload in parameter",
                f"2. Observe SQL error disclosure or boolean logic difference in response",
                f"3. Confirm parameterized extraction via UNION or boolean blind techniques",
            ],
            "ssti_analysis": [
                f"1. Submit expression polyglot `${{{{7*7}}}}` or `{{{{7*7}}}}` in dynamic input field",
                f"2. Request rendered output page or inspect returned payload",
                f"3. Observe evaluated mathematical result `49` confirming template engine execution",
            ],
            "command_injection": [
                f"1. Inject command separator `| id` or `; id` into target parameter",
                f"2. Observe system execution output `uid=` and `gid=` in response body",
            ],
            "rate_limit_bypass": [
                f"1. Exceed normal request limit to trigger 429 Too Many Requests",
                f"2. Append spoofed header `X-Forwarded-For: 10.0.0.X` or `X-Real-IP` to consecutive requests",
                f"3. Observe that requests succeed (200 OK) bypassing anti-automation limits",
            ],
            "info_disclosure": [
                f"1. Send GET request to discovered route `{target_url}`",
                f"2. Observe exposed environment configuration, JVM metrics, or private API schema",
            ],
            "open_redirect": [
                f"1. Navigate to target URL with redirect parameter set to `https://attacker.com`",
                f"2. Observe HTTP 302/301 redirect with `Location: https://attacker.com`",
            ]
        }

        default_steps = [
            f"1. Navigate to `{target_url}`",
            f"2. Intercept the request with a proxy (Burp Suite/Caido)",
            f"3. Apply the modification described in the evidence section",
            f"4. Forward the request and observe the response",
            f"5. Compare with the expected authorized behavior",
        ]

        step_list = steps.get(vuln_type, default_steps)
        return "\n".join(step_list)

    def _generate_curl_poc(self, finding: Dict, target_domain: str) -> str:
        """Generate a cURL command for reproducing the finding."""
        clean_domain = target_domain.strip()
        for prefix in ("https://", "http://"):
            while clean_domain.startswith(prefix):
                clean_domain = clean_domain[len(prefix):]
        clean_domain = clean_domain.split("/")[0].split("?")[0]

        evidence = finding.get("evidence", {}) if isinstance(finding.get("evidence"), dict) else {}
        target_url = evidence.get("target_url", "")
        while "https://https://" in target_url:
            target_url = target_url.replace("https://https://", "https://")
        while "http://http://" in target_url:
            target_url = target_url.replace("http://http://", "http://")

        exchanges = evidence.get("evidence_exchanges", [])

        if exchanges and isinstance(exchanges, list) and exchanges[0]:
            exch = exchanges[0]
            req = exch.get("request", {})
            if req:
                method = req.get("method", "GET")
                url = req.get("url", target_url or f"https://{clean_domain}/api/endpoint")
                while "https://https://" in url:
                    url = url.replace("https://https://", "https://")
                while "http://http://" in url:
                    url = url.replace("http://http://", "http://")
                headers = req.get("headers", {})
                body = req.get("body", "")

                parts = [f'curl -i -s -k -X {method}']
                for hk, hv in headers.items():
                    if hk.lower() not in ("host", "content-length"):
                        parts.append(f"  -H '{hk}: {hv}'")
                if body:
                    parts.append(f"  -d '{body}'")
                parts.append(f"  '{url}'")
                return " \\\n".join(parts)

        payload_info = evidence.get("payload") or finding.get("payload")
        if payload_info:
            target_endpoint = target_url or f"https://{clean_domain}/api/v1/search"
            while "https://https://" in target_endpoint:
                target_endpoint = target_endpoint.replace("https://https://", "https://")
            if isinstance(payload_info, dict):
                import json
                payload_str = json.dumps(payload_info)
                return f"curl -i -s -k -X POST -H 'Content-Type: application/json' -d '{payload_str}' '{target_endpoint}'"
            elif isinstance(payload_info, str):
                return f"curl -i -s -k -X POST -H 'Content-Type: application/json' -d '{payload_info}' '{target_endpoint}'"

        if target_url:
            return f'curl -i -s -k "{target_url}"'
        return f'curl -i -s -k "https://{clean_domain}/"'

    def save_report(self, target_domain: str, report_content: str,
                    output_dir: str = "reports") -> str:
        ensure_dir(output_dir)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        file_path = f"{output_dir}/penflow_{target_domain.replace('.', '_')}_{timestamp}.md"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(report_content)
        return file_path

