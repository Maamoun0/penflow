"""
SecurityHeadersAuditor — OWASP-Complete HTTP Security Headers Analysis for PenFlow.

Performs 12-point OWASP security headers audit plus server/tech version disclosure detection.
Each finding includes severity, CWE reference, and remediation guidance.
"""
import re
import httpx
from typing import Dict, Any, List, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.security_headers_audit")

# OWASP recommended headers and their expected values/patterns
SECURITY_HEADER_CHECKS = [
    {
        "id": "missing_hsts",
        "header": "strict-transport-security",
        "severity": "high",
        "cwe": "CWE-319",
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "description": "HSTS header is absent. Browsers may downgrade to HTTP, enabling MITM and SSL-stripping attacks.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    {
        "id": "weak_hsts_maxage",
        "header": "strict-transport-security",
        "severity": "medium",
        "cwe": "CWE-319",
        "title": "HSTS max-age Below Recommended Minimum (1 Year)",
        "description": "HSTS max-age is below 31536000 seconds (1 year), reducing protection window.",
        "remediation": "Set max-age to at least 31536000 (1 year).",
        "conditional": True,
    },
    {
        "id": "missing_clickjacking_protection",
        "header": "x-frame-options",
        "severity": "medium",
        "cwe": "CWE-1021",
        "title": "Missing Clickjacking Protection (X-Frame-Options / CSP frame-ancestors)",
        "description": "Neither X-Frame-Options nor CSP frame-ancestors directive is set. Clickjacking possible.",
        "remediation": "Add: X-Frame-Options: DENY or include frame-ancestors 'none' in CSP.",
    },
    {
        "id": "missing_nosniff",
        "header": "x-content-type-options",
        "severity": "low",
        "cwe": "CWE-430",
        "title": "Missing X-Content-Type-Options: nosniff",
        "description": "Browsers may MIME-sniff responses, enabling content injection attacks.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    {
        "id": "missing_csp",
        "header": "content-security-policy",
        "severity": "high",
        "cwe": "CWE-693",
        "title": "Missing Content Security Policy (CSP)",
        "description": "No CSP header. XSS attacks and data injection have no browser-level barrier.",
        "remediation": "Define a strict CSP: default-src 'self'; script-src 'self'; object-src 'none'",
    },
    {
        "id": "csp_unsafe_inline",
        "header": "content-security-policy",
        "severity": "high",
        "cwe": "CWE-693",
        "title": "CSP Allows 'unsafe-inline' Scripts",
        "description": "'unsafe-inline' in script-src defeats CSP XSS protection completely.",
        "remediation": "Remove 'unsafe-inline'; use nonces or hashes instead.",
        "conditional": True,
    },
    {
        "id": "csp_unsafe_eval",
        "header": "content-security-policy",
        "severity": "medium",
        "cwe": "CWE-693",
        "title": "CSP Allows 'unsafe-eval'",
        "description": "'unsafe-eval' permits eval() and similar — allows DOM-based XSS escalation.",
        "remediation": "Remove 'unsafe-eval' from script-src.",
        "conditional": True,
    },
    {
        "id": "csp_wildcard_source",
        "header": "content-security-policy",
        "severity": "medium",
        "cwe": "CWE-693",
        "title": "CSP Uses Wildcard (*) Source",
        "description": "Wildcard (*) in CSP directive allows loading resources from any origin.",
        "remediation": "Enumerate specific trusted origins instead of using wildcards.",
        "conditional": True,
    },
    {
        "id": "missing_referrer_policy",
        "header": "referrer-policy",
        "severity": "low",
        "cwe": "CWE-200",
        "title": "Missing Referrer-Policy Header",
        "description": "Full Referer URL sent to third-party sites, leaking sensitive path/query info.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "id": "missing_permissions_policy",
        "header": "permissions-policy",
        "severity": "low",
        "cwe": "CWE-284",
        "title": "Missing Permissions-Policy Header",
        "description": "No restrictions on browser feature access (camera, microphone, geolocation, etc.).",
        "remediation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
    {
        "id": "missing_coop",
        "header": "cross-origin-opener-policy",
        "severity": "medium",
        "cwe": "CWE-346",
        "title": "Missing Cross-Origin-Opener-Policy (COOP)",
        "description": "Without COOP, cross-origin windows can access the opener's browsing context.",
        "remediation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    {
        "id": "missing_coep",
        "header": "cross-origin-embedder-policy",
        "severity": "low",
        "cwe": "CWE-346",
        "title": "Missing Cross-Origin-Embedder-Policy (COEP)",
        "description": "Required for enabling cross-origin isolation (SharedArrayBuffer protection).",
        "remediation": "Add: Cross-Origin-Embedder-Policy: require-corp",
    },
    {
        "id": "cors_wildcard",
        "header": "access-control-allow-origin",
        "severity": "high",
        "cwe": "CWE-942",
        "title": "CORS Wildcard Origin (Access-Control-Allow-Origin: *)",
        "description": "Any origin can read responses from this endpoint — severe if combined with credentials.",
        "remediation": "Restrict to specific trusted origins. Never use '*' with credentials.",
        "conditional": True,
    },
    {
        "id": "server_version_disclosure",
        "header": "server",
        "severity": "low",
        "cwe": "CWE-200",
        "title": "Server Version Disclosed in Header",
        "description": "Exact server software and version is exposed, aiding vulnerability fingerprinting.",
        "remediation": "Strip version from Server header (e.g., 'nginx' not 'nginx/1.18.0').",
        "conditional": True,
    },
    {
        "id": "x_powered_by_disclosure",
        "header": "x-powered-by",
        "severity": "low",
        "cwe": "CWE-200",
        "title": "Technology Stack Disclosed via X-Powered-By",
        "description": "X-Powered-By reveals framework/language version (e.g., PHP/7.4, Express/4.x).",
        "remediation": "Remove X-Powered-By header entirely.",
        "conditional": True,
    },
]

# Severity-to-score mapping for risk scoring
SEVERITY_SCORES = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class SecurityHeadersAuditor:
    """
    OWASP-Complete HTTP Security Headers Auditor (12+ checks).
    Analyses response headers for security misconfigurations with CWE references,
    severity ratings, and specific remediation guidance.
    """

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    async def audit_url(self, target_url: str) -> Dict[str, Any]:
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        findings: List[Dict[str, Any]] = []
        headers_found: Dict[str, str] = {}
        risk_score = 0

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (PenFlow/20.0 Security Research)"}
            ) as client:
                resp = await client.get(target_url)
                headers_found = {k.lower(): v for k, v in resp.headers.items()}

                # 1. HSTS Check (existence + max-age strength)
                hsts_val = headers_found.get("strict-transport-security", "")
                if not hsts_val:
                    findings.append(self._make_finding("missing_hsts"))
                    risk_score += 3
                else:
                    # Check max-age
                    max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts_val, re.IGNORECASE)
                    if max_age_match and int(max_age_match.group(1)) < 31536000:
                        findings.append(self._make_finding(
                            "weak_hsts_maxage",
                            extra=f"Current max-age={max_age_match.group(1)} (minimum: 31536000)"
                        ))
                        risk_score += 2

                # 2. Clickjacking Protection
                xfo = headers_found.get("x-frame-options", "")
                csp_val = headers_found.get("content-security-policy", "")
                has_frame_ancestors = "frame-ancestors" in csp_val.lower()
                if not xfo and not has_frame_ancestors:
                    findings.append(self._make_finding("missing_clickjacking_protection"))
                    risk_score += 2

                # 3. X-Content-Type-Options
                xcto = headers_found.get("x-content-type-options", "").lower()
                if "nosniff" not in xcto:
                    findings.append(self._make_finding("missing_nosniff"))
                    risk_score += 1

                # 4. CSP Analysis
                if not csp_val:
                    findings.append(self._make_finding("missing_csp"))
                    risk_score += 3
                else:
                    csp_lower = csp_val.lower()
                    if "'unsafe-inline'" in csp_lower:
                        findings.append(self._make_finding(
                            "csp_unsafe_inline",
                            extra=f"CSP value: {csp_val[:120]}..."
                        ))
                        risk_score += 3
                    if "'unsafe-eval'" in csp_lower:
                        findings.append(self._make_finding(
                            "csp_unsafe_eval",
                            extra=f"CSP contains 'unsafe-eval'"
                        ))
                        risk_score += 2
                    # Wildcard detection (not in report-uri or nonce context)
                    if re.search(r'(?:script-src|default-src|img-src|connect-src)\s+[^;]*\*', csp_lower):
                        findings.append(self._make_finding(
                            "csp_wildcard_source",
                            extra="Wildcard (*) found in resource directive"
                        ))
                        risk_score += 2

                # 5. Referrer-Policy
                if "referrer-policy" not in headers_found:
                    findings.append(self._make_finding("missing_referrer_policy"))
                    risk_score += 1

                # 6. Permissions-Policy
                if "permissions-policy" not in headers_found and "feature-policy" not in headers_found:
                    findings.append(self._make_finding("missing_permissions_policy"))
                    risk_score += 1

                # 7. COOP
                if "cross-origin-opener-policy" not in headers_found:
                    findings.append(self._make_finding("missing_coop"))
                    risk_score += 2

                # 8. COEP
                if "cross-origin-embedder-policy" not in headers_found:
                    findings.append(self._make_finding("missing_coep"))
                    risk_score += 1

                # 9. CORS wildcard
                acao = headers_found.get("access-control-allow-origin", "")
                if acao.strip() == "*":
                    findings.append(self._make_finding(
                        "cors_wildcard",
                        extra="Access-Control-Allow-Origin: * — any origin may read responses"
                    ))
                    risk_score += 3

                # 10. Server version disclosure
                server_val = headers_found.get("server", "")
                if server_val and re.search(r"[\d.]+", server_val):
                    findings.append(self._make_finding(
                        "server_version_disclosure",
                        extra=f"Server: {server_val}"
                    ))
                    risk_score += 1

                # 11. X-Powered-By disclosure
                xpb = headers_found.get("x-powered-by", "")
                if xpb:
                    findings.append(self._make_finding(
                        "x_powered_by_disclosure",
                        extra=f"X-Powered-By: {xpb}"
                    ))
                    risk_score += 1

        except Exception as e:
            logger.debug(f"[SecurityHeadersAuditor] Failed to audit '{target_url}': {str(e)}")

        # Risk classification
        if risk_score >= 10:
            risk_level = "CRITICAL"
        elif risk_score >= 7:
            risk_level = "HIGH"
        elif risk_score >= 4:
            risk_level = "MEDIUM"
        elif risk_score >= 1:
            risk_level = "LOW"
        else:
            risk_level = "PASS"

        logger.info(
            f"[SecurityHeadersAuditor] Audit complete for '{target_url}': "
            f"{len(findings)} findings, Risk Score={risk_score} ({risk_level})"
        )

        return {
            "url": target_url,
            "headers": headers_found,
            "findings": findings,
            "findings_count": len(findings),
            "risk_score": risk_score,
            "risk_level": risk_level,
        }

    def _make_finding(self, check_id: str, extra: str = "") -> Dict[str, Any]:
        """Build a structured finding dict from the check catalog."""
        for check in SECURITY_HEADER_CHECKS:
            if check["id"] == check_id:
                finding = {
                    "id": check_id,
                    "title": check["title"],
                    "severity": check["severity"],
                    "cwe": check["cwe"],
                    "description": check["description"],
                    "remediation": check["remediation"],
                }
                if extra:
                    finding["detail"] = extra
                return finding
        return {"id": check_id, "severity": "info", "description": "Unknown check"}
