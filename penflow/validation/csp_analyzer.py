import re
from typing import Dict, Any, List
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.validation.csp_analyzer")

class CSPPolicyAnalyzer:
    """
    Parses and evaluates Content-Security-Policy (CSP) headers for security risks and bypasses.
    """
    def analyze_csp(self, csp_string: str) -> Dict[str, Any]:
        directives: Dict[str, List[str]] = {}
        findings: List[Dict[str, Any]] = []

        if not csp_string:
            return {"directives": directives, "findings": [{"issue": "empty_csp", "severity": "medium", "description": "Empty CSP header"}]}

        # Parse directives
        parts = csp_string.split(";")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            dname = tokens[0].lower()
            dval = tokens[1:] if len(tokens) > 1 else []
            directives[dname] = dval

        # Risk Analysis
        script_src = directives.get("script-src", directives.get("default-src", []))

        if "'unsafe-inline'" in script_src:
            findings.append({
                "issue": "csp_unsafe_inline",
                "severity": "high",
                "description": "CSP script-src contains 'unsafe-inline', weakening XSS protections."
            })

        if "'unsafe-eval'" in script_src:
            findings.append({
                "issue": "csp_unsafe_eval",
                "severity": "medium",
                "description": "CSP script-src contains 'unsafe-eval', allowing dynamic evaluation."
            })

        if "*" in script_src:
            findings.append({
                "issue": "csp_wildcard_script",
                "severity": "high",
                "description": "CSP script-src contains wildcard '*', allowing script loading from any origin."
            })

        return {
            "directives": directives,
            "findings": findings,
            "is_risky": len(findings) > 0
        }
