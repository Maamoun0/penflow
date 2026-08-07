"""
SensitiveDataExfiltrator & CORSSensitiveDataVerifier — PII & Token Inspection Engine.

Analyzes response bodies to verify if cross-origin data extraction leaks sensitive user data
(PII, JWT tokens, session IDs, financial data, or private API endpoints) vs public static HTML.
"""

import re
import json
from typing import Dict, Any, List

SENSITIVE_PATTERNS = {
    "jwt_token": [r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"],
    "oauth_bearer": [r"\"bearer_token\":\s*\"[^\"]+\"", r"\"access_token\":\s*\"[^\"]+\""],
    "email_address": [r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"],
    "user_id_field": [r"\"user_?id\":\s*\"?[0-9a-fA-F-]+\"?", r"\"account_?id\":\s*\"?[0-9a-fA-F-]+\"?"],
    "financial_data": [r"\"balance\":\s*\d+", r"\"portfolio\":", r"\"bank_account\":", r"\"credit_card\":"],
    "session_cookie": [r"\"session_?id\":\s*\"[^\"]+\"", r"\"auth_key\":\s*\"[^\"]+\""]
}

PUBLIC_HTML_PATTERNS = [
    r"<!DOCTYPE html>", r"<html", r"<head>", r"Error from cloudfront",
    r"403 Forbidden", r"404 Not Found", r"Too Many Requests", r"Challenge Required"
]


class CORSSensitiveDataVerifier:
    """Evaluates HTTP response bodies for CORS data exfiltration proof."""

    def inspect_response(self, status_code: int, headers: Dict[str, str], body: str) -> Dict[str, Any]:
        body_str = body or ""
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        content_type = headers_lower.get("content-type", "").lower()

        detected_matches: Dict[str, List[str]] = {}
        score = 0.0

        # Check for sensitive regex matches
        for category, patterns in SENSITIVE_PATTERNS.items():
            matches = []
            for pat in patterns:
                found = re.findall(pat, body_str, re.IGNORECASE)
                if found:
                    matches.extend(found[:3])
            if matches:
                detected_matches[category] = matches
                score += 0.25

        # JSON response check
        is_json = "application/json" in content_type
        if is_json and not any(re.search(pat, body_str, re.IGNORECASE) for pat in PUBLIC_HTML_PATTERNS):
            score += 0.2

        # Public HTML check penalty
        is_public_html = any(re.search(pat, body_str, re.IGNORECASE) for pat in PUBLIC_HTML_PATTERNS)
        if is_public_html:
            score = max(0.0, score - 0.5)

        score = min(1.0, score)
        has_exfiltration_impact = score >= 0.40 and not is_public_html

        return {
            "has_exfiltration_impact": has_exfiltration_impact,
            "data_sensitivity_score": round(score, 2),
            "is_json_response": is_json,
            "is_public_html": is_public_html,
            "detected_sensitive_categories": list(detected_matches.keys()),
            "evidence_snippets": detected_matches,
            "reasoning": (
                f"Proven Exfiltration Impact: Extracted {list(detected_matches.keys())} in JSON API response."
                if has_exfiltration_impact
                else "Theoretical/Public Response: No sensitive PII or authentication tokens present in response body."
            )
        }
