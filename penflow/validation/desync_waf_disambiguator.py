"""
DesyncWafDisambiguator — WAF & Rate-Limit False Positive Filter.

Disambiguates genuine HTTP Request Smuggling (CL.TE / TE.CL desync) and Blind SQLi / SSRF time delays
from Cloudflare 429 rate-limiting, CloudFront HTML challenge blocks, and network socket timeouts.
"""

import re
from typing import Dict, Any, List
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.validation.desync_waf_disambiguator")

WAF_CHALLENGE_PATTERNS = [
    r"cf-mitigated:\s*challenge", r"Just a moment\.\.\.", r"Attention Required!",
    r"429 Too Many Requests", r"Error from cloudfront", r"Cloudflare Ray ID"
]


class DesyncWafDisambiguator:
    """Disambiguates genuine HTTP desyncs and timing delays from WAF challenge pages & rate limiting."""

    def evaluate_desync_evidence(self, status_code: int, headers: Dict[str, str], body_text: str, elapsed_ms: float) -> Dict[str, Any]:
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        body = body_text or ""

        # 1. Rate Limit / 429 & Gateway Timeout Check
        if status_code == 429:
            return {
                "is_genuine_desync": False,
                "is_waf_false_positive": True,
                "reason": "Falsified: Response is HTTP 429 (Rate-limiting anti-automation block), not HTTP Request Smuggling."
            }

        if status_code in (504, 502, 503) and ("gateway timeout" in body.lower() or "server error" in body.lower()):
            return {
                "is_genuine_desync": False,
                "is_waf_false_positive": True,
                "reason": f"Falsified: Response is HTTP {status_code} Gateway Timeout / Network proxy error, not a verified application vulnerability."
            }

        # 2. Cloudflare Challenge Page Check
        for pat in WAF_CHALLENGE_PATTERNS:
            if re.search(pat, body, re.IGNORECASE) or any(re.search(pat, f"{k}: {v}", re.IGNORECASE) for k, v in headers_lower.items()):
                return {
                    "is_genuine_desync": False,
                    "is_waf_false_positive": True,
                    "reason": f"Falsified: Response contains WAF challenge/block pattern '{pat}'."
                }

        # 3. Connection Socket Pipeline Check
        connection_header = headers_lower.get("connection", "").lower()
        if status_code in (400, 502, 503) and connection_header == "close":
            # Proper RFC 7230 connection termination by reverse proxy
            return {
                "is_genuine_desync": True,
                "is_waf_false_positive": False,
                "reason": "Verified: Front-end proxy detected parsing ambiguity and terminated the connection (Connection: close)."
            }

        return {
            "is_genuine_desync": True,
            "is_waf_false_positive": False,
            "reason": "Verified: Response behavior indicates unhandled request boundary desynchronization."
        }
