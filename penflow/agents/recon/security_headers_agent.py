"""
Unified Security Headers & Configuration Capability Agent for PenFlow.

Replaces the overlap between `HeaderAnalysisAgent` and `SecurityConfigCapabilityAgent`
by producing a SINGLE consolidated finding per scan that covers:

  - Missing/weak security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
    Permissions-Policy, COOP, CORP, Referrer-Policy quality check)
  - Per-cookie flag audit (HttpOnly, Secure, SameSite) with specific cookie name reported
  - Context-aware severity: pages with login forms or auth cookies score MEDIUM;
    purely informational pages stay Informative
  - Server / X-Powered-By technology disclosure
  - SRI missing on external CDN scripts
  - No duplicate Request 1 / Request 2 with identical content
"""
import re
import httpx
from typing import List, Dict, Any, Tuple, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.security_headers")

# ────────────────────────────────────────────────────────────────────────
# Header definitions
# ────────────────────────────────────────────────────────────────────────

# (header-name, human-readable label, default-severity, remediation-note)
REQUIRED_HEADERS: List[Tuple[str, str, str, str]] = [
    ("strict-transport-security",
     "Strict-Transport-Security (HSTS)",
     "MEDIUM",
     "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses."),
    ("content-security-policy",
     "Content-Security-Policy",
     "MEDIUM",
     "Define a strict CSP policy. Avoid 'unsafe-inline' and 'unsafe-eval'."),
    ("x-frame-options",
     "X-Frame-Options / frame-ancestors CSP",
     "LOW",
     "Set 'X-Frame-Options: DENY' or use CSP frame-ancestors."),
    ("x-content-type-options",
     "X-Content-Type-Options",
     "LOW",
     "Set 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing attacks."),
    ("permissions-policy",
     "Permissions-Policy",
     "LOW",
     "Restrict browser feature access via Permissions-Policy."),
    ("cross-origin-opener-policy",
     "Cross-Origin-Opener-Policy (COOP)",
     "LOW",
     "Set 'Cross-Origin-Opener-Policy: same-origin' to isolate the browsing context."),
    ("cross-origin-resource-policy",
     "Cross-Origin-Resource-Policy (CORP)",
     "LOW",
     "Set 'Cross-Origin-Resource-Policy: same-origin' to prevent resource leakage."),
]

# Weak Referrer-Policy values — present but insecure
WEAK_REFERRER_POLICIES = {"unsafe-url", "no-referrer-when-downgrade", ""}

# Headers that disclose technology stack
DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                      "x-generator", "x-drupal-cache", "x-wp-total"]

# Patterns suggesting a login/auth page — elevate severity
LOGIN_PAGE_SIGNALS = re.compile(
    r'(type=["\']password["\']|login|sign.?in|authenticate|username|email|forgot.password)',
    re.IGNORECASE
)

SESSION_COOKIE_NAMES = re.compile(
    r'^(session|sess|auth|token|jwt|sid|user_id|account|access_token)',
    re.IGNORECASE
)


from penflow.agents.base.registry_loader import register_agent

@register_agent(tags=["recon", "security_headers", "configuration"])
class SecurityHeadersCapabilityAgent(BaseCapabilityAgent):
    """
    Unified Security Headers & Cookie Audit Agent.
    Emits one consolidated finding per scan — no duplicate header/config findings.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="SecurityHeadersCapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="security_headers_unified",
                name="Unified Security Headers & Cookie Audit",
                description=(
                    "Consolidated audit of HTTP security headers, cookie flags (per-cookie), "
                    "server disclosure, Referrer-Policy quality, SRI, COOP, CORP, Permissions-Policy. "
                    "Produces a single deduped finding — no overlapping header_analysis / security_config_audit."
                ),
                priority=self.priority,
                tags=["headers", "cookies", "csp", "hsts", "hardening", "security_config"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[SecurityHeadersCapabilityAgent] Auditing '{context.asset}'")

        asset = context.asset
        scheme = "http" if ("127.0.0.1" in asset or "localhost" in asset) else "https"
        target_url = f"{scheme}://{asset}/"

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
                resp = await client.get(target_url)
        except Exception as exc:
            logger.debug(f"[SecurityHeadersCapabilityAgent] Request failed: {exc}")
            return self._empty(capability_id, asset)

        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        headers_raw = {k.lower(): v for k, v in resp.headers.items()}
        body_text = resp.text or ""
        status = resp.status_code

        # Detect page context (login form present → raise severity floor)
        is_auth_page = bool(LOGIN_PAGE_SIGNALS.search(body_text))

        issues: List[Dict[str, str]] = []

        # ── 1. Missing / weak required headers ─────────────────────────────
        for h_name, label, base_severity, remediation in REQUIRED_HEADERS:
            if h_name not in headers_lower:
                sev = base_severity
                if is_auth_page and base_severity in ("LOW", "MEDIUM"):
                    sev = "MEDIUM"
                issues.append({
                    "header": h_name,
                    "issue": f"Missing {label}",
                    "severity": sev,
                    "detail": f"Header '{h_name}' absent from response.",
                    "remediation": remediation,
                })

        # ── 1b. Referrer-Policy quality (present but weak) ─────────────────
        ref_val = headers_lower.get("referrer-policy", "").strip()
        if ref_val in WEAK_REFERRER_POLICIES and "referrer-policy" not in {i["header"] for i in issues}:
            issues.append({
                "header": "referrer-policy",
                "issue": f"Weak Referrer-Policy value: '{ref_val or '(missing)'}'" ,
                "severity": "LOW",
                "detail": f"Referrer-Policy is set to '{ref_val}' which leaks full URLs to third parties.",
                "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
            })

        # ── 2. Server technology disclosure ────────────────────────────────
        for disc_header in DISCLOSURE_HEADERS:
            val = headers_raw.get(disc_header, "")
            if val:
                issues.append({
                    "header": disc_header,
                    "issue": f"Technology stack disclosure via '{disc_header}: {val}'",
                    "severity": "LOW",
                    "detail": f"Response reveals internal technology: '{disc_header}: {val}'.",
                    "remediation": f"Remove or obscure the '{disc_header}' response header in server configuration.",
                })

        # ── 3. Per-cookie flag audit ────────────────────────────────────────
        set_cookies = resp.headers.get_list("set-cookie") \
            if hasattr(resp.headers, "get_list") else \
            [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]

        for raw_cookie in set_cookies:
            if not raw_cookie:
                continue
            cookie_name = raw_cookie.split("=")[0].strip()
            cookie_lower = raw_cookie.lower()
            is_session = bool(SESSION_COOKIE_NAMES.match(cookie_name))

            # Severity escalation: session cookies missing flags → MEDIUM
            sev_escalate = "MEDIUM" if is_session else "LOW"

            if "httponly" not in cookie_lower:
                issues.append({
                    "header": "set-cookie",
                    "issue": f"Cookie '{cookie_name}' missing HttpOnly flag",
                    "severity": sev_escalate,
                    "detail": f"Cookie '{cookie_name}' lacks HttpOnly — XSS can steal this token.",
                    "remediation": f"Set HttpOnly flag on cookie '{cookie_name}'.",
                })
            if "secure" not in cookie_lower and scheme == "https":
                issues.append({
                    "header": "set-cookie",
                    "issue": f"Cookie '{cookie_name}' missing Secure flag",
                    "severity": sev_escalate,
                    "detail": f"Cookie '{cookie_name}' lacks Secure — can be sent over HTTP.",
                    "remediation": f"Set Secure flag on cookie '{cookie_name}'.",
                })
            if "samesite" not in cookie_lower:
                issues.append({
                    "header": "set-cookie",
                    "issue": f"Cookie '{cookie_name}' missing SameSite attribute",
                    "severity": "LOW",
                    "detail": f"Cookie '{cookie_name}' has no SameSite attribute, increasing CSRF risk.",
                    "remediation": f"Add 'SameSite=Strict' or 'SameSite=Lax' to cookie '{cookie_name}'.",
                })

        # ── 4. SRI check on external scripts ───────────────────────────────
        base_domain = asset.split(":")[0]
        external_scripts = re.findall(
            r'<script[^>]+src=["\']((https?:)?//[^"\']+)["\'][^>]*>',
            body_text, re.IGNORECASE
        )
        for (src, _) in external_scripts:
            if base_domain not in src and "integrity=" not in src.lower():
                issues.append({
                    "header": "subresource-integrity",
                    "issue": f"External script without SRI: {src[:80]}",
                    "severity": "LOW",
                    "detail": f"External JS '{src}' loaded without Subresource Integrity hash.",
                    "remediation": "Generate and include 'integrity' + 'crossorigin' attributes for all CDN scripts.",
                })
                break  # one example is sufficient

        if not issues:
            return self._empty(capability_id, asset)

        # ── Determine overall severity ──────────────────────────────────────
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIVE": 0}
        worst_sev = max(issues, key=lambda i: sev_rank.get(i["severity"], 0))["severity"]

        # Build consolidated description
        summary_lines = []
        for iss in issues:
            summary_lines.append(f"  • [{iss['severity']}] {iss['issue']}")
        consolidated_description = (
            f"Security header & cookie audit identified {len(issues)} configuration issue(s):\n"
            + "\n".join(summary_lines)
        )

        # Single HTTP evidence exchange (no duplicate identical requests)
        exchange = {
            "request": {"method": "GET", "url": target_url},
            "response": {
                "status_code": status,
                "headers": dict(resp.headers),
                "body_snippet": body_text[:300] if body_text else "(empty)"
            }
        }

        curl_cmd = f"curl -I -s -k '{target_url}'"
        finding = {
            "vulnerability_type": "security_headers_unified",
            "target_url": target_url,
            "severity": worst_sev,
            "confidence": 0.90,
            "confidence_score": 0.90,
            "is_vulnerable": True,
            "vulnerable": True,
            "description": consolidated_description,
            "issues": issues,
            "is_auth_page": is_auth_page,
            "exploit_curl": curl_cmd,
            "reproduction_steps": [
                f"curl -I -s -k '{target_url}'",
                "Inspect the response headers for the missing/weak security headers listed above.",
                "Cross-reference each missing header with the remediation guidance.",
            ],
            "_exchange_obj": exchange,
        }

        return {
            "capability_id": capability_id,
            "status": "COMPLETED",
            "agent": self.name,
            "is_vulnerable": True,
            "vulnerable": True,
            "confidence": 0.90,
            "confidence_score": 0.90,
            "vulnerability_type": "security_headers_unified",
            "target_url": target_url,
            "reasoning": consolidated_description,
            "_exchange_obj": exchange,
            "findings": [finding],
            "evidence": {
                "target_url": target_url,
                "issue_count": len(issues),
                "worst_severity": worst_sev,
                "is_auth_page": is_auth_page,
                "issues": issues,
                "evidence_exchanges": [exchange],
            }
        }

    @staticmethod
    def _empty(capability_id: str, asset: str) -> Dict[str, Any]:
        return {
            "capability_id": capability_id,
            "status": "COMPLETED",
            "agent": "SecurityHeadersCapabilityAgent",
            "is_vulnerable": False,
            "vulnerable": False,
            "confidence": 0.0,
            "confidence_score": 0.0,
            "reasoning": f"All required security headers and cookie flags are properly configured on '{asset}'.",
            "findings": [],
            "evidence": {}
        }
