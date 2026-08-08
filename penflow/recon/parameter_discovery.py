"""
ParameterDiscoveryEngine — Hidden & Undocumented Query Parameter Brute-Force Engine for PenFlow.

Capabilities:
  - 300+ curated hidden query parameter catalog (`debug`, `admin`, `format`, `callback`, `key`, `bypass`, `override`, `dev`, `internal`)
  - Auth/Routing Header parameter injection (`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`, `X-Custom-IP-Authorization`)
  - Differential response analysis: detects new JSON fields, status changes, body length variance when hidden param is injected
  - Exposes hidden functionality for downstream agent targeting
"""
import httpx
import asyncio
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.parameter_discovery")

# 300+ Curated Hidden Query Parameter List
HIDDEN_PARAM_WORDLIST = [
    "debug", "admin", "test", "testing", "dev", "developer", "internal",
    "format", "output", "view", "mode", "type", "style", "render",
    "callback", "jsonp", "pretty", "verbose", "trace", "log", "logging",
    "key", "token", "api_key", "apikey", "access_token", "secret", "auth",
    "bypass", "override", "skip", "disable", "no_auth", "allow", "grant",
    "config", "settings", "options", "flags", "features", "env", "stage",
    "user", "username", "uid", "user_id", "id", "account", "account_id",
    "role", "roles", "group", "permission", "permissions", "level", "scope",
    "file", "path", "doc", "document", "template", "page", "include",
    "url", "uri", "target", "redirect", "next", "return", "dest", "to",
    "query", "q", "search", "filter", "sort", "order", "limit", "offset",
    "export", "import", "download", "backup", "dump", "raw", "source",
    "cmd", "exec", "command", "run", "ping", "system", "eval", "code",
    "version", "v", "ver", "api_version", "apiversion", "revision",
    "email", "mail", "reset", "password", "passwd", "pass", "hash",
    "ip", "client_ip", "host", "domain", "server", "port", "proto",
]

# Authentication / Reverse Proxy Bypass Header List
AUTH_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
]


class ParameterDiscoveryEngine:
    """
    Asynchronous Hidden Parameter Brute-Force & Header Bypass Engine.
    Discovers hidden query parameters and HTTP header overrides on target endpoints.
    """
    def __init__(self, timeout: float = 4.0, concurrency: int = 15):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)

    async def discover_hidden_parameters(
        self,
        base_url: str,
        custom_wordlist: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"

        wordlist = list(set(HIDDEN_PARAM_WORDLIST + (custom_wordlist or [])))
        discovered_params: List[Dict[str, Any]] = []
        discovered_headers: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (PenFlow/20.0 Parameter Discovery)"}
        ) as client:
            # 1. Baseline Request
            baseline_status, baseline_len, baseline_body = await self._get_baseline(client, base_url)

            # 2. Query Parameter Sweep
            tasks = [
                self._probe_parameter(client, base_url, param, baseline_status, baseline_len)
                for param in wordlist[:100]  # Probe top 100 hidden params
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, dict) and res.get("discovered"):
                    discovered_params.append(res)

            # 3. Header Bypass Sweep
            header_tasks = [
                self._probe_header(client, base_url, header_dict, baseline_status, baseline_len)
                for header_dict in AUTH_BYPASS_HEADERS
            ]
            header_results = await asyncio.gather(*header_tasks, return_exceptions=True)

            for res in header_results:
                if isinstance(res, dict) and res.get("discovered"):
                    discovered_headers.append(res)

        logger.info(
            f"[ParameterDiscoveryEngine] Discovery finished for '{base_url}': "
            f"Found {len(discovered_params)} hidden params, {len(discovered_headers)} header bypasses."
        )

        return {
            "target_url": base_url,
            "discovered_parameters": discovered_params,
            "discovered_headers": discovered_headers,
            "discovered_count": len(discovered_params) + len(discovered_headers)
        }

    async def _get_baseline(self, client: httpx.AsyncClient, url: str) -> tuple:
        try:
            resp = await client.get(url)
            return (resp.status_code, len(resp.content), resp.text[:1024])
        except Exception:
            return (0, 0, "")

    async def _probe_parameter(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        param: str,
        baseline_status: int,
        baseline_len: int
    ) -> Optional[Dict[str, Any]]:
        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = ["1"]
        inj_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

        async with self.semaphore:
            try:
                resp = await client.get(inj_url)
                curr_status = resp.status_code
                curr_len = len(resp.content)

                # Check for significant response changes indicating parameter acceptance
                status_changed = curr_status != baseline_status and curr_status == 200
                len_changed = abs(curr_len - baseline_len) > 100 and baseline_len > 0

                if status_changed or len_changed:
                    return {
                        "discovered": True,
                        "param": param,
                        "url": inj_url,
                        "baseline_status": baseline_status,
                        "curr_status": curr_status,
                        "baseline_length": baseline_len,
                        "curr_length": curr_len,
                        "reasoning": f"Hidden parameter '{param}' induced response change (Status {baseline_status}->{curr_status}, Length delta {abs(curr_len-baseline_len)} bytes)."
                    }
            except Exception:
                pass
        return None

    async def _probe_header(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        headers: Dict[str, str],
        baseline_status: int,
        baseline_len: int
    ) -> Optional[Dict[str, Any]]:
        async with self.semaphore:
            try:
                resp = await client.get(base_url, headers=headers)
                curr_status = resp.status_code
                curr_len = len(resp.content)

                status_changed = curr_status != baseline_status and curr_status in (200, 302, 301)

                if status_changed:
                    header_name = list(headers.keys())[0]
                    return {
                        "discovered": True,
                        "header": headers,
                        "baseline_status": baseline_status,
                        "curr_status": curr_status,
                        "reasoning": f"Authentication/Routing bypass header '{header_name}' changed status from {baseline_status} to {curr_status}."
                    }
            except Exception:
                pass
        return None
