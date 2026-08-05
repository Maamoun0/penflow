"""
OpenAPIParser — Automatic OpenAPI (Swagger 2.0 / 3.x) Schema Harvester & Endpoint Extractor for PenFlow.

Ingests OpenAPI / Swagger specification JSON/dicts, dereferences schema `$ref` pointers,
and extracts paths, HTTP methods, required parameters, request bodies, and authentication security schemes.
Converts extracted specs into structured ClassifiedEndpoint objects for targeted capability agent testing.
"""
import json
import httpx
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urljoin, urlparse
from penflow.recon.endpoint_classifier import ClassifiedEndpoint
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.openapi_parser")

# Common candidate paths where OpenAPI / Swagger specs are exposed
OPENAPI_SPEC_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api-docs.json",
    "/api/swagger.json", "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/api/openapi.json", "/api/v1/openapi.json", "/schema.json",
]


class OpenAPIParser:
    """
    Automatic OpenAPI / Swagger 2.0 & 3.x Parser and Schema Harvester.
    """

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    async def discover_and_parse(self, base_url: str) -> List[ClassifiedEndpoint]:
        """Discover exposed OpenAPI specification endpoints and parse them."""
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"

        discovered_endpoints: List[ClassifiedEndpoint] = []

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (PenFlow/23.0 OpenAPI Harvester)"}
        ) as client:
            for path in OPENAPI_SPEC_PATHS:
                spec_url = urljoin(base_url, path)
                try:
                    resp = await client.get(spec_url)
                    if resp.status_code == 200:
                        content_type = resp.headers.get("content-type", "")
                        if "json" in content_type or resp.text.strip().startswith("{"):
                            try:
                                spec_dict = resp.json()
                                if isinstance(spec_dict, dict) and ("swagger" in spec_dict or "openapi" in spec_dict or "paths" in spec_dict):
                                    logger.info(f"[OpenAPIParser] Exposed OpenAPI specification discovered at: {spec_url}")
                                    endpoints = self.parse_spec(spec_url, spec_dict)
                                    discovered_endpoints.extend(endpoints)
                                    break  # Primary spec parsed successfully
                            except json.JSONDecodeError:
                                pass
                except Exception as e:
                    logger.debug(f"[OpenAPIParser] Spec check failed for {spec_url}: {e}")

        return discovered_endpoints

    def parse_spec(self, spec_url: str, spec_dict: Dict[str, Any]) -> List[ClassifiedEndpoint]:
        """Parse OpenAPI / Swagger spec dictionary into ClassifiedEndpoint objects."""
        base_host = spec_dict.get("host", "")
        base_path = spec_dict.get("basePath", "")
        schemes = spec_dict.get("schemes", ["https"])
        scheme = schemes[0] if schemes else "https"

        parsed_spec_url = urlparse(spec_url)
        origin = f"{scheme}://{base_host}" if base_host else f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"
        root_prefix = base_path if (base_path and base_path != "/") else ""

        paths_dict = spec_dict.get("paths", {})
        if not isinstance(paths_dict, dict):
            return []

        endpoints: List[ClassifiedEndpoint] = []

        for path_str, path_item in paths_dict.items():
            if not isinstance(path_item, dict):
                continue

            full_path = f"{root_prefix}{path_str}"
            endpoint_url = urljoin(origin, full_path)

            for method_str, op_dict in path_item.items():
                if method_str.lower() not in ("get", "post", "put", "delete", "patch", "options", "head"):
                    continue
                if not isinstance(op_dict, dict):
                    continue

                method = method_str.upper()
                params = self._extract_parameters(op_dict, path_item, spec_dict)
                tags = op_dict.get("tags", [])
                tags.append("openapi_discovered")

                # Endpoint type heuristic
                endpoint_type = "rest_api"
                if "auth" in path_str.lower() or "login" in path_str.lower():
                    endpoint_type = "auth"
                elif "admin" in path_str.lower():
                    endpoint_type = "admin"

                endpoints.append(ClassifiedEndpoint(
                    url=endpoint_url,
                    endpoint_type=endpoint_type,
                    method=method,
                    parameters=params,
                    confidence=0.95,
                    tags=tags,
                    source="openapi_spec"
                ))

        logger.info(f"[OpenAPIParser] Extracted {len(endpoints)} endpoints from OpenAPI specification.")
        return endpoints

    def _extract_parameters(self, op_dict: Dict[str, Any], path_item: Dict[str, Any], spec_dict: Dict[str, Any]) -> List[str]:
        """Extract parameter names from operation & path-level parameters plus OpenAPI 3 requestBody."""
        param_names: Set[str] = set()

        raw_params = path_item.get("parameters", []) + op_dict.get("parameters", [])
        for p in raw_params:
            if isinstance(p, dict):
                p_name = p.get("name")
                if p_name:
                    param_names.add(p_name)
                # Handle schema ref inside parameter
                schema = p.get("schema", {})
                if isinstance(schema, dict):
                    keys = self._extract_keys_from_schema(schema, spec_dict)
                    param_names.update(keys)

        # OpenAPI 3.x requestBody schema parsing
        req_body = op_dict.get("requestBody", {})
        if isinstance(req_body, dict):
            content = req_body.get("content", {})
            if isinstance(content, dict):
                for media_type, media_obj in content.items():
                    if isinstance(media_obj, dict):
                        schema = media_obj.get("schema", {})
                        if isinstance(schema, dict):
                            keys = self._extract_keys_from_schema(schema, spec_dict)
                            param_names.update(keys)

        return list(param_names)

    def _extract_keys_from_schema(self, schema: Dict[str, Any], spec_dict: Dict[str, Any], depth: int = 0) -> List[str]:
        """Extract field keys from JSON schema dict (dereferencing $ref if present)."""
        if depth > 5:  # Recursion guard
            return []

        keys: List[str] = []

        # Resolve $ref pointer
        ref = schema.get("$ref")
        if ref and isinstance(ref, str):
            resolved = self._resolve_ref(ref, spec_dict)
            if resolved:
                return self._extract_keys_from_schema(resolved, spec_dict, depth + 1)

        props = schema.get("properties", {})
        if isinstance(props, dict):
            for k in props.keys():
                keys.append(k)

        return keys

    def _resolve_ref(self, ref: str, spec_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Resolve a JSON pointer like '#/definitions/User' or '#/components/schemas/User'."""
        if not ref.startswith("#/"):
            return None

        parts = ref.lstrip("#/").split("/")
        curr = spec_dict
        for p in parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                return None

        return curr if isinstance(curr, dict) else None
