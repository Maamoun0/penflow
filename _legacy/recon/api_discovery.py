import asyncio
import json
from dataclasses import dataclass, field
from typing import Dict, List, Any
from urllib.parse import urljoin

from penflow.network.http_client import HttpClient
from penflow.utils.logger import get_logger
from penflow.utils.url_utils import normalize_url
from penflow.utils.file_utils import get_scan_dir, safe_write_json
from penflow.core.event_bus import EventBus

logger = get_logger("penflow.recon.api_discovery")

@dataclass
class APIDiscoveryResult:
    has_swagger: bool = False
    has_graphql: bool = False
    endpoints: List[Dict[str, str]] = field(default_factory=list)
    schemas: Dict[str, Any] = field(default_factory=dict)
    auth_types: List[str] = field(default_factory=list)

class APIDiscoverer:
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
        self.event_bus = EventBus.get_instance()
        
        self.swagger_paths = [
            "/swagger.json", "/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/openapi.json", "/openapi.yaml", "/swagger-ui.html", 
            "/.well-known/openapi.yaml", "/api/swagger.json"
        ]
        
        self.graphql_paths = [
            "/graphql", "/api/graphql", "/v1/graphql", "/graphiql"
        ]

    async def discover(self, base_url: str) -> APIDiscoveryResult:
        logger.info(f"Starting API Discovery for {base_url}")
        result = APIDiscoveryResult()
        
        # 1. Check for Swagger/OpenAPI
        swagger_tasks = [self._check_swagger(urljoin(base_url, p)) for p in self.swagger_paths]
        swagger_results = await asyncio.gather(*swagger_tasks)
        
        for res in swagger_results:
            if res:
                result.has_swagger = True
                self._parse_swagger(res, result, base_url)
                # We only need one valid swagger file
                break
                
        # 2. Check for GraphQL
        graphql_tasks = [self._check_graphql(urljoin(base_url, p)) for p in self.graphql_paths]
        graphql_results = await asyncio.gather(*graphql_tasks)
        
        for res in graphql_results:
            if res:
                result.has_graphql = True
                result.endpoints.append({"url": res["url"], "method": "POST", "type": "graphql"})
                result.schemas["graphql"] = res["schema"]
                break
                
        # Save results
        from urllib.parse import urlparse
        domain = urlparse(base_url).netloc.split(':')[0]
        out_dir = get_scan_dir(domain, "filtered")
        
        if result.endpoints:
            safe_write_json(out_dir / "api_endpoints.json", result.endpoints)
            
        logger.info(f"API Discovery complete. Found {len(result.endpoints)} documented endpoints.")
        return result

    async def _check_swagger(self, url: str) -> dict | None:
        try:
            response = await self.http_client.get(url, skip_cache=True, timeout=3.0, skip_retries=True)
            if response and response.status == 200:
                if "swagger" in response.body.lower() or "openapi" in response.body.lower():
                    try:
                        data = json.loads(response.body)
                        # Minimal validation
                        if "swagger" in data or "openapi" in data:
                            return data
                    except json.JSONDecodeError:
                        # Could be YAML, we'll implement full parsing later if needed
                        pass
        except Exception:
            pass
        return None

    def _parse_swagger(self, data: dict, result: APIDiscoveryResult, base_url: str) -> None:
        """Parse OpenAPI/Swagger JSON to extract endpoints and parameters."""
        paths = data.get("paths", {})
        base_path = data.get("basePath", "")
        
        # Servers block in OpenAPI v3
        servers = data.get("servers", [])
        if servers:
            base_url = servers[0].get("url", base_url)
            
        result.schemas["openapi"] = data
        
        for path, methods in paths.items():
            full_path = f"{base_path}{path}"
            if not full_path.startswith("/"): full_path = f"/{full_path}"
            
            full_url = urljoin(base_url, full_path)
            
            for method, details in methods.items():
                if method.lower() not in ['get', 'post', 'put', 'delete', 'patch']:
                    continue
                    
                params = []
                for p in details.get("parameters", []):
                    params.append(p.get("name", ""))
                    
                ep = {
                    "url": normalize_url(full_url),
                    "method": method.upper(),
                    "type": "api",
                    "params": [p for p in params if p],
                    "source": "swagger"
                }
                result.endpoints.append(ep)
                
                # Emit event
                asyncio.create_task(self.event_bus.emit("ENDPOINT_FOUND", ep))
                
        # Extract Auth
        security_defs = data.get("securityDefinitions", {}) or data.get("components", {}).get("securitySchemes", {})
        for name, details in security_defs.items():
            t = details.get("type", "")
            if t: result.auth_types.append(t)

    async def _check_graphql(self, url: str) -> dict | None:
        """Send Introspection Query to check if GraphQL is active."""
        introspection_query = {
            "query": "\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        subscriptionType { name }\n      }\n    }\n  "
        }
        try:
            response = await self.http_client.post(url, json=introspection_query, timeout=3.0, skip_retries=True)
            if response and response.status == 200:
                data = json.loads(response.body)
                if "data" in data and "__schema" in data["data"]:
                    # Introspection enabled!
                    asyncio.create_task(self.event_bus.emit("VULN_DETECTED", {
                        "type": "graphql_introspection_enabled",
                        "url": url,
                        "severity": "Low",
                        "details": "GraphQL Introspection is enabled, revealing schema structure."
                    }))
                    return {"url": url, "schema": data["data"]["__schema"]}
        except Exception:
            pass
        return None
