from typing import Dict, Any, List
from penflow.agents.base_agent import BaseSwarmAgent
from penflow.network.http_client import HttpClient
from penflow.utils.logger import get_logger

logger = get_logger("penflow.agents.api")

class APIAgent(BaseSwarmAgent):
    """
    API Agent: Responsible for discovering REST and GraphQL API endpoints,
    parsing OpenAPI/Swagger specs, GraphQL introspection schemas, and routing
    API structures to the shared memory and specialized vulnerability agents.
    """

    @property
    def agent_name(self) -> str:
        return "APIAgent"

    @property
    def role(self) -> str:
        return "APIDiscovery"

    async def discover_api_schema(self, base_url: str, http_client: HttpClient) -> Dict[str, Any]:
        """
        Attempts to discover OpenAPI/Swagger docs or GraphQL introspection.
        """
        known_spec_paths = [
            "/openapi.json", "/swagger.json", "/v2/api-docs", "/api/v1/swagger.json",
            "/graphql", "/api/graphql"
        ]
        
        discovered_specs = []
        is_graphql = False
        
        for path in known_spec_paths:
            url = base_url.rstrip("/") + path
            resp = await http_client.get(url, skip_cache=True)
            if resp and resp.status == 200:
                if "graphql" in path:
                    is_graphql = True
                    discovered_specs.append({"type": "GraphQL", "url": url})
                elif "swagger" in resp.body.lower() or "openapi" in resp.body.lower():
                    discovered_specs.append({"type": "OpenAPI", "url": url})
                    
        summary = {
            "base_url": base_url,
            "discovered_specs": discovered_specs,
            "is_graphql": is_graphql,
            "endpoint_count": len(discovered_specs)
        }
        
        logger.info(f"[APIAgent] API Discovery on {base_url}: Found {len(discovered_specs)} specs.")
        await self.publish_event("API_SPECS_DISCOVERED", summary)
        return summary

    async def process_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        http_client = task_data.get("http_client")
        base_url = task_data.get("base_url", "")
        if http_client and base_url:
            return await self.discover_api_schema(base_url, http_client)
        return {"status": "error", "message": "Missing http_client or base_url"}
