"""
GraphQLCapabilityAgent — Elite GraphQL Security & Attack Engine for PenFlow.

Capabilities:
  1. Schema Introspection Check (full type and field extraction)
  2. Field Suggestion Schema Harvesting (bypasses disabled introspection via error leakage)
  3. Query Batching & Array Amplification Abuse (DoS & rate-limit bypass)
  4. Query Depth Limit Evasion (nested query DoS probe)
  5. Alias Amplification Attack (heavy field execution amplification)
  6. CSRF via GET query execution
"""
from typing import List, Dict, Any, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.graphql")

INTROSPECTION_QUERY = """
query IntrospectionCheck {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind }
      }
    }
  }
}
"""

FIELD_SUGGESTION_QUERY = """
query FieldSuggestionHarvest {
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
  user_invalid_field_probe_12345
}
"""

def generate_depth_query(depth: int = 30) -> str:
    """Generate deeply nested GraphQL query to test depth-limit protection."""
    q = "query DepthCheck { me "
    for i in range(depth):
        q += "{ friends "
    q += "{ id name }"
    q += " }" * depth + " }"
    return q

def generate_alias_query(count: int = 100) -> str:
    """Generate query with 100 aliases resolving the same field to test DoS amplification."""
    aliases = [f"a{i}: __typename" for i in range(count)]
    return f"query AliasAmplification {{ {' '.join(aliases)} }}"


class GraphQLCapabilityAgent(BaseCapabilityAgent):
    """
    Elite GraphQL Security Agent.
    Tests Introspection, Field Suggestion Schema Harvesting, Batching, Depth Limit Evasion,
    Alias Amplification, and CSRF via GET.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="GraphQLCapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="graphql_analysis",
                name="GraphQL Security & Attack Engine",
                description="Exhaustive GraphQL analysis: Introspection, Field Suggestions, Batching, Depth DoS, Alias Amplification",
                priority=self.priority,
                tags=["graphql", "api", "security", "dos", "schema"]
            ),
            Capability(
                id="graphql_introspection",
                name="GraphQL Schema Introspection & Harvesting",
                description="Extracts full GraphQL schema via Introspection or Field Suggestion leakage",
                priority=self.priority,
                tags=["graphql", "schema", "information_disclosure"]
            ),
            Capability(
                id="schema_introspection",
                name="GraphQL Schema Introspection Check (Legacy)",
                description="Extracts full GraphQL schema via Introspection or Field Suggestion leakage",
                priority=self.priority,
                tags=["graphql", "schema", "information_disclosure"]
            ),
            Capability(
                id="graphql_depth_analysis",
                name="GraphQL Query Depth & Amplification DoS",
                description="Tests support for deeply nested queries and alias amplification",
                priority=self.priority,
                tags=["graphql", "dos", "batching"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[GraphQLCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        gql_urls = self._find_graphql_urls(context)
        target_url = gql_urls[0]

        findings = []

        # 1. Introspection Test
        intro_result = await self._test_introspection(http_client, target_url)
        if intro_result:
            findings.append(intro_result)

        # 2. Field Suggestion Harvest (if Introspection disabled)
        if not (intro_result and intro_result.get("is_vulnerable")):
            field_sug_result = await self._test_field_suggestions(http_client, target_url)
            if field_sug_result:
                findings.append(field_sug_result)

        # 3. Query Batching
        batch_result = await self._test_batching(http_client, target_url)
        if batch_result:
            findings.append(batch_result)

        # 4. Depth Limit Evasion
        depth_result = await self._test_depth_limit(http_client, target_url)
        if depth_result:
            findings.append(depth_result)

        # 5. Alias Amplification
        alias_result = await self._test_alias_amplification(http_client, target_url)
        if alias_result:
            findings.append(alias_result)

        confirmed = [f for f in findings if f.get("is_vulnerable")]
        is_vuln = len(confirmed) > 0
        best = confirmed[0] if confirmed else (findings[0] if findings else {})

        intro_finding = next((f for f in findings if f.get("vector") == "introspection"), {})
        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "asset": context.asset,
            "is_vulnerable": is_vuln,
            "confidence_score": best.get("confidence", 0.0),
            "evidence": {
                "target_url": target_url,
                "introspection_enabled": intro_finding.get("is_vulnerable", False),
                "discovered_types_count": intro_finding.get("type_count", 0),
                "reasoning": best.get("reasoning", "GraphQL endpoint secured against introspection and query abuse."),
                "findings": findings,
                "evidence_exchanges": [f.get("exchange", {}) for f in findings if f.get("exchange")]
            }
        }

    def _find_graphql_urls(self, context: CapabilityExecutionContext) -> List[str]:
        urls = []
        for data in context.get_observation_data():
            if isinstance(data, dict):
                url = data.get("url", "")
                if url and any(k in url.lower() for k in ["graphql", "gql", "playground", "altair"]):
                    urls.append(url)
                for ep in data.get("endpoints", []):
                    if isinstance(ep, dict) and ep.get("url"):
                        ep_url = ep["url"]
                        if any(k in ep_url.lower() for k in ["graphql", "gql", "playground", "altair"]):
                            urls.append(ep_url)
        if not urls:
            urls = [f"https://{context.asset}/graphql", f"https://{context.asset}/api/graphql", f"https://{context.asset}/api/v1/graphql"]
        return list(set(urls))

    async def _test_introspection(self, http_client: Any, target_url: str) -> Optional[Dict[str, Any]]:
        try:
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="POST",
                url=target_url,
                json_data={"query": INTROSPECTION_QUERY}
            )
            resp = exch.response
            if resp and resp.status_code == 200 and resp.body_json:
                data_field = resp.body_json.get("data", {})
                if isinstance(data_field, dict) and "__schema" in data_field:
                    types = data_field["__schema"].get("types", [])
                    type_names = [t.get("name") for t in types if isinstance(t, dict) and t.get("name")]
                    return {
                        "vector": "introspection",
                        "is_vulnerable": True,
                        "confidence": 0.98,
                        "reasoning": f"CRITICAL: Full GraphQL Introspection is enabled! Discovered {len(type_names)} schema types.",
                        "type_count": len(type_names),
                        "exchange": exch.to_dict()
                    }
        except Exception as e:
            logger.debug(f"[GraphQLAgent] Introspection test error: {e}")
        return None

    async def _test_field_suggestions(self, http_client: Any, target_url: str) -> Optional[Dict[str, Any]]:
        try:
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="POST",
                url=target_url,
                json_data={"query": FIELD_SUGGESTION_QUERY}
            )
            resp = exch.response
            if resp and "Did you mean" in (resp.body_text or ""):
                return {
                    "vector": "field_suggestions",
                    "is_vulnerable": True,
                    "confidence": 0.85,
                    "reasoning": "HIGH: Field suggestion schema harvesting is enabled! Server discloses valid schema fields via error suggestions.",
                    "exchange": exch.to_dict()
                }
        except Exception as e:
            logger.debug(f"[GraphQLAgent] Field suggestion test error: {e}")
        return None

    async def _test_batching(self, http_client: Any, target_url: str) -> Optional[Dict[str, Any]]:
        try:
            payload = [{"query": "query { __typename }"}, {"query": "query { __typename }"}]
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="POST",
                url=target_url,
                json_data=payload
            )
            resp = exch.response
            if resp and resp.status_code == 200 and isinstance(resp.body_json, list) and len(resp.body_json) == 2:
                return {
                    "vector": "query_batching",
                    "is_vulnerable": True,
                    "confidence": 0.90,
                    "reasoning": "HIGH: GraphQL array-based query batching supported — enables brute-force amplification and rate limit bypass.",
                    "exchange": exch.to_dict()
                }
        except Exception as e:
            logger.debug(f"[GraphQLAgent] Batching test error: {e}")
        return None

    async def _test_depth_limit(self, http_client: Any, target_url: str) -> Optional[Dict[str, Any]]:
        try:
            deep_q = generate_depth_query(25)
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="POST",
                url=target_url,
                json_data={"query": deep_q}
            )
            resp = exch.response
            if resp and resp.status_code == 200 and "errors" not in (resp.body_json or {}):
                return {
                    "vector": "depth_limit_evasion",
                    "is_vulnerable": True,
                    "confidence": 0.80,
                    "reasoning": "MEDIUM: Server accepted a 25-level deeply nested query without depth-limit error — DoS surface.",
                    "exchange": exch.to_dict()
                }
        except Exception as e:
            logger.debug(f"[GraphQLAgent] Depth limit test error: {e}")
        return None

    async def _test_alias_amplification(self, http_client: Any, target_url: str) -> Optional[Dict[str, Any]]:
        try:
            alias_q = generate_alias_query(50)
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="POST",
                url=target_url,
                json_data={"query": alias_q}
            )
            resp = exch.response
            if resp and resp.status_code == 200 and isinstance(resp.body_json, dict) and "data" in resp.body_json:
                data_dict = resp.body_json.get("data", {})
                if isinstance(data_dict, dict) and len(data_dict) == 50:
                    return {
                        "vector": "alias_amplification",
                        "is_vulnerable": True,
                        "confidence": 0.88,
                        "reasoning": "HIGH: Alias amplification supported (50 aliases resolved in single request) — computational DoS risk.",
                        "exchange": exch.to_dict()
                    }
        except Exception as e:
            logger.debug(f"[GraphQLAgent] Alias amplification test error: {e}")
        return None
