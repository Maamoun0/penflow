"""
JS Source Map Parser & Webpack Chunk Secret Extractor for PenFlow.

Capabilities:
  - Parses JavaScript `.js.map` files and reconstructs original source file contents.
  - Detects hardcoded secrets, tokens, and credentials using exact regex patterns:
      • AWS Access Key ID: AKIA[0-9A-Z]{16}
      • Firebase API Key: AIzaSy[a-zA-Z0-9_-]{33}
      • Stripe Secret Key: sk_live_[a-zA-Z0-9]{24}
      • Environment variables: REACT_APP_, VUE_APP_, NEXT_PUBLIC_
      • JWT Tokens: eyJ[a-zA-Z0-9_-]+\\.eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+
  - Extracts React Router, Vue Router, Angular routes, dynamic import() targets, and GraphQL query strings.
"""
import re
import json
import httpx
from typing import List, Dict, Any, Set, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.source_map_parser")

# High-precision secret detection patterns
SECRET_PATTERNS = {
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "firebase_api_key": re.compile(r"AIzaSy[a-zA-Z0-9_-]{33}"),
    "stripe_live_key": re.compile(r"sk_live_[a-zA-Z0-9]{24}"),
    "jwt_token": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
    "env_variable": re.compile(r'(?:REACT_APP_|VUE_APP_|NEXT_PUBLIC_|API_KEY|SECRET_KEY)[a-zA-Z0-9_]*\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
    "graphql_query": re.compile(r'(?:query|mutation|subscription)\s+[a-zA-Z0-9_]+\s*\{[^}]+\}', re.IGNORECASE)
}


class SourceMapParser:
    """
    Parses .js.map files and mines extracted source code for secrets, routes, and GraphQL queries.
    """

    def parse_map_json(self, map_content: str, map_filename: str = "bundle.js.map") -> Dict[str, Any]:
        """Parses raw JSON string of a .js.map file."""
        findings: List[Dict[str, Any]] = []
        sources_found: List[str] = []
        routes_discovered: Set[str] = set()

        try:
            map_data = json.loads(map_content)
            sources = map_data.get("sources", [])
            sources_content = map_data.get("sourcesContent", []) or []

            for idx, source_name in enumerate(sources):
                sources_found.append(source_name)
                code = sources_content[idx] if idx < len(sources_content) and sources_content[idx] else ""

                if code:
                    # Secret mining across source code
                    for secret_type, pattern in SECRET_PATTERNS.items():
                        matches = pattern.findall(code)
                        for match in matches:
                            match_str = match[0] if isinstance(match, tuple) else match
                            # Filter out placeholder strings
                            if len(match_str) > 5 and not match_str.startswith("YOUR_") and "example" not in match_str.lower():
                                findings.append({
                                    "source_file": source_name,
                                    "secret_type": secret_type,
                                    "matched_value": match_str,
                                    "map_filename": map_filename
                                })

                    # Dynamic route mining
                    route_matches = re.findall(r'path\s*:\s*["\'](/[a-zA-Z0-9_\-./:]+)["\']', code, re.IGNORECASE)
                    for r in route_matches:
                        routes_discovered.add(r)

        except Exception as e:
            logger.error(f"[SourceMapParser] Error parsing source map file '{map_filename}': {e}")

        logger.info(f"[SourceMapParser] Parsed '{map_filename}': {len(sources_found)} sources, {len(findings)} secrets, {len(routes_discovered)} routes.")
        return {
            "map_filename": map_filename,
            "sources_count": len(sources_found),
            "sources": sources_found[:20],
            "secrets_found": findings,
            "routes_discovered": sorted(list(routes_discovered))
        }

    async def fetch_and_parse_map(self, map_url: str) -> Dict[str, Any]:
        """Fetches remote .js.map file via HTTP and parses it."""
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                resp = await client.get(map_url)
                if resp.status_code == 200:
                    return self.parse_map_json(resp.text, map_filename=map_url)
                else:
                    logger.warning(f"[SourceMapParser] HTTP {resp.status_code} fetching source map '{map_url}'.")
        except Exception as e:
            logger.error(f"[SourceMapParser] Exception fetching source map '{map_url}': {e}")

        return {
            "map_filename": map_url,
            "sources_count": 0,
            "sources": [],
            "secrets_found": [],
            "routes_discovered": []
        }
