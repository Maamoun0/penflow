import re
from typing import List, Dict, Any, Set
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.js_miner")

# Patterns for extracting endpoints, API keys, and parameter names from JS bundles
ENDPOINT_REGEX = re.compile(r"[\"'](/(?:api|v1|v2|graphql|users|admin|auth|account|data)/[a-zA-Z0-9_\-\?=/&%]+)[\"']")
API_KEY_REGEX = re.compile(r"[\"'](AIzaSy[a-zA-Z0-9_\-]{33}|eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)[\"']")
PARAM_REGEX = re.compile(r"([a-zA-Z0-9_]+_id|[a-zA-Z0-9_]+Id|role|admin|token|secret|password)\s*=")

class JavaScriptASTParser:
    """
    Client-Side JavaScript Mining Engine: Parses JS source bundles,
    extracts unlinked API Endpoints, hidden secrets, and parameters,
    and feeds them directly into the PenFlow KnowledgeGraph.
    """

    def parse_js_content(self, js_code: str, source_url: str = "") -> Dict[str, Any]:
        logger.info(f"[JavaScriptASTParser] Mining JS bundle from '{source_url}' ({len(js_code)} bytes)...")

        endpoints: Set[str] = set(ENDPOINT_REGEX.findall(js_code))
        api_keys: Set[str] = set(API_KEY_REGEX.findall(js_code))
        params: Set[str] = set(PARAM_REGEX.findall(js_code))

        result = {
            "source_url": source_url,
            "discovered_endpoints": list(endpoints),
            "discovered_secrets": list(api_keys),
            "discovered_parameters": list(params)
        }

        logger.info(f"[JavaScriptASTParser] Mining Complete: Found {len(endpoints)} endpoints, {len(api_keys)} secrets, {len(params)} parameters.")
        return result
