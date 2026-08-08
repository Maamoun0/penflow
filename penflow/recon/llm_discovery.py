"""
LLMEndpointDiscoverer — Modern AI & LLM Endpoint Discovery Engine for PenFlow.

Scans web targets for AI/LLM entrypoints, streaming chat endpoints, header signatures,
and client-side AI SDK integration in JavaScript bundles.
"""
import re
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.llm_discovery")

COMMON_LLM_PATHS = [
    "/api/chat",
    "/api/ai",
    "/api/assistant",
    "/api/generate",
    "/api/complete",
    "/api/v1/chat/completions",
    "/api/v1/completions",
    "/v1/chat/completions",
    "/copilot/chat",
    "/assistant/message",
    "/api/agent",
    "/api/rag/query",
]

LLM_HEADER_PATTERNS = [
    "x-openai-",
    "x-anthropic-",
    "x-mistral-",
    "x-groq-",
    "x-llm-",
]

LLM_JS_KEYWORDS = [
    "openai",
    "anthropic",
    "langchain",
    "llamaindex",
    "huggingface",
    "text/event-stream",
    "chat_history",
    "system_prompt",
]

class LLMEndpointDiscoverer:
    def __init__(self, concurrency: int = 10):
        self.concurrency = concurrency

    def analyze_headers(self, headers: Dict[str, str]) -> List[str]:
        detected = []
        for h, val in headers.items():
            h_lower = h.lower()
            if any(pat in h_lower for pat in LLM_HEADER_PATTERNS):
                detected.append(f"{h}: {val}")
        return detected

    def analyze_js_bundle(self, js_content: str) -> List[Dict[str, Any]]:
        matches = []
        for kw in LLM_JS_KEYWORDS:
            pattern = re.compile(rf"\b{kw}\b", re.IGNORECASE)
            for m in pattern.finditer(js_content):
                start = max(0, m.start() - 30)
                end = min(len(js_content), m.end() + 30)
                snippet = js_content[start:end].strip()
                matches.append({
                    "keyword": kw,
                    "snippet": snippet
                })
        return matches

    def discover_endpoints_from_crawl(self, crawl_endpoints: List[str]) -> List[Dict[str, Any]]:
        discovered = []
        for ep in crawl_endpoints:
            ep_lower = ep.lower()
            for pattern in COMMON_LLM_PATHS:
                if pattern in ep_lower:
                    discovered.append({
                        "endpoint": ep,
                        "matched_pattern": pattern,
                        "type": "llm_chat_api" if "chat" in pattern else "llm_general_api"
                    })
        return discovered
