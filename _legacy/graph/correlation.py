from dataclasses import dataclass
from typing import List, Dict, Any

from penflow.graph.attack_surface import AttackSurfaceGraph
from penflow.utils.logger import get_logger

logger = get_logger("penflow.graph.correlation")

@dataclass
class VulnCandidate:
    vuln_type: str
    endpoint_url: str
    endpoint_method: str
    parameters: List[str]
    confidence: float  # 0.0 to 1.0
    reasoning: str
    priority: int      # 1 to 10
    
    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "endpoint_url": self.endpoint_url,
            "endpoint_method": self.endpoint_method,
            "parameters": self.parameters,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "priority": self.priority
        }

class SignalCorrelator:
    def __init__(self):
        self.rules = self._init_rules()

    def _init_rules(self):
        # We can move this to YAML later, but hardcoded for reliability now
        return {
            "idor_params": ["id", "user_id", "uid", "account", "profile"],
            "ssrf_params": ["url", "redirect", "callback", "next", "path", "dest"],
            "sqli_params": ["id", "q", "search", "sort", "order", "filter"],
            "lfi_params": ["file", "path", "template", "include"]
        }

    async def correlate(self, graph: AttackSurfaceGraph) -> List[VulnCandidate]:
        logger.info("Starting graph correlation to find vulnerability candidates...")
        candidates = []
        
        # 1. IDOR Candidates
        idor_cands = self._find_idor_candidates(graph)
        candidates.extend(idor_cands)
        
        # 2. SSRF Candidates
        ssrf_cands = self._find_ssrf_candidates(graph)
        candidates.extend(ssrf_cands)
        
        # 3. Mass Assignment Candidates
        mass_cands = self._find_mass_assignment_candidates(graph)
        candidates.extend(mass_cands)
        
        # 4. Auth Bypass Candidates
        auth_cands = self._find_auth_bypass_candidates(graph)
        candidates.extend(auth_cands)
        
        logger.info(f"Correlation complete. Generated {len(candidates)} vulnerability candidates.")
        return candidates

    def _find_idor_candidates(self, graph: AttackSurfaceGraph) -> List[VulnCandidate]:
        candidates = []
        endpoints = graph.query_nodes("ENDPOINT")
        
        for ep in endpoints:
            ep_id = ep["id"]
            
            # Look for accepted parameters
            params = []
            for _, neighbor, data in graph.graph.out_edges(ep_id, data=True):
                if data.get("type") == "ACCEPTS":
                    node = graph.graph.nodes[neighbor]
                    if node.get("type") == "PARAMETER":
                        params.append(node["name"])
            
            # Check if any parameter matches IDOR signatures
            matching_params = [p for p in params if any(ip in p.lower() for ip in self.rules["idor_params"])]
            
            # Check URL pattern for REST IDs (e.g., /users/123)
            url = ep.get("url", "")
            has_rest_id = bool(re.search(r'/[0-9a-fA-F\-]{8,}/|/\d+/', url))
            
            if matching_params or has_rest_id:
                reason = []
                if matching_params: reason.append(f"Accepts identity parameters: {matching_params}")
                if has_rest_id: reason.append("URL contains REST-style identifier")
                if ep.get("classification") == "api": reason.append("Is an API endpoint")
                
                candidates.append(VulnCandidate(
                    vuln_type="IDOR",
                    endpoint_url=url,
                    endpoint_method=ep.get("method", "GET"),
                    parameters=matching_params,
                    confidence=0.7 if (has_rest_id and "api" in ep.get("classification", "")) else 0.4,
                    reasoning=" + ".join(reason),
                    priority=8
                ))
        return candidates

    def _find_ssrf_candidates(self, graph: AttackSurfaceGraph) -> List[VulnCandidate]:
        candidates = []
        endpoints = graph.query_nodes("ENDPOINT")
        
        for ep in endpoints:
            ep_id = ep["id"]
            params = []
            for _, neighbor, data in graph.graph.out_edges(ep_id, data=True):
                if data.get("type") == "ACCEPTS":
                    node = graph.graph.nodes[neighbor]
                    if node.get("type") == "PARAMETER":
                        params.append(node["name"])
                        
            matching_params = [p for p in params if any(sp in p.lower() for sp in self.rules["ssrf_params"])]
            
            if matching_params:
                candidates.append(VulnCandidate(
                    vuln_type="SSRF",
                    endpoint_url=ep.get("url", ""),
                    endpoint_method=ep.get("method", "GET"),
                    parameters=matching_params,
                    confidence=0.5,
                    reasoning=f"Accepts URL/Redirect parameters: {matching_params}",
                    priority=9
                ))
        return candidates

    def _find_mass_assignment_candidates(self, graph: AttackSurfaceGraph) -> List[VulnCandidate]:
        candidates = []
        endpoints = graph.query_nodes("ENDPOINT", method="POST")
        endpoints.extend(graph.query_nodes("ENDPOINT", method="PUT"))
        endpoints.extend(graph.query_nodes("ENDPOINT", method="PATCH"))
        
        for ep in endpoints:
            if "api" in ep.get("classification", "") or "users" in ep.get("url", "") or "profile" in ep.get("url", ""):
                candidates.append(VulnCandidate(
                    vuln_type="MASS_ASSIGNMENT",
                    endpoint_url=ep.get("url", ""),
                    endpoint_method=ep.get("method"),
                    parameters=[],
                    confidence=0.4,
                    reasoning="State-changing API endpoint dealing with user/profile data",
                    priority=7
                ))
        return candidates

    def _find_auth_bypass_candidates(self, graph: AttackSurfaceGraph) -> List[VulnCandidate]:
        candidates = []
        endpoints = graph.query_nodes("ENDPOINT")
        
        for ep in endpoints:
            classification = ep.get("classification", "")
            if classification in ["admin", "auth"]:
                candidates.append(VulnCandidate(
                    vuln_type="AUTH_BYPASS",
                    endpoint_url=ep.get("url", ""),
                    endpoint_method=ep.get("method", "GET"),
                    parameters=[],
                    confidence=0.6,
                    reasoning=f"Highly sensitive endpoint classification: {classification}",
                    priority=10
                ))
        return candidates

import re
