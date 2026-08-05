from dataclasses import dataclass
from typing import List, Dict

from penflow.graph.correlation import VulnCandidate
from penflow.graph.attack_surface import AttackSurfaceGraph
from penflow.utils.logger import get_logger
from penflow.config import Config

logger = get_logger("penflow.graph.prioritizer")

@dataclass
class ScanTarget:
    url: str
    method: str
    params: List[str]
    vuln_type: str
    priority_score: float
    scan_config: Dict[str, any]
    
    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "vuln_type": self.vuln_type,
            "priority_score": self.priority_score,
            "scan_config": self.scan_config
        }

class TargetPrioritizer:
    def __init__(self):
        self.config = Config.load()
        # Default weights
        self.weights = {
            "IDOR": 1.0,
            "AUTH_BYPASS": 1.0,
            "SSRF": 0.9,
            "SQLI": 0.9,
            "RCE": 1.0,
            "MASS_ASSIGNMENT": 0.7,
            "XSS": 0.6,
            "CORS": 0.5
        }

    async def prioritize(self, candidates: List[VulnCandidate], graph: AttackSurfaceGraph) -> List[ScanTarget]:
        logger.info(f"Prioritizing {len(candidates)} candidates...")
        targets = []
        
        for cand in candidates:
            # Base score from Vuln Type
            base_weight = self.weights.get(cand.vuln_type, 0.5)
            
            # Priority from candidate generation logic
            priority_mult = cand.priority / 10.0
            
            # Final score (0.0 to 1.0)
            score = base_weight * priority_mult * cand.confidence
            
            # Setup specific scan configuration based on vuln type
            scan_config = self._generate_scan_config(cand, graph)
            
            targets.append(ScanTarget(
                url=cand.endpoint_url,
                method=cand.endpoint_method,
                params=cand.parameters,
                vuln_type=cand.vuln_type,
                priority_score=round(score, 3),
                scan_config=scan_config
            ))
            
        # Sort by highest score first
        targets.sort(key=lambda x: x.priority_score, reverse=True)
        
        logger.info(f"Generated {len(targets)} prioritized scan targets.")
        return targets

    def _generate_scan_config(self, cand: VulnCandidate, graph: AttackSurfaceGraph) -> Dict[str, any]:
        """Generate specific instructions for the scanner based on context."""
        config = {"focus_params": cand.parameters}
        
        if cand.vuln_type == "IDOR":
            config["test_vertical_escalation"] = True
            config["test_horizontal_escalation"] = True
            
        elif cand.vuln_type == "SSRF":
            # Pass our out-of-band interact URL if configured
            oob = self.config.get("scanner.oob_server", "")
            if oob:
                config["oob_url"] = oob
                
        return config
