from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from penflow.intelligence.writeup_miner import SecurityWriteup
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.experience_layer")

@dataclass
class VulnerabilityPatternStats:
    vulnerability_type: str
    total_attempts: int = 0
    successful_verifications: int = 0
    falsified_attempts: int = 0
    historical_confidence_weight: float = 1.0

class ExperienceLayer:
    """
    Experience Layer: Maintains persistent empirical statistical weights
    and tactical knowledge mined from past scans and public writeups.
    Dynamically adjusts rule prioritization weights in the Planner.
    """

    def __init__(self):
        self._stats: Dict[str, VulnerabilityPatternStats] = {}
        self._mined_writeups: List[SecurityWriteup] = []

    def record_scan_result(self, vulnerability_type: str, is_verified: bool) -> None:
        if vulnerability_type not in self._stats:
            self._stats[vulnerability_type] = VulnerabilityPatternStats(vulnerability_type=vulnerability_type)

        stat = self._stats[vulnerability_type]
        stat.total_attempts += 1
        if is_verified:
            stat.successful_verifications += 1
        else:
            stat.falsified_attempts += 1

        # Calculate new empirical confidence multiplier
        success_rate = stat.successful_verifications / max(1, stat.total_attempts)
        stat.historical_confidence_weight = round(0.5 + (0.5 * success_rate), 2)

        logger.info(f"[ExperienceLayer] Updated stats for '{vulnerability_type}': SuccessRate={success_rate*100:.1f}%, Weight={stat.historical_confidence_weight}")

    def absorb_writeup(self, writeup: SecurityWriteup) -> None:
        self._mined_writeups.append(writeup)
        for vtype in writeup.detected_vulnerabilities:
            if vtype not in self._stats:
                self._stats[vtype] = VulnerabilityPatternStats(vulnerability_type=vtype)
            # Boost historical weight based on external empirical prevalence
            self._stats[vtype].historical_confidence_weight = min(1.5, self._stats[vtype].historical_confidence_weight + 0.1)

        logger.info(f"[ExperienceLayer] Absorbed writeup '{writeup.title}' into Experience Layer.")

    def get_priority_multiplier(self, vulnerability_type: str) -> float:
        stat = self._stats.get(vulnerability_type)
        if not stat:
            return 1.0
        return stat.historical_confidence_weight

    def get_all_stats(self) -> Dict[str, Any]:
        return {
            vtype: {
                "total_attempts": s.total_attempts,
                "successful_verifications": s.successful_verifications,
                "falsified_attempts": s.falsified_attempts,
                "confidence_weight": s.historical_confidence_weight
            }
            for vtype, s in self._stats.items()
        }
