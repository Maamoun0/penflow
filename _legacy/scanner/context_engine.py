import asyncio
import time
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

from penflow.graph.prioritizer import ScanTarget
from penflow.network.http_client import HttpClient
from penflow.utils.logger import get_logger
from penflow.core.event_bus import EventBus
from penflow.core.plugin_manager import PluginManager

logger = get_logger("penflow.scanner.context_engine")

@dataclass
class Finding:
    vuln_type: str
    url: str
    method: str
    param: str
    payload: str
    confidence: float
    raw_request: str
    raw_response: str
    
    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "url": self.url,
            "method": self.method,
            "param": self.param,
            "payload": self.payload,
            "confidence": self.confidence,
            "raw_request": self.raw_request,
            "raw_response": self.raw_response
        }

@dataclass
class ScanResult:
    target: ScanTarget
    findings: List[Finding]
    scan_time_ms: int

class ContextVulnEngine:
    def __init__(self, http_client: HttpClient, plugin_manager: PluginManager):
        self.http_client = http_client
        self.plugin_manager = plugin_manager
        self.event_bus = EventBus.get_instance()
        self._load_detectors()

    def _load_detectors(self):
        # Dynamically load all detector plugins
        self.detectors = {}
        plugins = self.plugin_manager.get_plugins("detector")
        for p in plugins:
            # Group detectors by the vuln types they handle (assuming they have supported_types property)
            if hasattr(p, 'supported_types'):
                for t in p.supported_types:
                    self.detectors[t] = p

    async def scan(self, targets: List[ScanTarget]) -> List[ScanResult]:
        logger.info(f"Starting precision scan on {len(targets)} prioritized targets...")
        results = []
        
        # In a real scenario, we'd use a semaphore to limit concurrency
        # For this prototype, we'll process sequentially or in small batches
        
        for target in targets:
            start_time = time.monotonic()
            
            # Select appropriate detector based on target vuln_type
            detector = self.detectors.get(target.vuln_type)
            findings = []
            
            if detector:
                try:
                    logger.debug(f"Running {detector.name()} against {target.url}")
                    # Convert ScanTarget to endpoint dict required by detector
                    endpoint = {
                        "url": target.url,
                        "method": target.method,
                        "params": target.params
                    }
                    
                    # Detectors should return a list of dicts that we convert to Finding
                    raw_findings = await detector.detect(endpoint, self.http_client, config=target.scan_config)
                    
                    for rf in raw_findings:
                        finding = Finding(**rf)
                        findings.append(finding)
                        
                        # Emit event immediately when found
                        await self.event_bus.emit("VULN_DETECTED", finding.to_dict())
                        
                except Exception as e:
                    logger.error(f"Detector {target.vuln_type} failed on {target.url}: {e}")
            else:
                logger.warning(f"No detector available for {target.vuln_type}")
                
            elapsed = int((time.monotonic() - start_time) * 1000)
            
            result = ScanResult(
                target=target,
                findings=findings,
                scan_time_ms=elapsed
            )
            results.append(result)
            
        logger.info(f"Precision scan completed. Found {sum(len(r.findings) for r in results)} potential vulnerabilities.")
        return results
