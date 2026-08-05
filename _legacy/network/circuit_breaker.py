import asyncio
import time
from enum import Enum
from typing import Dict

from penflow.config import Config
from penflow.utils.logger import get_logger

logger = get_logger("penflow.network.circuit_breaker")

class CircuitState(Enum):
    CLOSED = "CLOSED"      # Normal operation, requests flow freely
    OPEN = "OPEN"          # Circuit broken, requests fail immediately
    HALF_OPEN = "HALF_OPEN"  # Testing recovery, single request allowed

class DomainCircuit:
    def __init__(self, failure_threshold: int, recovery_timeout: int, half_open_max: int):
        self.state = CircuitState.CLOSED
        self.failures = 0
        self.successes_in_half_open = 0
        
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max = half_open_max
        
        self.last_failure_time = 0.0
        self.lock = asyncio.Lock()

    async def can_execute(self) -> bool:
        async with self.lock:
            if self.state == CircuitState.CLOSED:
                return True
                
            if self.state == CircuitState.OPEN:
                # Check if recovery timeout has passed
                if time.time() - self.last_failure_time > self.recovery_timeout:
                    self.state = CircuitState.HALF_OPEN
                    self.successes_in_half_open = 0
                    logger.info("Circuit moving to HALF_OPEN state. Testing connection.")
                    return True
                return False
                
            if self.state == CircuitState.HALF_OPEN:
                # Only allow a limited number of test requests
                if self.successes_in_half_open < self.half_open_max:
                    return True
                return False
                
        return False

    async def record_success(self):
        async with self.lock:
            if self.state == CircuitState.HALF_OPEN:
                self.successes_in_half_open += 1
                if self.successes_in_half_open >= self.half_open_max:
                    self.state = CircuitState.CLOSED
                    self.failures = 0
                    logger.info("Circuit recovered. Moving to CLOSED state.")
            elif self.state == CircuitState.CLOSED:
                self.failures = 0

    async def record_failure(self):
        async with self.lock:
            self.last_failure_time = time.time()
            
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.OPEN
                logger.warning("Circuit test failed. Moving back to OPEN state.")
                
            elif self.state == CircuitState.CLOSED:
                self.failures += 1
                if self.failures >= self.failure_threshold:
                    self.state = CircuitState.OPEN
                    logger.error(f"Circuit broken! Threshold reached ({self.failure_threshold} failures). Moving to OPEN state.")

class CircuitBreaker:
    def __init__(self):
        self.config = Config.load()
        self.failure_threshold = self.config.get("circuit_breaker.failure_threshold", 5)
        self.recovery_timeout = self.config.get("circuit_breaker.recovery_timeout_seconds", 30)
        self.half_open_max = self.config.get("circuit_breaker.half_open_max_calls", 3)
        
        self.circuits: Dict[str, DomainCircuit] = {}
        self._lock = asyncio.Lock()

    async def get_circuit(self, domain: str) -> DomainCircuit:
        async with self._lock:
            if domain not in self.circuits:
                self.circuits[domain] = DomainCircuit(
                    self.failure_threshold, 
                    self.recovery_timeout, 
                    self.half_open_max
                )
            return self.circuits[domain]

    async def can_execute(self, domain: str) -> bool:
        circuit = await self.get_circuit(domain)
        return await circuit.can_execute()

    async def record_success(self, domain: str):
        circuit = await self.get_circuit(domain)
        await circuit.record_success()

    async def record_failure(self, domain: str):
        circuit = await self.get_circuit(domain)
        await circuit.record_failure()
