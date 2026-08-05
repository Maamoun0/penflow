from dataclasses import dataclass, field
from typing import Dict, List, Any
from penflow.shared.utils import get_utc_timestamp

@dataclass
class DNSRecord:
    domain: str
    record_type: str  # A, AAAA, CNAME, TXT, MX, NS, SOA
    value: str
    timestamp: float = field(default_factory=get_utc_timestamp)

class DNSDiscoveryEngine:
    """
    DNS Record collection and historical change tracker.
    """
    def __init__(self):
        self._dns_history: Dict[str, List[DNSRecord]] = {}  # domain -> List[DNSRecord]

    def record_dns_entry(self, domain: str, record_type: str, value: str) -> DNSRecord:
        domain_clean = domain.strip().lower()
        if domain_clean not in self._dns_history:
            self._dns_history[domain_clean] = []

        rec = DNSRecord(domain=domain_clean, record_type=record_type.upper(), value=value)
        self._dns_history[domain_clean].append(rec)
        return rec

    def get_dns_history(self, domain: str) -> List[DNSRecord]:
        return list(self._dns_history.get(domain.strip().lower(), []))
