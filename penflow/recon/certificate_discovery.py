from dataclasses import dataclass, field
from typing import List, Set, Optional
from penflow.shared.utils import get_utc_timestamp

@dataclass
class CertificateEntry:
    serial_number: str
    issuer: str
    subject_alt_names: Set[str] = field(default_factory=set)
    valid_from: float = 0.0
    valid_to: float = 0.0
    is_expired: bool = False

class CertificateDiscoveryEngine:
    """
    Certificate Transparency (CT) log and SAN entry tracking engine.
    """
    def __init__(self):
        self._certificates: List[CertificateEntry] = []

    def record_certificate(self, serial: str, issuer: str, san_entries: List[str], valid_from: float, valid_to: float) -> CertificateEntry:
        now = get_utc_timestamp()
        is_expired = now > valid_to
        cert = CertificateEntry(
            serial_number=serial,
            issuer=issuer,
            subject_alt_names=set(san_entries),
            valid_from=valid_from,
            valid_to=valid_to,
            is_expired=is_expired
        )
        self._certificates.append(cert)
        return cert

    def get_all_san_domains(self) -> Set[str]:
        all_domains = set()
        for cert in self._certificates:
            all_domains.update(cert.subject_alt_names)
        return all_domains
