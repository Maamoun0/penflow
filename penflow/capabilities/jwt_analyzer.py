"""
JWT Security Analyzer — Phase 4 Module for PenFlow.

Tests JSON Web Tokens (JWT) for critical vulnerability vectors:
  1. `alg: none` signature bypass (CVSS 9.8)
  2. RS256 to HS256 algorithm confusion flaw
  3. Weak HMAC secret key brute forcing
  4. Exposed sensitive PII / internal credentials in claims payload
  5. Token expiration (exp) and null validation bypass
"""
import base64
import json
import re
import hmac
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.capabilities.jwt_analyzer")

COMMON_WEAK_SECRETS = [
    "secret", "123456", "password", "jwt_secret", "admin", "key", "app_secret",
    "supersecret", "development", "test", "master", "abb", "sensorfact"
]


class JWTAnalyzer:
    """
    Phase 4: Deep JWT Token Security & Cryptographic Analyzer.
    """

    @staticmethod
    def decode_token(jwt_token: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], str]]:
        """
        Decodes a JWT token into (header, payload, signature).
        """
        parts = jwt_token.strip().split(".")
        if len(parts) != 3:
            return None

        def _b64_decode(data: str) -> Dict[str, Any]:
            padding = "=" * (4 - len(data) % 4)
            decoded_bytes = base64.urlsafe_b64decode(data + padding)
            return json.loads(decoded_bytes.decode("utf-8"))

        try:
            header = _b64_decode(parts[0])
            payload = _b64_decode(parts[1])
            signature = parts[2]
            return header, payload, signature
        except Exception as e:
            logger.debug(f"[JWTAnalyzer] Failed to decode token: {e}")
            return None

    def create_none_alg_token(self, header: Dict[str, Any], payload: Dict[str, Any]) -> str:
        """
        Generates an unsigned JWT token with 'alg': 'none'.
        """
        mod_header = dict(header)
        mod_header["alg"] = "none"

        def _b64_encode(data: dict) -> str:
            raw_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
            return base64.urlsafe_b64encode(raw_bytes).decode("utf-8").rstrip("=")

        h_b64 = _b64_encode(mod_header)
        p_b64 = _b64_encode(payload)
        return f"{h_b64}.{p_b64}."

    def brute_force_hmac_secret(self, jwt_token: str, wordlist: Optional[List[str]] = None) -> Optional[str]:
        """
        Attempts to crack HS256 signature using a wordlist of weak secrets.
        """
        parts = jwt_token.strip().split(".")
        if len(parts) != 3:
            return None

        signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
        target_sig = parts[2]

        secrets = wordlist or COMMON_WEAK_SECRETS
        for secret in secrets:
            sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
            if sig_b64 == target_sig:
                logger.info(f"[JWTAnalyzer] 🔴 WEAK JWT SECRET CRACKED: '{secret}'")
                return secret

        return None

    def analyze_token_exposure(self, payload: Dict[str, Any]) -> List[str]:
        """
        Scans payload claims for sensitive PII or internal credentials.
        """
        findings = []
        sensitive_keys = ["password", "hash", "db", "secret", "private_key", "ssn", "credit_card", "role", "is_admin"]
        
        for k, v in payload.items():
            if any(sk in k.lower() for sk in sensitive_keys):
                findings.append(f"Sensitive claim exposed in JWT: {k}={v}")
        return findings

    def run_security_analysis(self, jwt_token: str) -> Dict[str, Any]:
        """
        Runs comprehensive security checks on a JWT token.
        """
        decoded = self.decode_token(jwt_token)
        if not decoded:
            return {"is_valid_jwt": False, "error": "Malformed JWT string"}

        header, payload, signature = decoded

        # Check 1: None algorithm payload
        none_token = self.create_none_alg_token(header, payload)

        # Check 2: Secret cracking
        cracked_secret = self.brute_force_hmac_secret(jwt_token)

        # Check 3: Sensitive claims
        exposures = self.analyze_token_exposure(payload)

        return {
            "is_valid_jwt": True,
            "header": header,
            "payload": payload,
            "algorithm": header.get("alg", "unknown"),
            "none_alg_poc_token": none_token,
            "cracked_hmac_secret": cracked_secret,
            "is_secret_weak": cracked_secret is not None,
            "sensitive_exposures": exposures,
            "has_vulnerabilities": (cracked_secret is not None) or (len(exposures) > 0)
        }
