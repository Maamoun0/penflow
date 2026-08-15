import difflib
import json
import re
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Set
from penflow.traffic.models import (
    TrafficExchange,
    DiffResult,
    DiffField,
)
from penflow.analysis.response_intelligence import DeceptiveResponseDetector
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.traffic.diff_engine")

SENSITIVE_KEY_PATTERNS = [
    r"user_?id", r"account_?id", r"email", r"phone", r"ssn", r"balance",
    r"credit_?card", r"token", r"secret", r"password", r"role", r"tenant_?id",
    r"invoice_?id", r"order_?id", r"private", r"profile", r"document_?id"
]

UUID_REGEX = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
MONGO_ID_REGEX = re.compile(r"^[0-9a-fA-F]{24}$")

class DifferentialEngine:
    """
    Cognitive differential analysis engine that compares multi-tenant HTTP exchanges
    to deterministically identify Broken Object Level Authorization (BOLA/IDOR),
    Broken Function Level Authorization (BFLA), and information disclosure.
    """

    def compare_exchanges(
        self,
        exchange_a: TrafficExchange,
        exchange_b: TrafficExchange,
        context_asset: str = ""
    ) -> DiffResult:
        resp_a = exchange_a.response
        resp_b = exchange_b.response

        url_a = exchange_a.request.url if exchange_a.request else context_asset
        ident_a = exchange_a.identity_used or "Identity A"
        ident_b = exchange_b.identity_used or "Identity B"

        if not resp_a or not resp_b:
            return DiffResult(
                endpoint_url=url_a,
                identity_a=ident_a,
                identity_b=ident_b,
                status_code_a=resp_a.status_code if resp_a else 0,
                status_code_b=resp_b.status_code if resp_b else 0,
                body_similarity_ratio=0.0,
                length_delta=0,
                structural_match=False,
                confidence_score=0.0,
                reasoning="Incomplete exchange data."
            )

        status_a = resp_a.status_code
        status_b = resp_b.status_code

        # Similarity calculation
        matcher = difflib.SequenceMatcher(None, resp_a.body_text, resp_b.body_text)
        similarity_ratio = round(matcher.ratio(), 4)
        length_delta = abs(resp_a.content_length - resp_b.content_length)

        # JSON structural comparison
        json_a = resp_a.body_json
        json_b = resp_b.body_json
        structural_match = False
        discrepant_fields: List[DiffField] = []
        leaked_identifiers: List[str] = []

        if json_a is not None and json_b is not None:
            structural_match = self._compare_json_structures(json_a, json_b)
            discrepant_fields = self._find_json_field_differences(json_a, json_b)
            leaked_identifiers = list(self.extract_identifiers(json_b))
        elif resp_a.body_text and resp_b.body_text:
            structural_match = (similarity_ratio > 0.85)

        # Heuristic rules for BOLA/IDOR and BFLA
        is_potential_idor = False
        is_potential_bfla = False
        confidence = 0.0
        reasons: List[str] = []

        # URL inspection
        url_lower = url_a.lower()
        parsed_url = urllib.parse.urlparse(url_lower)
        url_path = parsed_url.path.rstrip("/")
        is_root_or_empty = url_path in ("", "/")
        is_public_catalog = any(p in url_path for p in ["/product", "/item", "/catalog", "/category", "/post", "/article", "/doc", "/help", "/about", "/terms", "/privacy", "/blog", "/image", "/resource", "/css", "/js"])

        # Case 1: Both users access a private/tenant resource and receive HTTP 200 with matching schema
        is_b_deceptive = DeceptiveResponseDetector.is_deceptive_success(status_b, resp_b.body_text)
        if not is_root_or_empty and not is_public_catalog and status_a == 200 and status_b == 200 and not is_b_deceptive:
            is_json_response = (json_a is not None and json_b is not None)
            is_private_tenant_url = any(p in url_path for p in ["/user", "/account", "/order", "/invoice", "/profile", "/me", "/billing", "/wallet", "/tenant", "/customer"])
            
            if structural_match:
                sensitive_matches = [f for f in discrepant_fields if f.is_sensitive]
                
                # Check for sensitive PII in structured JSON response
                if is_json_response and (sensitive_matches or is_private_tenant_url):
                    is_potential_idor = True
                    confidence = 0.95 if sensitive_matches else 0.85
                    reasons.append(
                        f"Both {ident_a} and unauthorized {ident_b} received HTTP 200 on private JSON endpoint '{url_a}' "
                        f"with structural schema match (Similarity={similarity_ratio*100:.1f}%)."
                    )
                    if sensitive_matches:
                        reasons.append(f"Sensitive fields accessed across tenant boundary: {[f.field_path for f in sensitive_matches]}")
                elif not is_json_response and is_private_tenant_url:
                    # For HTML, 100% similarity on a page without authentication headers is public content, not IDOR
                    body_b_lower = resp_b.body_text.lower()
                    is_login_page = "login" in body_b_lower or "sign in" in body_b_lower
                    if not is_login_page and similarity_ratio < 0.99:
                        is_potential_idor = True
                        confidence = 0.85
                        reasons.append(f"Unauthorized identity '{ident_b}' accessed private tenant resource '{url_a}' without segregation.")

        # Case 2: Guest or Standard User accessed Admin function successfully (BFLA)
        admin_indicators = ["admin", "manage", "delete", "update_role", "system", "config"]
        if any(ind in url_a.lower() for ind in admin_indicators) and status_b == 200:
            is_potential_bfla = True
            confidence = max(confidence, 0.90)
            reasons.append(f"Unauthorized identity '{ident_b}' successfully accessed privileged admin endpoint '{url_a}' (HTTP 200).")

        # Case 3: Proper isolation (User A gets 200, User B gets 401/403/404)
        if status_a == 200 and status_b in [401, 403, 404]:
            confidence = 0.0
            reasons.append(f"Authorization boundary enforced properly: {ident_a} received 200, while {ident_b} received {status_b}.")

        reasoning_text = " | ".join(reasons) if reasons else "No clear authorization breach observed."

        return DiffResult(
            endpoint_url=url_a,
            identity_a=ident_a,
            identity_b=ident_b,
            status_code_a=status_a,
            status_code_b=status_b,
            body_similarity_ratio=similarity_ratio,
            length_delta=length_delta,
            structural_match=structural_match,
            discrepant_fields=discrepant_fields,
            leaked_identifiers=leaked_identifiers,
            is_potential_idor=is_potential_idor,
            is_potential_bfla=is_potential_bfla,
            confidence_score=confidence,
            reasoning=reasoning_text,
            evidence_exchange_a=exchange_a,
            evidence_exchange_b=exchange_b
        )

    def _compare_json_structures(self, obj_a: Any, obj_b: Any) -> bool:
        if type(obj_a) != type(obj_b):
            return False
        if isinstance(obj_a, dict):
            keys_a = set(obj_a.keys())
            keys_b = set(obj_b.keys())
            overlap = keys_a.intersection(keys_b)
            if not keys_a and not keys_b:
                return True
            return len(overlap) / max(len(keys_a), len(keys_b), 1) >= 0.70
        elif isinstance(obj_a, list):
            if not obj_a and not obj_b:
                return True
            if obj_a and obj_b:
                return self._compare_json_structures(obj_a[0], obj_b[0])
            return True
        return True

    def _find_json_field_differences(self, obj_a: Any, obj_b: Any, path: str = "") -> List[DiffField]:
        diffs: List[DiffField] = []
        if isinstance(obj_a, dict) and isinstance(obj_b, dict):
            all_keys = set(obj_a.keys()).union(set(obj_b.keys()))
            for k in all_keys:
                current_path = f"{path}.{k}" if path else k
                val_a = obj_a.get(k)
                val_b = obj_b.get(k)
                
                is_sens = any(re.search(pat, k, re.IGNORECASE) for pat in SENSITIVE_KEY_PATTERNS)

                if k not in obj_a or k not in obj_b or val_a != val_b:
                    diffs.append(DiffField(
                        field_path=current_path,
                        val_a=val_a,
                        val_b=val_b,
                        is_sensitive=is_sens
                    ))
                if isinstance(val_a, (dict, list)) and isinstance(val_b, (dict, list)):
                    diffs.extend(self._find_json_field_differences(val_a, val_b, current_path))
        return diffs

    def extract_identifiers(self, data: Any) -> Set[str]:
        """
        Recursively extracts potential resource IDs (UUIDs, MongoIDs, sequential ints)
        from parameters or JSON response objects.
        """
        identifiers: Set[str] = set()
        if isinstance(data, dict):
            for k, v in data.items():
                if any(re.search(pat, k, re.IGNORECASE) for pat in [r"_id$", r"^id$", r"uuid"]):
                    if isinstance(v, (str, int)):
                        identifiers.add(str(v))
                if isinstance(v, str):
                    if UUID_REGEX.match(v) or MONGO_ID_REGEX.match(v):
                        identifiers.add(v)
                elif isinstance(v, (dict, list)):
                    identifiers.update(self.extract_identifiers(v))
        elif isinstance(data, list):
            for item in data:
                identifiers.update(self.extract_identifiers(item))
        elif isinstance(data, str):
            if UUID_REGEX.match(data) or MONGO_ID_REGEX.match(data):
                identifiers.add(data)
        return identifiers
