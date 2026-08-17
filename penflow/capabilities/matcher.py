from typing import List, Tuple, Optional
from penflow.capabilities.registry import CapabilityRegistry
from penflow.capabilities.capability import Capability
from penflow.capabilities.interfaces import ICapabilityProvider
from penflow.capabilities.exceptions import CapabilityNotFoundError

CAPABILITY_ALIASES = {
    "nosql_sqli_injection": ["nosql_injection", "sql_injection"],
    "nosql_injection": ["nosql_injection"],
    "sql_injection": ["sql_injection"],
    "sqli_vulnerability": ["sqli_vulnerability", "sql_injection"],
    "ssrf_analysis": ["ssrf_metadata_exfiltration"],
    "cors_misconfiguration": ["cors_misconfig_check"],
    "security_headers": ["security_config_audit"],
    "security_config": ["security_config_audit"],
    "idor": ["id_access_analysis", "authorization", "bola_check"],
    "bfla": ["bfla_analysis", "privilege_analysis", "method_tampering"],
    "graphql": ["graphql_analysis", "graphql_introspection"],
    "xss": ["reflected_xss", "stored_xss"],
    "xss_injection": ["reflected_xss", "stored_xss"],   # legacy alias fixed
    "reflected_xss": ["reflected_xss"],
    "stored_xss": ["stored_xss"],
    "file_upload_bypass": ["file_upload_bypass"],
    "file_upload": ["file_upload_bypass"],
    "rce": ["command_injection", "ssti_analysis"],
    # JWT/OAuth aliases
    "jwt": ["jwt_security_analysis", "oauth_state_verification", "jwt_alg_confusion_and_jwks"],
    "jwt_validation": ["jwt_security_analysis", "jwt_alg_confusion_and_jwks"],          # fix broken
    "jwt_security": ["jwt_security_analysis", "jwt_alg_confusion_and_jwks"],
    "oauth_jwt_validation": ["jwt_security_analysis", "oauth_state_verification"],
    "oauth_jwt_validation": ["jwt_security_analysis", "oauth_state_verification", "oauth_pkce_deep_audit"],
    "oauth_misconfiguration": ["oauth_state_verification", "oauth_pkce_deep_audit"],     # fix broken
    "oauth_pkce": ["oauth_pkce_deep_audit"],
    # Race condition aliases
    "race_condition": ["race_condition_check", "concurrency_burst"],
    "race_condition_analysis": ["race_condition_check", "concurrency_burst"],             # fix broken
    # WebSocket aliases
    "websocket": ["cswsh_vulnerability", "websocket_security"],
    "websocket_auth_flaw": ["cswsh_vulnerability", "websocket_security"],                # fix broken
    "cswsh": ["cswsh_vulnerability"],
    # Other aliases
    "subdomain_takeover": ["subdomain_takeover_check"],
    "http_smuggling": ["http_smuggling_desync", "cl0_smuggling"],
    "cache_poisoning": ["cache_poisoning", "host_header_injection", "cpdos_analysis", "framework_cache_poisoning"],
    "xxe": ["xxe_injection", "xml_parser_analysis", "oob_xxe"],
    "ato": ["account_takeover", "password_reset_poisoning", "mfa_bypass_analysis"],
    "account_takeover": ["account_takeover", "password_reset_poisoning", "mfa_bypass_analysis"],
    "prototype_pollution": ["prototype_pollution", "server_side_pollution"],
    "business_logic": ["business_logic_bypass", "workflow_state_tampering", "price_manipulation"],
    "rate_limit": ["rate_limit_bypass"],
    "rate_limit_bypass": ["rate_limit_bypass"],
    "open_redirect": ["open_redirect"],
    "path_traversal": ["path_traversal", "file_inclusion"],
    "lfi": ["file_inclusion", "path_traversal"],
    "command_injection": ["command_injection"],
    "ssti": ["ssti_analysis", "polyglot_ssti"],
    "ssti_rce_analysis": ["ssti_analysis", "polyglot_ssti"],
    "info_disclosure": ["info_disclosure"],
    "saml": ["saml_auth_bypass"],
    "cors": ["cors_misconfig_check"],
    "parameter_tampering": ["parameter_tampering", "parameter_discovery"],
    "mass_assignment": ["mass_assignment", "parameter_tampering"],
    "mass_assignment_analysis": ["mass_assignment", "parameter_tampering"],
    "authorization": ["id_access_analysis", "authorization", "bola_check", "bfla_analysis"],
    "privilege_analysis": ["privilege_analysis", "bfla_analysis"],
    "function_level_access": ["bfla_analysis", "privilege_analysis", "method_tampering"],
}

class CapabilityMatcher:
    """
    Matches abstract capability string requests (e.g. "idor", "graphql", "jwt") to registered providers.
    """
    def __init__(self, registry: CapabilityRegistry):
        self.registry = registry

    def match(self, capability_id: str) -> List[Tuple[ICapabilityProvider, str]]:
        providers = self.registry.get_providers(capability_id)
        if providers:
            return providers

        # Try aliases
        if capability_id in CAPABILITY_ALIASES:
            for alias in CAPABILITY_ALIASES[capability_id]:
                alias_providers = self.registry.get_providers(alias)
                if alias_providers:
                    return alias_providers

        # Try tag-based matching
        for reg_cap in self.registry.get_all_capabilities():
            if capability_id in reg_cap.tags or reg_cap.id in capability_id or capability_id in reg_cap.id:
                tag_providers = self.registry.get_providers(reg_cap.id)
                if tag_providers:
                    return tag_providers

        # Fallback: check if capability matches any agent
        return []
