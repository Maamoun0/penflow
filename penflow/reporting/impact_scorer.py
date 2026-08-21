"""
Business Impact Scoring Engine for PenFlow.

Capabilities:
  - Translates technical vulnerabilities into business impact metrics:
      • Financial Fraud / Payment Data Compromise
      • Personally Identifiable Information (PII) Data Exfiltration
      • Administrative Privilege Escalation
      • Remote System Infrastructure Takeover
"""
from typing import Dict, Any
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.reporting.impact_scorer")

IMPACT_MAPPINGS = {
    "ssrf": {
        "business_impact": "An unauthenticated attacker can pivot into internal private network boundaries, access AWS/GCP cloud instance metadata credentials (IAM keys), and achieve full infrastructure compromise.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-918"
    },
    "ssrf_redirect_chain": {
        "business_impact": "An attacker can bypass network firewall filters via HTTP redirect chaining to reach internal management endpoints and leak internal services.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "cwe": "CWE-918"
    },
    "idor": {
        "business_impact": "An attacker can systematically enumerate and exfiltrate private user PII, order histories, and financial records belonging to all tenants across the platform.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-639"
    },
    "jwt_security_analysis": {
        "business_impact": "An attacker can forge administrative JWT tokens using 'alg: none' or key confusion, completely bypassing authentication to control any user account.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-347"
    },
    "polyglot_ssti": {
        "business_impact": "An attacker can execute arbitrary remote code on the web server host process, gaining interactive shell access and compromising system databases.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-1336"
    },
    "orm_leak": {
        "business_impact": "An attacker can exploit ORM filter parameter parsing differentials to extract hidden database columns and exfiltrate database records.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-89"
    },
    "framework_cache_poisoning": {
        "business_impact": "An attacker can poison CDN and edge proxy caches with malicious unkeyed headers, serving compromised JavaScript payloads to all visiting legitimate users.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        "cwe": "CWE-444"
    },
    "prompt_injection_audit": {
        "business_impact": "An attacker can override system instructions in downstream AI features, forcing the model to exfiltrate private tenant data or run arbitrary tool actions.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-1393"
    },
    "rag_poisoning_audit": {
        "business_impact": "An attacker can inject malicious instruction text into shared knowledge base documents, hijacking context retrieval for all enterprise users.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-1393"
    },
    "ai_agent_security_audit": {
        "business_impact": "An attacker can trick autonomous AI agents into executing arbitrary system commands or unauthorized tool calls with server privileges.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-77"
    },
    "nosql_injection": {
        "business_impact": "An attacker can inject NoSQL query operators ($ne, $gt) into JSON requests to bypass login authentication without a valid password.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-943"
    },
    "ai_supply_chain_security": {
        "business_impact": "Exposed OpenAI/HuggingFace API keys in configuration files allow unauthorized third parties to hijack AI infrastructure and bill usage to the victim organization.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-798"
    },
    "cspt": {
        "business_impact": "Client-Side Path Traversal enables an attacker to manipulate fetch/XHR path routing in single-page applications, performing unauthorized API operations within the victim's session context.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe": "CWE-22"
    },
    "client_side_path_traversal": {
        "business_impact": "Client-Side Path Traversal enables an attacker to manipulate fetch/XHR path routing in single-page applications, performing unauthorized API operations within the victim's session context.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe": "CWE-22"
    },
    "oauth_csrf": {
        "business_impact": "Missing or unvalidated state parameters during OAuth authorization permit account takeover by linking the victim's identity provider account to an attacker-controlled profile.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "cwe": "CWE-352"
    },
    "missing_headers": {
        "business_impact": "Absence of hardening HTTP security headers (such as CSP, HSTS, X-Frame-Options) reduces defense-in-depth protections against client-side side-channel attacks.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "cwe": "CWE-693"
    },
    "path_traversal": {
        "business_impact": "Path traversal sequences permit reading arbitrary local files outside the web root, exposing configuration secrets and system user credentials.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-22"
    },
    "xss": {
        "business_impact": "Cross-Site Scripting allows execution of arbitrary client-side JavaScript in the victim's browser session, enabling session hijacking and DOM manipulation.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-79"
    }
}


from penflow.domain.vulnerability_types import normalize_vulnerability_type, VULN_OAUTH


IMPACT_MAPPINGS = {
    "ssrf": {
        "business_impact": "An unauthenticated attacker can pivot into internal private network boundaries, access AWS/GCP cloud instance metadata credentials (IAM keys), and achieve full infrastructure compromise.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-918"
    },
    "ssrf_redirect_chain": {
        "business_impact": "An attacker can bypass network firewall filters via HTTP redirect chaining to reach internal management endpoints and leak internal services.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "cwe": "CWE-918"
    },
    "idor": {
        "business_impact": "An attacker can systematically enumerate and exfiltrate private user PII, order histories, and financial records belonging to all tenants across the platform.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-639"
    },
    "bola": {
        "business_impact": "Broken Object Level Authorization allows an authenticated user to manipulate object IDs in API requests to access or modify unauthorized user resources.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-639"
    },
    "bfla": {
        "business_impact": "Broken Function Level Authorization allows non-admin users to invoke privileged administrative API endpoints and perform unauthorized state changes.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-285"
    },
    "oauth_misconfiguration": {
        "business_impact": "Missing or unvalidated state parameters / redirect_uri validation during OAuth authorization permits account takeover by linking the victim's identity provider account to an attacker-controlled profile.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N",
        "cwe": "CWE-352"
    },
    "oauth_missing_state": {
        "business_impact": "Missing or unvalidated state parameters / redirect_uri validation during OAuth authorization permits account takeover.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N",
        "cwe": "CWE-352"
    },
    "jwt_validation": {
        "business_impact": "An attacker can forge administrative JWT tokens using 'alg: none' or key confusion, completely bypassing authentication to control any user account.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-347"
    },
    "polyglot_ssti": {
        "business_impact": "An attacker can execute arbitrary remote code on the web server host process, gaining interactive shell access and compromising system databases.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-1336"
    },
    "ssti_rce": {
        "business_impact": "Server-Side Template Injection permits executing arbitrary code on the web server host process, gaining interactive shell access and compromising system databases.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-1336"
    },
    "sql_injection": {
        "business_impact": "SQL Injection enables an attacker to execute arbitrary SQL queries, bypassing authentication, reading sensitive database contents, and modifying data.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-89"
    },
    "command_injection": {
        "business_impact": "Command Injection allows an unauthenticated attacker to execute system commands directly on the host operating system.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-77"
    },
    "orm_leak": {
        "business_impact": "An attacker can exploit ORM filter parameter parsing differentials to extract hidden database columns and exfiltrate database records.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-89"
    },
    "framework_cache_poisoning": {
        "business_impact": "An attacker can poison CDN and edge proxy caches with malicious unkeyed headers, serving compromised JavaScript payloads to all visiting legitimate users.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        "cwe": "CWE-444"
    },
    "prompt_injection_audit": {
        "business_impact": "An attacker can override system instructions in downstream AI features, forcing the model to exfiltrate private tenant data or run arbitrary tool actions.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-1393"
    },
    "rag_poisoning_audit": {
        "business_impact": "An attacker can inject malicious instruction text into shared knowledge base documents, hijacking context retrieval for all enterprise users.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-1393"
    },
    "ai_agent_security_audit": {
        "business_impact": "An attacker can trick autonomous AI agents into executing arbitrary system commands or unauthorized tool calls with server privileges.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-77"
    },
    "nosql_injection": {
        "business_impact": "An attacker can inject NoSQL query operators ($ne, $gt) into JSON requests to bypass login authentication without a valid password.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-943"
    },
    "ai_supply_chain_security": {
        "business_impact": "Exposed OpenAI/HuggingFace API keys in configuration files allow unauthorized third parties to hijack AI infrastructure and bill usage to the victim organization.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-798"
    },
    "cspt": {
        "business_impact": "Client-Side Path Traversal enables an attacker to manipulate fetch/XHR path routing in single-page applications, performing unauthorized API operations within the victim's session context.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe": "CWE-22"
    },
    "oauth_csrf": {
        "business_impact": "Missing or unvalidated state parameters during OAuth authorization permit account takeover by linking the victim's identity provider account to an attacker-controlled profile.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N",
        "cwe": "CWE-352"
    },
    "missing_headers": {
        "business_impact": "Absence of hardening HTTP security headers (such as CSP, HSTS, X-Frame-Options) reduces defense-in-depth protections against client-side side-channel attacks.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "cwe": "CWE-693"
    },
    "open_redirect": {
        "business_impact": "Unvalidated open redirects allow attackers to craft trustworthy-looking phishing URLs that redirect victims to malicious credential-harvesting destinations.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-601"
    },
    "path_traversal": {
        "business_impact": "Path traversal sequences permit reading arbitrary local files outside the web root, exposing configuration secrets and system user credentials.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-22"
    },
    "xss": {
        "business_impact": "Cross-Site Scripting allows execution of arbitrary client-side JavaScript in the victim's browser session, enabling session hijacking and DOM manipulation.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-79"
    },
    "info_disclosure": {
        "business_impact": "Sensitive information disclosure leaks internal endpoint patterns, software version banners, or technical stack details to unauthorized third parties.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200"
    },
    "saml_auth_bypass": {
        "business_impact": "SAML response signature wrapping or assertion manipulation allows an unauthenticated attacker to bypass single sign-on (SSO) authentication.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-347"
    },
    "webauthn_passkey_bypass": {
        "business_impact": "WebAuthn / Passkey signature verification flaws allow an attacker to bypass multi-factor authentication.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-287"
    },
    "account_takeover": {
        "business_impact": "Flaws in password reset or session management workflows permit an unauthenticated attacker to seize complete control of arbitrary user accounts.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        "cwe": "CWE-640"
    },
    "crlf_injection": {
        "business_impact": "CRLF Injection allows splitting HTTP response headers to introduce arbitrary response headers or perform HTTP response splitting attacks.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe": "CWE-113"
    },
    "api_version_regression": {
        "business_impact": "Exposed deprecated API endpoint versions lack modern security controls, enabling attackers to bypass current authentication protections.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-1188"
    },
    "double_clickjacking": {
        "business_impact": "Lack of X-Frame-Options or CSP frame-ancestors permits framing the target application to trick users into executing unintended UI actions.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "cwe": "CWE-1021"
    },
    "mcp_server_vulnerability": {
        "business_impact": "Model Context Protocol (MCP) server integration flaws allow unauthorized external prompt or context injection into host agents.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-20"
    },
    "parser_differential": {
        "business_impact": "Discrepancies in HTTP request parsing between reverse proxies and backend servers permit security control bypasses or smuggling.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe": "CWE-436"
    },
    "business_logic_bypass": {
        "business_impact": "Flaws in business workflow logic permit parameter tampering, price manipulation, or state transition bypasses.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
        "cwe": "CWE-840"
    },
    "http_parameter_pollution": {
        "business_impact": "HTTP Parameter Pollution permits overriding internal server configuration variables or bypassing web application firewall rules.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe": "CWE-235"
    },
    "websocket_auth_flaw": {
        "business_impact": "Cross-Site WebSocket Hijacking (CSWSH) permits an attacker's origin site to hijack the victim's authenticated WebSocket connection.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "cwe": "CWE-1385"
    },
    "http_smuggling": {
        "business_impact": "HTTP Request Smuggling permits bypassing front-end security controls, hijacking user web sessions, and poisoning web caches.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-444"
    },
    "race_condition_analysis": {
        "business_impact": "Race condition / limit overrun allows an attacker to bypass business logic limits (e.g. coupon redemption, fund transfer) via synchronized concurrent requests.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-362"
    },
    "cors_misconfiguration": {
        "business_impact": "Overly permissive CORS policy with arbitrary Origin reflection and Access-Control-Allow-Credentials: true permits untrusted third-party sites to exfiltrate private authenticated data.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
        "cwe": "CWE-346"
    },
    "prototype_pollution": {
        "business_impact": "Server-side prototype pollution permits injecting properties into Object.prototype, leading to property injection, privilege escalation, or Remote Code Execution (RCE).",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1321"
    },
    "xxe_injection": {
        "business_impact": "XML External Entity (XXE) injection permits an attacker to read local system configuration files, exfiltrate sensitive data, or trigger internal SSRF.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-611"
    },
    "graphql_introspection": {
        "business_impact": "Enabled GraphQL Schema Introspection leaks internal database schemas, private types, queries, and unreleased API mutations to unauthorized users.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200"
    },
    "graphql_depth_analysis": {
        "business_impact": "Unbounded GraphQL query depth allows nested circular queries that exhaust server CPU and memory resources, causing application denial of service.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400"
    },
    "mass_assignment_analysis": {
        "business_impact": "Mass Assignment allows an authenticated user to bind hidden or privileged object attributes (such as is_admin or user_role), gaining administrative access.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-915"
    }
}


class ImpactScorer:
    """
    Evaluates finding attributes and returns business impact descriptions.
    """

    def evaluate_impact(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        raw_vtype = finding.get("vulnerability_type") or finding.get("capability") or ""
        norm_type = normalize_vulnerability_type(raw_vtype)
        
        mapping = IMPACT_MAPPINGS.get(norm_type, IMPACT_MAPPINGS.get(raw_vtype.lower(), {
            "business_impact": "Unsanitized parameter handling permits unauthorized information disclosure or security control bypass.",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cwe": "CWE-200"
        }))
        return mapping

