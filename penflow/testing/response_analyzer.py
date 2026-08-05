"""
SemanticResponseAnalyzer: Intelligent response analysis engine that goes beyond
simple text comparison to detect real security issues in HTTP responses.

Capabilities:
- Sensitive data leak detection (emails, tokens, API keys, passwords, SSNs, credit cards)
- Error disclosure analysis (stack traces, SQL errors, debug info, internal paths)
- Technology fingerprint extraction from error responses
- Authorization boundary verification
- JSON structural comparison for differential analysis
"""
import re
import json
from typing import Dict, Any, List, Optional, Tuple, Set
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.testing.response_analyzer")


# ──────────────────────────────────────────────
# Sensitive Data Patterns
# ──────────────────────────────────────────────
SENSITIVE_PATTERNS = {
    "email_address": {
        "pattern": r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        "severity": "medium",
        "description": "Email address found in response"
    },
    "jwt_token": {
        "pattern": r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
        "severity": "critical",
        "description": "JWT token exposed in response body"
    },
    "api_key_generic": {
        "pattern": r'(?:api[_-]?key|apikey|api_secret|secret_key)[\s]*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})',
        "severity": "critical",
        "description": "API key or secret exposed in response"
    },
    "aws_access_key": {
        "pattern": r'AKIA[0-9A-Z]{16}',
        "severity": "critical",
        "description": "AWS Access Key ID exposed"
    },
    "aws_secret_key": {
        "pattern": r'(?:aws_secret_access_key|secret_key)[\s]*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})',
        "severity": "critical",
        "description": "AWS Secret Access Key exposed"
    },
    "private_key": {
        "pattern": r'-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----',
        "severity": "critical",
        "description": "Private key exposed in response"
    },
    "password_field": {
        "pattern": r'(?:"password"|"passwd"|"pass"|"secret"|"credential")[\s]*:\s*"[^"]{1,100}"',
        "severity": "critical",
        "description": "Password or credential value in response body"
    },
    "ssn_us": {
        "pattern": r'\b\d{3}-\d{2}-\d{4}\b',
        "severity": "critical",
        "description": "US Social Security Number pattern detected"
    },
    "credit_card": {
        "pattern": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
        "severity": "critical",
        "description": "Credit card number pattern detected"
    },
    "bearer_token": {
        "pattern": r'[Bb]earer\s+[a-zA-Z0-9_\-\.]{20,}',
        "severity": "critical",
        "description": "Bearer token exposed in response"
    },
    "internal_ip": {
        "pattern": r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
        "severity": "medium",
        "description": "Internal/private IP address leaked"
    },
    "github_token": {
        "pattern": r'gh[ps]_[a-zA-Z0-9]{36}',
        "severity": "critical",
        "description": "GitHub personal access token exposed"
    },
    "slack_token": {
        "pattern": r'xox[baprs]-[a-zA-Z0-9\-]{10,}',
        "severity": "critical",
        "description": "Slack token exposed"
    },
    "phone_number": {
        "pattern": r'(?:\+1|1)?[\s\-]?\(?[2-9]\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{4}',
        "severity": "medium",
        "description": "Phone number pattern detected"
    },
    "rce_output": {
        "pattern": r'(?:uid=\d+\([a-zA-Z0-9_\-]+\)|root:x:0:0:|Windows IP Configuration|Directory of [A-Z]:\\)',
        "severity": "critical",
        "description": "OS command execution output detected in response"
    },
    "actuator_env_leak": {
        "pattern": r'(?:spring\.datasource|management\.endpoints|server\.port|activeProfiles)',
        "severity": "critical",
        "description": "Spring Boot Actuator environment configuration leaked"
    },
    "oauth_token_leak": {
        "pattern": r'(?:access_token=|id_token=|refresh_token=)[a-zA-Z0-9_\-\.]{20,}',
        "severity": "critical",
        "description": "OAuth token or authorization parameter leaked"
    },
}

# ──────────────────────────────────────────────
# Error Disclosure Patterns
# ──────────────────────────────────────────────
ERROR_PATTERNS = {
    "sql_error": {
        "patterns": [
            r'SQL\s+syntax.*?MySQL',
            r'ORA-\d{5}',
            r'PostgreSQL.*?ERROR',
            r'microsoft.*?ODBC.*?driver',
            r'SQLite.*?error',
            r'Unclosed\s+quotation\s+mark',
            r'quoted\s+string\s+not\s+properly\s+terminated',
            r'com\.mysql\.jdbc',
            r'org\.postgresql\.util',
        ],
        "severity": "high",
        "description": "SQL error disclosure — potential SQL injection surface"
    },
    "nosql_error": {
        "patterns": [
            r'MongoError',
            r'Cannot use \'in\' operator to search for',
            r'Cast to ObjectId failed for value',
            r'org\.bson\.BsonInvalidOperationException',
            r'com\.mongodb\.MongoException',
        ],
        "severity": "high",
        "description": "NoSQL / MongoDB error disclosure — potential operator injection surface"
    },
    "ssti_error": {
        "patterns": [
            r'jinja2\.exceptions',
            r'Twig_Error_Syntax',
            r'freemarker\.core\.ParseException',
            r'VelocityException',
            r'SmartyCompilerException',
            r'org\.thymeleaf\.exceptions',
        ],
        "severity": "critical",
        "description": "Server-Side Template Engine error / stack trace disclosure"
    },
    "stack_trace": {
        "patterns": [
            r'Traceback\s+\(most\s+recent\s+call\s+last\)',
            r'at\s+[a-zA-Z0-9_$]+\.[a-zA-Z0-9_$]+\([a-zA-Z0-9_$]+\.java:\d+\)',
            r'File\s+"[^"]+",\s+line\s+\d+',
            r'Exception\s+in\s+thread\s+"[^"]+"',
            r'\.cs:line\s+\d+',
            r'at\s+\S+\s+in\s+\S+:\s*line\s+\d+',
        ],
        "severity": "medium",
        "description": "Stack trace exposed — reveals internal structure"
    },
    "debug_info": {
        "patterns": [
            r'DEBUG\s*[:=]\s*[Tt]rue',
            r'DJANGO_SETTINGS_MODULE',
            r'X-Debug-Token',
            r'laravel_session',
            r'__debugger__',
            r'Werkzeug\s+Debugger',
            r'ASPNETCORE_ENVIRONMENT.*?Development',
        ],
        "severity": "medium",
        "description": "Debug mode enabled in production"
    },
    "internal_path": {
        "patterns": [
            r'(?:/home/[a-zA-Z0-9_]+|/var/www|/usr/local|/opt/|C:\\\\Users\\\\|C:\\\\inetpub)',
            r'(?:/app/|/src/|/build/|/deploy/)',
        ],
        "severity": "low",
        "description": "Internal filesystem path disclosed"
    },
    "version_disclosure": {
        "patterns": [
            r'(?:Apache|nginx|IIS|Tomcat|Express|Kestrel)/[\d\.]+',
            r'PHP/[\d\.]+',
            r'X-Powered-By:\s*[\w\./]+',
        ],
        "severity": "low",
        "description": "Server version information disclosed"
    },
}


class SensitiveFinding:
    """A single sensitive data finding in a response."""
    def __init__(self, finding_type: str, matched_value: str, severity: str,
                 description: str, location: str = "body"):
        self.finding_type = finding_type
        self.matched_value = self._mask_value(matched_value)
        self.raw_value = matched_value
        self.severity = severity
        self.description = description
        self.location = location

    def _mask_value(self, val: str) -> str:
        """Partially mask sensitive values for safe logging."""
        if len(val) <= 6:
            return val[:2] + "****"
        return val[:4] + "****" + val[-4:]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.finding_type,
            "value_masked": self.matched_value,
            "severity": self.severity,
            "description": self.description,
            "location": self.location
        }


class SemanticResponseAnalyzer:
    """
    Analyzes HTTP responses for sensitive data leaks, error disclosures,
    and security-relevant patterns.
    """

    def analyze_response(self, status_code: int, headers: Dict[str, str],
                         body: str, context: str = "") -> Dict[str, Any]:
        """
        Perform comprehensive analysis of an HTTP response.
        Returns analysis result with findings and risk score.
        """
        findings: List[SensitiveFinding] = []
        risk_score = 0.0

        # 1. Scan body for sensitive data
        body_findings = self._scan_for_sensitive_data(body, "body")
        findings.extend(body_findings)

        # 2. Scan headers for sensitive data
        header_text = json.dumps(headers)
        header_findings = self._scan_for_sensitive_data(header_text, "headers")
        findings.extend(header_findings)

        # 3. Check for error disclosures
        error_findings = self._scan_for_error_disclosure(body)
        findings.extend(error_findings)

        # 4. Check security headers
        security_header_issues = self._check_security_headers(headers)
        findings.extend(security_header_issues)

        # 5. JSON structural analysis
        json_analysis = self._analyze_json_structure(body)

        # Calculate composite risk score
        for f in findings:
            if f.severity == "critical":
                risk_score += 0.4
            elif f.severity == "high":
                risk_score += 0.25
            elif f.severity == "medium":
                risk_score += 0.1
            elif f.severity == "low":
                risk_score += 0.05
        risk_score = min(1.0, risk_score)

        return {
            "status_code": status_code,
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings],
            "risk_score": round(risk_score, 2),
            "json_analysis": json_analysis,
            "has_critical": any(f.severity == "critical" for f in findings),
            "has_sensitive_data": any(f.finding_type in SENSITIVE_PATTERNS for f in findings),
            "has_error_disclosure": any(f.finding_type in ERROR_PATTERNS for f in findings),
        }

    def compare_responses_semantic(self, resp_a: Dict[str, Any],
                                    resp_b: Dict[str, Any]) -> Dict[str, Any]:
        """
        Semantically compare two responses to detect authorization bypass indicators.
        Goes beyond text comparison — analyzes JSON structure differences.
        """
        body_a = resp_a.get("body_text", "")
        body_b = resp_b.get("body_text", "")
        status_a = resp_a.get("status_code", 0)
        status_b = resp_b.get("status_code", 0)

        result = {
            "status_match": status_a == status_b,
            "both_success": 200 <= status_a < 300 and 200 <= status_b < 300,
            "key_differences": [],
            "shared_sensitive_data": [],
            "is_potential_bypass": False,
            "confidence": 0.0,
        }

        # If both return success, compare deeply
        if result["both_success"]:
            json_a = self._try_parse_json(body_a)
            json_b = self._try_parse_json(body_b)

            if json_a and json_b:
                # Check for shared sensitive fields
                keys_a = self._extract_all_keys(json_a)
                keys_b = self._extract_all_keys(json_b)
                shared_keys = keys_a & keys_b

                sensitive_shared = {k for k in shared_keys if k.lower() in
                                   {"email", "password", "token", "secret", "ssn",
                                    "phone", "address", "credit_card", "balance",
                                    "api_key", "private", "salary", "dob"}}

                if sensitive_shared:
                    result["shared_sensitive_data"] = list(sensitive_shared)
                    result["is_potential_bypass"] = True
                    result["confidence"] = min(0.95, 0.5 + len(sensitive_shared) * 0.1)

                # Check for identical data values (same object returned to different users)
                if json_a == json_b:
                    result["is_potential_bypass"] = True
                    result["confidence"] = max(result["confidence"], 0.85)
                    result["key_differences"].append("IDENTICAL_RESPONSE: Both users received exactly the same data")

                # Structural key diff
                unique_a = keys_a - keys_b
                unique_b = keys_b - keys_a
                if unique_a:
                    result["key_differences"].append(f"Keys only in A: {list(unique_a)[:10]}")
                if unique_b:
                    result["key_differences"].append(f"Keys only in B: {list(unique_b)[:10]}")

            elif body_a == body_b and len(body_a) > 50:
                # Non-JSON but identical substantial bodies
                result["is_potential_bypass"] = True
                result["confidence"] = 0.75
                result["key_differences"].append("IDENTICAL_BODY: Non-JSON bodies are exactly equal")

        return result

    def _scan_for_sensitive_data(self, text: str, location: str) -> List[SensitiveFinding]:
        """Scan text for sensitive data patterns."""
        findings: List[SensitiveFinding] = []
        if not text:
            return findings

        for name, config in SENSITIVE_PATTERNS.items():
            matches = re.findall(config["pattern"], text, re.IGNORECASE)
            for match in matches[:3]:  # Limit to 3 matches per pattern to avoid noise
                findings.append(SensitiveFinding(
                    finding_type=name,
                    matched_value=match if isinstance(match, str) else str(match),
                    severity=config["severity"],
                    description=config["description"],
                    location=location
                ))

        return findings

    def _scan_for_error_disclosure(self, text: str) -> List[SensitiveFinding]:
        """Scan for error disclosure patterns."""
        findings: List[SensitiveFinding] = []
        if not text:
            return findings

        for name, config in ERROR_PATTERNS.items():
            for pattern in config["patterns"]:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    findings.append(SensitiveFinding(
                        finding_type=name,
                        matched_value=matches[0] if matches else "",
                        severity=config["severity"],
                        description=config["description"],
                        location="body"
                    ))
                    break  # One match per category is enough

        return findings

    def _check_security_headers(self, headers: Dict[str, str]) -> List[SensitiveFinding]:
        """Check for missing security headers."""
        findings: List[SensitiveFinding] = []
        header_keys_lower = {k.lower() for k in headers.keys()}

        required_headers = {
            "strict-transport-security": ("Missing HSTS header — vulnerable to downgrade attacks", "medium"),
            "x-content-type-options": ("Missing X-Content-Type-Options — vulnerable to MIME sniffing", "low"),
            "x-frame-options": ("Missing X-Frame-Options — vulnerable to clickjacking", "medium"),
            "content-security-policy": ("Missing CSP header — vulnerable to XSS", "medium"),
        }

        for header, (desc, sev) in required_headers.items():
            if header not in header_keys_lower:
                findings.append(SensitiveFinding(
                    finding_type=f"missing_{header.replace('-', '_')}",
                    matched_value="NOT_PRESENT",
                    severity=sev,
                    description=desc,
                    location="headers"
                ))

        return findings

    def _analyze_json_structure(self, body: str) -> Dict[str, Any]:
        """Extract structural metadata from JSON response body."""
        data = self._try_parse_json(body)
        if not data:
            return {"is_json": False}

        keys = self._extract_all_keys(data)
        return {
            "is_json": True,
            "total_keys": len(keys),
            "key_names": list(keys)[:50],
            "has_nested_objects": any(isinstance(v, dict) for v in
                                      (data.values() if isinstance(data, dict) else [])),
            "has_arrays": any(isinstance(v, list) for v in
                              (data.values() if isinstance(data, dict) else [])),
        }

    def _try_parse_json(self, text: str) -> Optional[Any]:
        """Safely try to parse JSON."""
        if not text:
            return None
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return None

    def _extract_all_keys(self, obj: Any, prefix: str = "") -> Set[str]:
        """Recursively extract all keys from a JSON object."""
        keys: Set[str] = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                keys.add(full_key)
                keys |= self._extract_all_keys(v, full_key)
        elif isinstance(obj, list):
            for item in obj[:5]:  # Limit list traversal
                keys |= self._extract_all_keys(item, prefix)
        return keys
