"""
Declarative Security DSL & Template Engine for PenFlow.

Enables expressive, multi-criteria vulnerability templates using YAML/Dict specifications.
Supports:
  - Status code matching
  - Substring & Keyword matchers (AND/OR logic)
  - Regex pattern matching with extraction
  - Header inspection
  - Composite multi-matcher evaluation
"""
import re
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.rules.dsl_engine")


class RuleMatcher:
    """
    Evaluates individual matcher blocks against HTTP responses.
    """

    def __init__(self, matcher_spec: Dict[str, Any]):
        self.matcher_type = matcher_spec.get("type", "word")  # word, regex, status, header
        self.condition = matcher_spec.get("condition", "or").lower()  # and, or
        self.part = matcher_spec.get("part", "body").lower()  # body, header, status
        self.words = matcher_spec.get("words", [])
        self.regexes = [re.compile(p) for p in matcher_spec.get("regex", [])]
        self.status_codes = matcher_spec.get("status", [])
        self.headers = matcher_spec.get("headers", {})

    def evaluate(self, status_code: int, headers: Dict[str, str], body: str) -> bool:
        """Evaluates whether the HTTP response matches the matcher rules."""
        target_text = body if self.part == "body" else "\n".join(f"{k}: {v}" for k, v in headers.items())

        if self.matcher_type == "status":
            return status_code in self.status_codes

        elif self.matcher_type == "word":
            if not self.words:
                return False
            if self.condition == "and":
                return all(w in target_text for w in self.words)
            else:  # or
                return any(w in target_text for w in self.words)

        elif self.matcher_type == "regex":
            if not self.regexes:
                return False
            if self.condition == "and":
                return all(r.search(target_text) is not None for r in self.regexes)
            else:  # or
                return any(r.search(target_text) is not None for r in self.regexes)

        elif self.matcher_type == "header":
            headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
            for k, expected_v in self.headers.items():
                k_low = k.lower()
                if k_low not in headers_lower:
                    return False
                if expected_v.lower() not in headers_lower[k_low]:
                    return False
            return True

        return False


class SecurityTemplate:
    """
    Represents a declarative vulnerability rule template.
    """

    def __init__(self, spec: Dict[str, Any]):
        self.id = spec.get("id", "custom-rule")
        self.name = spec.get("name", "Custom Security Rule")
        self.severity = spec.get("severity", "MEDIUM").upper()
        self.description = spec.get("description", "")
        self.matchers_condition = spec.get("matchers-condition", "and").lower()
        self.matchers: List[RuleMatcher] = [
            RuleMatcher(m) for m in spec.get("matchers", [])
        ]

    def evaluate(self, status_code: int, headers: Dict[str, str], body: str) -> bool:
        if not self.matchers:
            return False

        results = [m.evaluate(status_code, headers, body) for m in self.matchers]
        if self.matchers_condition == "and":
            return all(results)
        else:
            return any(results)


class DSLEngine:
    """
    Manages and executes collections of declarative security templates.
    """

    def __init__(self):
        self.templates: List[SecurityTemplate] = []

    def load_template(self, spec: Dict[str, Any]) -> SecurityTemplate:
        template = SecurityTemplate(spec)
        self.templates.append(template)
        logger.info(f"[DSLEngine] Loaded template '{template.id}' ({template.name}) [{template.severity}]")
        return template

    def load_templates(self, specs: List[Dict[str, Any]]) -> int:
        for s in specs:
            self.load_template(s)
        return len(self.templates)

    def evaluate_response(self, status_code: int, headers: Dict[str, str], body: str) -> List[Dict[str, Any]]:
        """Evaluates all registered templates against a response and returns matched vulnerabilities."""
        matched: List[Dict[str, Any]] = []

        for template in self.templates:
            if template.evaluate(status_code, headers, body):
                result = {
                    "rule_id": template.id,
                    "name": template.name,
                    "severity": template.severity,
                    "description": template.description
                }
                matched.append(result)
                logger.info(f"[DSLEngine] Rule MATCHED: '{template.id}' [{template.severity}]")

        return matched
