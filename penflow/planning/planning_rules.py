from dataclasses import dataclass, field
from typing import Dict, List, Any, Callable, Optional
from penflow.planning.rule_loader import DeclarativeRuleLoader

@dataclass
class DeclarativePlanningRule:
    rule_id: str
    condition_type: str  # observation_contains, tech_match, endpoint_match
    match_value: str
    generated_title: str
    generated_reason: str
    required_capabilities: List[str] = field(default_factory=list)

class PlanningRuleEngine:
    """
    Declarative rule engine for matching observation patterns against hypothesis generation rules loaded from YAML files.
    """
    def __init__(self, rule_loader: Optional[DeclarativeRuleLoader] = None):
        self.loader = rule_loader or DeclarativeRuleLoader()
        self.rules: List[DeclarativePlanningRule] = self.loader.load_rules()
        if not self.rules:
            self._init_default_rules()

    def _init_default_rules(self) -> None:
        self.rules.append(DeclarativePlanningRule(
            rule_id="R001",
            condition_type="observation_contains",
            match_value="graphql",
            generated_title="Possible GraphQL Authorization Weakness",
            generated_reason="GraphQL introspection or endpoint discovered",
            required_capabilities=["graphql_analysis"]
        ))
        self.rules.append(DeclarativePlanningRule(
            rule_id="R002",
            condition_type="observation_contains",
            match_value="/admin",
            generated_title="Possible Privilege Escalation Surface",
            generated_reason="Admin endpoint path observed in target scope",
            required_capabilities=["privilege_analysis"]
        ))
        self.rules.append(DeclarativePlanningRule(
            rule_id="R003",
            condition_type="observation_contains",
            match_value="id=",
            generated_title="Possible Object Authorization Issue (IDOR/BOLA)",
            generated_reason="Sequential or direct object references detected in parameters",
            required_capabilities=["id_access_analysis"]
        ))

    def evaluate(self, observation_text: str) -> List[DeclarativePlanningRule]:
        matched = []
        obs_lower = observation_text.lower()
        for rule in self.rules:
            if rule.condition_type == "observation_contains":
                if not rule.match_value or rule.match_value == "*" or rule.match_value.lower() in obs_lower:
                    matched.append(rule)
        
        # If no specific rule matched, trigger comprehensive default security audit rules across all capability agents
        if not matched:
            matched.append(DeclarativePlanningRule(
                rule_id="R_DEFAULT_AUDIT",
                condition_type="observation_contains",
                match_value="*",
                generated_title="Comprehensive Target Vulnerability Audit",
                generated_reason="Target endpoint observed; triggering full agent capability evaluation",
                required_capabilities=[
                    "id_access_analysis", "function_level_access", "xss_injection",
                    "cors_misconfiguration", "ssrf_analysis", "info_disclosure",
                    "open_redirect", "rate_limit_bypass", "security_headers",
                    "parameter_discovery", "nosql_sqli_injection", "mass_assignment",
                    "oauth_jwt_validation", "graphql_analysis", "ssti_rce_analysis"
                ]
            ))
        return matched
