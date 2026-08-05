import os
import glob
from typing import List, Dict, Any, TYPE_CHECKING
from penflow.shared.utils import load_yaml_file
from penflow.infrastructure.logger import get_logger

if TYPE_CHECKING:
    from penflow.planning.planning_rules import DeclarativePlanningRule

logger = get_logger("penflow.planning.rule_loader")

class DeclarativeRuleLoader:
    """
    Loads and validates security planning rules dynamically from YAML configuration files.
    """
    def __init__(self, rules_dir: str = "config/rules"):
        self.rules_dir = rules_dir

    def load_rules(self) -> List[Any]:
        from penflow.planning.planning_rules import DeclarativePlanningRule
        rules: List[DeclarativePlanningRule] = []

        if not os.path.exists(self.rules_dir):
            logger.warning(f"[DeclarativeRuleLoader] Directory '{self.rules_dir}' not found.")
            return rules

        yaml_files = glob.glob(os.path.join(self.rules_dir, "*.yaml")) + glob.glob(os.path.join(self.rules_dir, "*.yml"))

        for file_path in yaml_files:
            try:
                data = load_yaml_file(file_path)
                rule_list = data.get("rules", [])
                for r_dict in rule_list:
                    rule = DeclarativePlanningRule(
                        rule_id=r_dict.get("rule_id", "R_UNKNOWN"),
                        condition_type=r_dict.get("condition_type", "observation_contains"),
                        match_value=r_dict.get("match_value", ""),
                        generated_title=r_dict.get("generated_title", ""),
                        generated_reason=r_dict.get("generated_reason", ""),
                        required_capabilities=r_dict.get("required_capabilities", [])
                    )
                    rules.append(rule)
                logger.info(f"[DeclarativeRuleLoader] Loaded {len(rule_list)} rules from '{file_path}'")
            except Exception as e:
                logger.error(f"[DeclarativeRuleLoader] Failed to load rule file '{file_path}': {str(e)}")

        return rules
