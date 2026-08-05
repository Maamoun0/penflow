import os
import glob
import yaml
from typing import List, Dict, Any, Optional
from penflow.intelligence.writeup_miner import WriteupMiner, SecurityWriteup
from penflow.intelligence.experience_layer import ExperienceLayer
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.writeup_loader")

class WriteupIngestionEngine:
    """
    Continuous Learning Engine: Mines folders of markdown/text writeups,
    absorbs tactical insights into ExperienceLayer, and dynamically generates
    mined rules in YAML format for the Planner.
    """
    def __init__(self, experience_layer: Optional[ExperienceLayer] = None):
        self.miner = WriteupMiner()
        self.experience = experience_layer or ExperienceLayer()

    def ingest_directory(self, dir_path: str, rules_output_file: str = "config/rules/mined_rules.yaml") -> Dict[str, Any]:
        logger.info(f"[WriteupIngestionEngine] Beginning writeup ingestion from directory '{dir_path}'...")
        
        if not os.path.exists(dir_path):
            logger.warning(f"[WriteupIngestionEngine] Directory '{dir_path}' does not exist.")
            return {"ingested_count": 0, "rules_generated": 0}

        files = glob.glob(os.path.join(dir_path, "**", "*.md"), recursive=True) + \
                glob.glob(os.path.join(dir_path, "**", "*.txt"), recursive=True)

        ingested_writeups: List[SecurityWriteup] = []
        mined_rules: List[Dict[str, Any]] = []

        for idx, file_path in enumerate(files, 1):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
                title = os.path.basename(file_path).replace(".md", "").replace(".txt", "").replace("_", " ").title()
                writeup = self.miner.parse_writeup_text(title=title, content=content, source_url=file_path)
                
                # Absorb into ExperienceLayer
                self.experience.absorb_writeup(writeup)
                ingested_writeups.append(writeup)

                # Generate dynamic rule from extracted paths
                for pattern in writeup.extracted_patterns[:3]:
                    rule_id = f"R_MINED_{len(mined_rules) + 1:03d}"
                    mined_rule = {
                        "rule_id": rule_id,
                        "condition_type": "observation_contains",
                        "match_value": pattern.split("?")[0],
                        "generated_title": f"Mined Pattern: {writeup.title}",
                        "generated_reason": f"Tactical pattern learned from security research writeup ({writeup.id})",
                        "required_capabilities": self._map_vtypes_to_capabilities(writeup.detected_vulnerabilities)
                    }
                    mined_rules.append(mined_rule)

            except Exception as ex:
                logger.error(f"[WriteupIngestionEngine] Failed to process writeup '{file_path}': {str(ex)}")

        # Save mined rules to YAML file
        if mined_rules:
            os.makedirs(os.path.dirname(rules_output_file), exist_ok=True)
            with open(rules_output_file, "w", encoding="utf-8") as rf:
                yaml.dump({"rules": mined_rules}, rf, default_flow_style=False)
            logger.info(f"[WriteupIngestionEngine] Generated {len(mined_rules)} mined rules and saved to '{rules_output_file}'.")

        return {
            "ingested_count": len(ingested_writeups),
            "rules_generated": len(mined_rules),
            "rules_file": rules_output_file
        }

    def _map_vtypes_to_capabilities(self, vtypes: List[str]) -> List[str]:
        mapping = {
            "idor": ["id_access_analysis", "authorization"],
            "bfla": ["bfla_analysis", "privilege_analysis"],
            "mass_assignment": ["mass_assignment_analysis", "parameter_tampering"],
            "graphql": ["graphql_introspection", "graphql_depth_analysis"],
            "race_condition": ["race_condition_analysis"],
            "oauth_jwt": ["jwt_validation", "oauth_misconfiguration"],
            "ssrf": ["ssrf_analysis"],
            "cors": ["cors_misconfiguration"],
            "nosql": ["nosql_injection"],
            "sqli": ["sql_injection"],
            "ssti": ["ssti_analysis"],
            "rce": ["command_injection"],
            "rate_limit": ["rate_limit_bypass"],
            "open_redirect": ["open_redirect"],
            "info_disclosure": ["info_disclosure"],
            "websocket": ["websocket_auth_flaw"],
            "smuggling": ["http_smuggling"]
        }
        caps = set()
        for vt in vtypes:
            caps.update(mapping.get(vt, ["id_access_analysis"]))
        return list(caps) if caps else ["id_access_analysis"]
