"""
Auto-Learning Engine for PenFlow.

Capabilities:
  - Fetches security research RSS feeds (PortSwigger Research, GitHub Advisories)
  - Extracts new attack payloads & detection patterns
  - Updates payload libraries & mined rules automatically in config/rules/mined_rules.yaml
"""
import httpx
import re
import os
import yaml
from typing import Dict, Any, List, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.auto_learning")

RSS_SOURCES = [
    "https://portswigger.net/research/rss",
    "https://github.com/advisories.atom"
]


class AutoLearningEngine:
    """
    Engine fetching and mining security research articles for dynamic payload expansion.
    """

    def __init__(self, rules_file_path: str = "config/rules/mined_rules.yaml"):
        self.rules_file_path = rules_file_path
        self.learned_techniques: List[Dict[str, Any]] = []

    async def fetch_latest_research(self) -> List[Dict[str, str]]:
        articles = []
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
                for rss_url in RSS_SOURCES:
                    try:
                        resp = await client.get(rss_url)
                        if resp.status_code == 200:
                            titles = re.findall(r'<title>(.*?)</title>', resp.text)
                            links = re.findall(r'<link>(.*?)</link>', resp.text)
                            for t, l in zip(titles[:5], links[:5]):
                                articles.append({"title": t, "url": l})
                    except Exception as e:
                        logger.debug(f"[AutoLearningEngine] RSS fetch failed for {rss_url}: {e}")
        except Exception as ex:
            logger.error(f"[AutoLearningEngine] Exception during research fetch: {ex}")

        return articles

    def extract_techniques_from_text(self, text: str) -> List[str]:
        patterns = [
            r'(/api/v[0-9]/[a-z0-9_-]+)',
            r'([a-zA-Z0-9_-]+=[a-zA-Z0-9_%.-]+)',
            r'(__proto__|constructor\.prototype)',
            r'(\{\{.*?\}\})',
            r'(%2e%2e%2f|%252e%252e%252f)'
        ]
        found = []
        for pat in patterns:
            matches = re.findall(pat, text)
            found.extend(matches)
        return list(set(found))

    def append_mined_rule(self, title: str, pattern: str) -> bool:
        """Appends mined research pattern into config/rules/mined_rules.yaml."""
        if not os.path.exists(self.rules_file_path):
            return False

        try:
            with open(self.rules_file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {"rules": []}

            existing_rules = data.get("rules", [])
            rule_id = f"R_MINED_{len(existing_rules) + 1:03d}"

            new_rule = {
                "rule_id": rule_id,
                "generated_title": f"Mined Research: {title[:50]}",
                "generated_reason": f"Tactical pattern harvested from security research feed",
                "condition_type": "observation_contains",
                "match_value": pattern,
                "required_capabilities": ["parameter_tampering", "vulnerability_audit"]
            }

            existing_rules.append(new_rule)
            data["rules"] = existing_rules

            with open(self.rules_file_path, "w", encoding="utf-8") as f:
                yaml.dump(data, f, sort_keys=False)

            logger.info(f"[AutoLearningEngine] Appended mined research rule '{rule_id}' ({pattern}) to '{self.rules_file_path}'")
            return True
        except Exception as e:
            logger.error(f"[AutoLearningEngine] Error writing mined rule to yaml: {e}")
            return False

    async def run_learning_cycle(self) -> Dict[str, Any]:
        articles = await self.fetch_latest_research()
        mined_count = 0

        for art in articles:
            techniques = self.extract_techniques_from_text(art.get("title", ""))
            for tech in techniques:
                if self.append_mined_rule(art.get("title", "Research Feed"), tech):
                    mined_count += 1

        return {
            "status": "COMPLETED",
            "articles_analyzed": len(articles),
            "techniques_mined": mined_count,
            "articles": articles
        }
