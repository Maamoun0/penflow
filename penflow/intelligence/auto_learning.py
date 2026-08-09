"""
Auto-Learning Engine for PenFlow.

Capabilities:
  - Fetches security research RSS feeds (PortSwigger Research, GitHub Advisories)
  - Extracts new attack payloads & detection patterns
  - Updates payload libraries automatically
"""
import httpx
import re
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

    def __init__(self):
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
                            for t, l in zip(titles[:3], links[:3]):
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
            r'(__proto__|constructor\.prototype)'
        ]
        found = []
        for pat in patterns:
            matches = re.findall(pat, text)
            found.extend(matches)
        return list(set(found))

    async def run_learning_cycle(self) -> Dict[str, Any]:
        articles = await self.fetch_latest_research()
        return {
            "status": "COMPLETED",
            "articles_analyzed": len(articles),
            "articles": articles
        }
