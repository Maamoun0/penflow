from typing import Dict, Set, List, Any
from penflow.shared.utils import get_utc_timestamp

class IndexEngine:
    """
    In-memory inverted index engine indexing assets, technologies, parameters, headers, paths, files, and repos.
    """
    def __init__(self):
        self._indices: Dict[str, Dict[str, Set[str]]] = {
            "assets": {},
            "technologies": {},
            "parameters": {},
            "headers": {},
            "paths": {},
            "files": {},
            "repositories": {}
        }

    def index_term(self, category: str, term: str, entity_id: str) -> None:
        if category not in self._indices:
            self._indices[category] = {}

        term_clean = term.strip().lower()
        if term_clean not in self._indices[category]:
            self._indices[category][term_clean] = set()

        self._indices[category][term_clean].add(entity_id)

    def lookup(self, category: str, term: str) -> Set[str]:
        category_index = self._indices.get(category, {})
        return category_index.get(term.strip().lower(), set())

    def clear(self) -> None:
        for cat in self._indices:
            self._indices[cat].clear()
