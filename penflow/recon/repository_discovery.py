from dataclasses import dataclass, field
from typing import Dict, List, Optional
from penflow.shared.utils import get_utc_timestamp

@dataclass
class RepositoryMetadata:
    platform: str  # GitHub, GitLab, Bitbucket
    repo_url: str
    owner: str
    name: str
    is_private: bool = False
    stars: int = 0
    updated_at: float = field(default_factory=get_utc_timestamp)

class RepositoryDiscoveryEngine:
    """
    Tracks repository metadata across GitHub, GitLab, and Bitbucket.
    """
    def __init__(self):
        self._repositories: Dict[str, RepositoryMetadata] = {}

    def record_repository(self, platform: str, repo_url: str, owner: str, name: str, is_private: bool = False, stars: int = 0) -> RepositoryMetadata:
        url_clean = repo_url.strip().lower()
        meta = RepositoryMetadata(
            platform=platform,
            repo_url=url_clean,
            owner=owner,
            name=name,
            is_private=is_private,
            stars=stars,
            updated_at=get_utc_timestamp()
        )
        self._repositories[url_clean] = meta
        return meta

    def get_repositories(self, platform: Optional[str] = None) -> List[RepositoryMetadata]:
        if platform:
            return [r for r in self._repositories.values() if r.platform.lower() == platform.lower()]
        return list(self._repositories.values())
