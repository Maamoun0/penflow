import fnmatch
from typing import List, Set, Optional

class ScopeManager:
    """
    Scope validation engine enforcing in-scope inclusion rules and blocking out-of-scope assets.
    """
    def __init__(self, in_scope: Optional[List[str]] = None, out_of_scope: Optional[List[str]] = None):
        self.in_scope: Set[str] = set(in_scope or [])
        self.out_of_scope: Set[str] = set(out_of_scope or [])

    def add_in_scope(self, pattern: str) -> None:
        self.in_scope.add(pattern.strip().lower())

    def add_out_of_scope(self, pattern: str) -> None:
        self.out_of_scope.add(pattern.strip().lower())

    def is_in_scope(self, asset: str) -> bool:
        asset_clean = asset.strip().lower()

        # Check out-of-scope first
        for oos_pattern in self.out_of_scope:
            if fnmatch.fnmatch(asset_clean, oos_pattern):
                return False

        # If no in-scope patterns set, default to True
        if not self.in_scope:
            return True

        # Check in-scope matching
        for ins_pattern in self.in_scope:
            if fnmatch.fnmatch(asset_clean, ins_pattern):
                return True

        return False
