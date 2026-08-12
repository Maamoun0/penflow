"""
Wildcard Scope Pattern Resolver for PenFlow.

Extracts root apex domains from wildcard expressions (e.g. prod-*.nubank.com.br -> nubank.com.br),
queries Certificate Transparency logs (crt.sh), and filters subdomains matching the target pattern.
"""
import fnmatch
from typing import List, Optional
from penflow.recon.crt_sh_client import CrtShClient
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.scope_resolver")


class ScopePatternResolver:
    """
    Resolves wildcard target patterns (e.g., prod-*.example.com, *.target.org)
    against real subdomains discovered via Certificate Transparency logs.
    """

    def __init__(self, crt_client: Optional[CrtShClient] = None):
        self.crt_client = crt_client or CrtShClient()

    @staticmethod
    def extract_root_domain(pattern: str) -> str:
        """
        Extracts the apex root domain from a wildcard pattern or URL.
        Examples:
          - 'prod-*.nubank.com.br' -> 'nubank.com.br'
          - 'prod-*.nu.com.mx'     -> 'nu.com.mx'
          - '*.example.com'        -> 'example.com'
          - 'https://api.test.org' -> 'test.org'
        """
        clean = pattern.strip().lower()
        for prefix in ["https://", "http://"]:
            if clean.startswith(prefix):
                clean = clean[len(prefix):]
        clean = clean.split("/")[0].split("?")[0].split(":")[0]

        parts = clean.split(".")
        if len(parts) <= 2:
            return clean

        # Handle multi-segment TLDs like .com.br, .co.uk, .com.mx, .co.jp
        two_level_tlds = {"com.br", "co.uk", "com.mx", "co.jp", "com.co", "gov.br", "edu.br", "org.br", "net.br"}
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_level_tlds:
            # e.g. prod-*.nubank.com.br -> nubank.com.br
            root_domain = f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
        else:
            root_domain = f"{parts[-2]}.{parts[-1]}"

        return root_domain

    @staticmethod
    def filter_by_pattern(pattern: str, domains: List[str]) -> List[str]:
        """
        Filters a list of domain strings against a wildcard pattern using fnmatch.
        Case-insensitive matching.
        """
        pattern_clean = pattern.strip().lower()
        for prefix in ["https://", "http://"]:
            if pattern_clean.startswith(prefix):
                pattern_clean = pattern_clean[len(prefix):]
        pattern_clean = pattern_clean.split("/")[0].split("?")[0].split(":")[0]

        matched = []
        for dom in domains:
            dom_clean = dom.strip().lower()
            if fnmatch.fnmatch(dom_clean, pattern_clean):
                matched.append(dom)

        return sorted(list(set(matched)))

    async def resolve_scope(self, target_pattern: str) -> List[str]:
        """
        Resolves a wildcard target pattern to concrete subdomains.
        If no wildcard '*' is present, returns target_pattern as a single-element list.
        If wildcard is present, fetches subdomains for root domain and filters matches.
        """
        target_clean = target_pattern.strip().lower()
        if "*" not in target_clean:
            return [target_clean]

        root_domain = self.extract_root_domain(target_clean)
        logger.info(f"[ScopeResolver] Resolving wildcard pattern '{target_pattern}' for root domain '{root_domain}'...")

        discovered = await self.crt_client.fetch_subdomains(root_domain)
        matched_targets = self.filter_by_pattern(target_clean, discovered)

        if not matched_targets:
            logger.warning(f"[ScopeResolver] No subdomains matched pattern '{target_pattern}'. Falling back to root domain '{root_domain}'.")
            return [root_domain]

        logger.info(f"[ScopeResolver] Successfully resolved {len(matched_targets)} targets matching '{target_pattern}': {matched_targets}")
        return matched_targets
