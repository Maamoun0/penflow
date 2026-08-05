"""
SubdomainBruteforceEngine — Multi-Level Subdomain & Sub-subdomain Enumeration Engine.

Discovers subdomains and multi-level sub-subdomains (e.g. api.dev.target.com, staging.auth.target.com)
using a high-density wordlist combined with real async DNS resolution.
"""
import asyncio
from typing import List, Set, Dict, Any, Optional
from penflow.recon.dns_resolver import DNSResolverEngine
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.subdomain_bruteforce")

# High-density wordlist for subdomains and sub-subdomains
SUBDOMAIN_WORDLIST = [
    # Top tier subdomains
    "api", "dev", "staging", "test", "admin", "app", "auth", "v1", "v2", "v3",
    "internal", "private", "corp", "portal", "db", "database", "mail", "vpn",
    "dashboard", "backend", "web", "server", "demo", "prod", "production",
    "git", "gitlab", "github", "ci", "jenkins", "docker", "k8s", "grafana",
    "prometheus", "vault", "consul", "elastic", "kibana", "ws", "grpc",
    "static", "assets", "media", "cdn", "images", "docs", "swagger", "openapi",
    "login", "signin", "sso", "oauth", "saml", "account", "users", "billing",
    "pay", "checkout", "store", "shop", "manage", "monitor", "status", "health",
    "qa", "uat", "sandbox", "beta", "alpha", "old", "new", "bak", "backup",
]

# Secondary prefixes for sub-subdomains (e.g., api.dev, auth.staging)
SUB_SUB_PAIRS = [
    ("api", "dev"), ("api", "staging"), ("api", "test"), ("api", "v1"), ("api", "v2"),
    ("admin", "dev"), ("admin", "staging"), ("auth", "dev"), ("auth", "staging"),
    ("app", "dev"), ("app", "staging"), ("db", "dev"), ("internal", "dev"),
]


class SubdomainBruteforceEngine:
    """
    Asynchronous Multi-level Subdomain & Sub-subdomain Enumerator.
    Combines single-level dictionary probing with 2nd-level sub-subdomain generation.
    """

    def __init__(self, concurrency: int = 25, timeout: float = 5.0):
        self.dns_resolver = DNSResolverEngine()
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = timeout

    async def enumerate_subdomains(
        self,
        target_domain: str,
        deep_mode: bool = False,
        custom_wordlist: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        clean_domain = target_domain.strip().lower()
        wordlist = list(set(SUBDOMAIN_WORDLIST + (custom_wordlist or [])))

        candidates: Set[str] = set()

        # 1. Level-1 Subdomains (sub.target.com)
        for word in wordlist:
            candidates.add(f"{word}.{clean_domain}")

        # 2. Level-2 Sub-subdomains (sub.sub.target.com)
        if deep_mode:
            for p1, p2 in SUB_SUB_PAIRS:
                candidates.add(f"{p1}.{p2}.{clean_domain}")
            # Also combine top 10 words with top 10 words
            top_words = ["api", "dev", "staging", "admin", "auth", "v1", "app", "test", "internal", "db"]
            for w1 in top_words:
                for w2 in top_words:
                    if w1 != w2:
                        candidates.add(f"{w1}.{w2}.{clean_domain}")

        logger.info(f"[SubdomainBruteforce] Generated {len(candidates)} candidate subdomains for resolution...")

        discovered: List[Dict[str, Any]] = []

        async def probe_candidate(sub: str):
            async with self.semaphore:
                res = await self.dns_resolver.resolve_domain(sub)
                if res.get("is_resolved"):
                    discovered.append(res)

        tasks = [probe_candidate(sub) for sub in candidates]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"[SubdomainBruteforce] Completed enumeration for '{clean_domain}': Discovered {len(discovered)} active subdomains.")
        return discovered
