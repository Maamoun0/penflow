import json
import time
from pathlib import Path
from typing import Dict, Any, Optional

from penflow.config import Config
from penflow.utils.logger import get_logger
from penflow.utils.file_utils import safe_read_json, safe_write_json, ensure_dir
from penflow.utils.hash_utils import content_hash

logger = get_logger("penflow.network.cache_manager")

class CachedResponse:
    def __init__(self, data: Dict[str, Any]):
        self.status = data.get("status", 0)
        self.headers = data.get("headers", {})
        self.body = data.get("body", "")
        self.timestamp = data.get("timestamp", 0.0)
        self.fingerprint = data.get("fingerprint", "")
        self.elapsed_ms = data.get("elapsed_ms", 0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "headers": self.headers,
            "body": self.body,
            "timestamp": self.timestamp,
            "fingerprint": self.fingerprint,
            "elapsed_ms": self.elapsed_ms
        }

class CacheManager:
    def __init__(self):
        self.config = Config.load()
        self.enabled = self.config.get("cache.enabled", True)
        self.ttl_seconds = self.config.get("cache.ttl_hours", 24) * 3600
        
        # Base cache directory
        base_dir = Path(self.config.get("cache.directory", "cache"))
        self.cache_dir = ensure_dir(base_dir)
        
        self.stats = {"hits": 0, "misses": 0, "saved": 0}

    def _get_cache_path(self, domain: str, fingerprint: str) -> Path:
        """Get the file path for a cached response."""
        domain_dir = ensure_dir(self.cache_dir / domain)
        return domain_dir / f"{fingerprint}.json"

    def get(self, domain: str, fingerprint: str) -> Optional[CachedResponse]:
        """Retrieve a response from cache if it exists and is fresh."""
        if not self.enabled:
            return None
            
        path = self._get_cache_path(domain, fingerprint)
        
        if not path.exists():
            self.stats["misses"] += 1
            return None
            
        data = safe_read_json(path)
        if not data:
            self.stats["misses"] += 1
            return None
            
        cached = CachedResponse(data)
        
        # Check freshness
        if time.time() - cached.timestamp > self.ttl_seconds:
            self.stats["misses"] += 1
            return None
            
        self.stats["hits"] += 1
        return cached

    def put(self, domain: str, fingerprint: str, status: int, headers: Dict[str, str], body: str, elapsed_ms: int, response_fingerprint: str) -> None:
        """Store a response in the cache."""
        if not self.enabled:
            return
            
        path = self._get_cache_path(domain, fingerprint)
        
        # Only store serializable headers
        safe_headers = {k: str(v) for k, v in headers.items()}
        
        data = {
            "status": status,
            "headers": safe_headers,
            "body": body,
            "timestamp": time.time(),
            "fingerprint": response_fingerprint,
            "elapsed_ms": elapsed_ms
        }
        
        safe_write_json(path, data)
        self.stats["saved"] += 1

    def has_changed(self, domain: str, fingerprint: str, new_body: str) -> bool:
        """
        Check if the content has changed compared to the cached version.
        Useful for delta scanning. Returns True if changed OR if not in cache.
        """
        cached = self.get(domain, fingerprint)
        if not cached:
            return True
            
        return content_hash(cached.body) != content_hash(new_body)

    def clear_domain(self, domain: str) -> None:
        """Clear all cached responses for a specific domain."""
        domain_dir = self.cache_dir / domain
        if domain_dir.exists() and domain_dir.is_dir():
            for file in domain_dir.iterdir():
                if file.is_file():
                    try:
                        file.unlink()
                    except OSError:
                        pass

    def get_stats(self) -> Dict[str, int]:
        return self.stats
