from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from penflow.shared.utils import compute_sha256, get_utc_timestamp

@dataclass
class JSFileMetadata:
    url: str
    sha256_hash: str
    version: str = "1.0.0"
    imports: Set[str] = field(default_factory=set)
    exports: Set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=get_utc_timestamp)
    last_seen: float = field(default_factory=get_utc_timestamp)

class JSDiscoveryEngine:
    """
    Tracks JavaScript files, version changes, content hashes, and ES module imports/exports.
    """
    def __init__(self):
        self._js_files: Dict[str, JSFileMetadata] = {}  # url -> JSFileMetadata

    def record_js_file(self, url: str, content: str, version: str = "1.0.0", imports: Optional[List[str]] = None, exports: Optional[List[str]] = None) -> JSFileMetadata:
        url_clean = url.strip().lower()
        content_hash = compute_sha256(content)
        now = get_utc_timestamp()

        if url_clean in self._js_files:
            js_meta = self._js_files[url_clean]
            js_meta.last_seen = now
            if js_meta.sha256_hash != content_hash:
                js_meta.sha256_hash = content_hash
                js_meta.version = version
            if imports:
                js_meta.imports.update(imports)
            if exports:
                js_meta.exports.update(exports)
            return js_meta

        js_meta = JSFileMetadata(
            url=url_clean,
            sha256_hash=content_hash,
            version=version,
            imports=set(imports or []),
            exports=set(exports or []),
            first_seen=now,
            last_seen=now
        )
        self._js_files[url_clean] = js_meta
        return js_meta

    def get_js_file(self, url: str) -> Optional[JSFileMetadata]:
        return self._js_files.get(url.strip().lower())
