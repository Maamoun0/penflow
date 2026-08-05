import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from penflow.network.http_client import HttpClient, HttpResponse
from penflow.utils.logger import get_logger
from penflow.utils.url_utils import normalize_url, is_same_origin, is_static_resource, classify_endpoint
from penflow.utils.file_utils import get_scan_dir, safe_write_json
from penflow.recon.tech_fingerprint import TechFingerprinter
from penflow.core.event_bus import EventBus
from penflow.config import Config

logger = get_logger("penflow.recon.smart_crawler")

@dataclass
class CrawlResult:
    urls: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    endpoints_by_type: Dict[str, List[str]] = field(default_factory=dict)
    tech_profiles: Dict[str, dict] = field(default_factory=dict)

class SmartCrawler:
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
        self.event_bus = EventBus.get_instance()
        self.fingerprinter = TechFingerprinter()
        self.config = Config.load()
        
        crawler_cfg = self.config.get("recon.crawler", {})
        self.max_depth = crawler_cfg.get("max_depth", 5)
        self.max_pages = crawler_cfg.get("max_pages", 1000)
        self.skip_static = crawler_cfg.get("skip_static", True)
        self.extract_forms = crawler_cfg.get("extract_forms", True)
        self.extract_comments = crawler_cfg.get("extract_comments", True)
        
        profile = self.config.get_active_profile()
        concurrency = profile.get("max_concurrency", 10)
        self.semaphore = asyncio.Semaphore(concurrency)
        
        # State
        self.visited: Set[str] = set()
        self.to_visit: List[Tuple[str, int]] = [] # (url, depth)
        self.result = CrawlResult()
        self.base_url = ""

    async def crawl(self, base_url: str) -> CrawlResult:
        self.base_url = base_url
        normalized_base = normalize_url(base_url)
        
        logger.info(f"Starting smart crawl on {normalized_base} (Max depth: {self.max_depth}, Max pages: {self.max_pages})")
        
        self.to_visit.append((normalized_base, 0))
        
        # Initialize endpoints dict
        for t in ['api', 'admin', 'auth', 'upload', 'debug', 'graphql', 'static', 'page']:
            self.result.endpoints_by_type[t] = []
            
        tasks = []
        pages_crawled = 0
        
        while self.to_visit and pages_crawled < self.max_pages:
            batch_size = min(self.semaphore._value, len(self.to_visit), self.max_pages - pages_crawled)
            batch = [self.to_visit.pop(0) for _ in range(batch_size)]
            
            # Create tasks for batch
            current_tasks = [self._process_url(url, depth) for url, depth in batch]
            await asyncio.gather(*current_tasks)
            
            pages_crawled += len(batch)
            logger.debug(f"Crawled {pages_crawled}/{self.max_pages} pages. Queue size: {len(self.to_visit)}")
            
        logger.info(f"Crawl completed. Found {len(self.result.urls)} unique URLs and {len(self.result.forms)} forms.")
        
        # Save results
        self._save_results()
        
        return self.result

    async def _process_url(self, url: str, depth: int) -> None:
        if url in self.visited:
            return
            
        self.visited.add(url)
        self.result.urls.append(url)
        
        # Classify and store
        endpoint_type = classify_endpoint(url)
        self.result.endpoints_by_type[endpoint_type].append(url)
        
        # Emit event for graph builder
        await self.event_bus.emit("ENDPOINT_FOUND", {
            "url": url,
            "method": "GET",
            "type": endpoint_type,
            "source": "crawler"
        })
        
        if self.skip_static and is_static_resource(url):
            return
            
        if depth >= self.max_depth:
            return
            
        async with self.semaphore:
            response = await self.http_client.get(url)
            if not response:
                return
                
            # Fingerprint on first page or randomly
            if depth == 0 or len(self.result.tech_profiles) == 0:
                profile = await self.fingerprinter.fingerprint(url, response)
                self.result.tech_profiles[url] = profile.to_dict()
                
            # Parse HTML
            content_type = response.headers.get("content-type", "").lower()
            if "text/html" in content_type:
                self._extract_html(url, response.body, depth)

    def _extract_html(self, base_url: str, html: str, depth: int) -> None:
        soup = BeautifulSoup(html, 'html.parser')
        
        # 1. Extract links
        tags_attributes = {
            'a': 'href', 'form': 'action', 'script': 'src', 
            'link': 'href', 'iframe': 'src', 'img': 'src'
        }
        
        for tag, attr in tags_attributes.items():
            for element in soup.find_all(tag):
                link = element.get(attr)
                if link:
                    full_url = urljoin(base_url, link)
                    norm_url = normalize_url(full_url)
                    
                    if norm_url not in self.visited and is_same_origin(self.base_url, norm_url):
                        # Avoid adding if already in queue
                        if not any(u == norm_url for u, d in self.to_visit):
                            self.to_visit.append((norm_url, depth + 1))
                            
        # 2. Extract forms
        if self.extract_forms:
            for form in soup.find_all('form'):
                action = form.get('action', '')
                full_action = urljoin(base_url, action)
                method = form.get('method', 'GET').upper()
                
                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if name:
                        inputs.append({
                            "name": name,
                            "type": inp.get('type', 'text'),
                            "hidden": inp.get('type') == 'hidden',
                            "value": inp.get('value', '')
                        })
                        
                form_data = {
                    "url": normalize_url(full_action),
                    "method": method,
                    "inputs": inputs,
                    "source_page": base_url
                }
                self.result.forms.append(form_data)
                
                # Emit form found event
                # We do it synchronously here as emit pushes to background task
                asyncio.create_task(self.event_bus.emit("ENDPOINT_FOUND", {
                    "url": form_data["url"],
                    "method": method,
                    "type": "form",
                    "params": [i["name"] for i in inputs],
                    "source": "crawler_form"
                }))

        # 3. Extract comments
        if self.extract_comments:
            from bs4 import Comment
            for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                c_text = comment.strip()
                if len(c_text) > 5: # Skip empty or trivial comments
                    self.result.comments.append(f"<!-- {c_text} --> (from {base_url})")

    def _save_results(self) -> None:
        from urllib.parse import urlparse
        domain = urlparse(self.base_url).netloc.split(':')[0]
        
        raw_dir = get_scan_dir(domain, "raw")
        filtered_dir = get_scan_dir(domain, "filtered")
        
        safe_write_json(raw_dir / "crawl_results.json", self.result.urls)
        safe_write_json(raw_dir / "forms.json", self.result.forms)
        safe_write_json(raw_dir / "comments.json", self.result.comments)
        safe_write_json(filtered_dir / "endpoints.json", self.result.endpoints_by_type)
        safe_write_json(filtered_dir / "technologies.json", self.result.tech_profiles)
