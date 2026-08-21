"""
BrowserPool — Headless Browser Lifecycle Manager.

Manages the lifecycle of Playwright browsers (Chromium) and provides an asynchronous,
reusable pool of browser contexts for advanced agents (DOM XSS, SPA Crawling).
Ensures browsers are not restarted unnecessarily, reducing overhead.
"""
import asyncio
from typing import Optional
from playwright.async_api import async_playwright, Playwright, Browser, BrowserContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.infrastructure.browser_pool")

class BrowserPool:
    _instance: Optional["BrowserPool"] = None
    _lock: asyncio.Lock = asyncio.Lock()

    def __init__(self):
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._is_initialized: bool = False
        self._init_lock: asyncio.Lock = asyncio.Lock()

    @classmethod
    def get_instance(cls) -> "BrowserPool":
        if cls._instance is None:
            cls._instance = BrowserPool()
        return cls._instance

    async def initialize(self) -> bool:
        """Initialize the global browser instance if not already running."""
        async with self._init_lock:
            if self._is_initialized and self._browser:
                return True

            try:
                self._playwright = await async_playwright().start()
                # Launch headless chromium. In BB scenario, we might want proxy support here later.
                self._browser = await self._playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-gpu",
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-web-security",
                    ]
                )
                self._is_initialized = True
                logger.info("[BrowserPool] Successfully launched headless Chromium browser.")
                return True
            except Exception as e:
                logger.error(f"[BrowserPool] Failed to launch headless browser: {e}. Ensure 'playwright install chromium' has been run.")
                self._is_initialized = False
                return False

    async def new_context(self) -> Optional[BrowserContext]:
        """Creates a new isolated browser context (like an incognito window)."""
        if not self._is_initialized:
            success = await self.initialize()
            if not success:
                return None
        
        try:
            context = await self._browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 PenFlow/1.0"
            )
            # Set default timeout to 15s to prevent agents from hanging forever
            context.set_default_timeout(15000)
            return context
        except Exception as e:
            logger.error(f"[BrowserPool] Failed to create new browser context: {e}")
            return None

    async def shutdown(self):
        """Shutdown the browser and playwright instance."""
        async with self._init_lock:
            if self._browser:
                await self._browser.close()
                self._browser = None
            if self._playwright:
                await self._playwright.stop()
                self._playwright = None
            self._is_initialized = False
            logger.info("[BrowserPool] Shutdown headless browser.")

