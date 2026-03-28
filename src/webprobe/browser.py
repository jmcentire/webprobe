"""Playwright browser lifecycle and context pool."""

from __future__ import annotations

from playwright.async_api import Browser, BrowserContext, Playwright, async_playwright

from webprobe.auth import AuthManager
from webprobe.config import CaptureConfig


class BrowserPool:
    """Manages a single Playwright browser instance with multiple contexts."""

    def __init__(self, config: CaptureConfig) -> None:
        self._config = config
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None

    async def start(self) -> None:
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=True)

    async def new_context(
        self,
        auth: AuthManager | None = None,
        base_url: str = "",
    ) -> BrowserContext:
        assert self._browser is not None, "Call start() first"
        context = await self._browser.new_context(
            viewport={
                "width": self._config.viewport_width,
                "height": self._config.viewport_height,
            },
            ignore_https_errors=True,
        )
        if auth and auth.has_auth:
            await auth.apply_to_context(context, base_url)
        return context

    async def stop(self) -> None:
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        self._browser = None
        self._playwright = None

    async def __aenter__(self) -> BrowserPool:
        await self.start()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.stop()
