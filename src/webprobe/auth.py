"""Auth context management: cookie/bearer/header injection and auth detection."""

from __future__ import annotations

from urllib.parse import urlparse

import aiohttp
from playwright.async_api import BrowserContext, Page

from webprobe.config import AuthConfig


class AuthManager:
    """Manages authentication injection for both aiohttp and Playwright."""

    def __init__(self, config: AuthConfig) -> None:
        self.config = config

    @property
    def has_auth(self) -> bool:
        return self.config.method != "none"

    def apply_to_session(self, session: aiohttp.ClientSession) -> None:
        """Inject auth into an aiohttp session for Phase 1 crawling."""
        if self.config.method == "cookie":
            session.cookie_jar.update_cookies(
                {self.config.cookie_name: self.config.cookie_value}
            )
        elif self.config.method == "bearer":
            session.headers["Authorization"] = f"Bearer {self.config.bearer_token}"
        elif self.config.method == "header":
            session.headers[self.config.header_name] = self.config.header_value

    async def apply_to_context(self, context: BrowserContext, base_url: str) -> None:
        """Inject auth into a Playwright browser context for Phase 2 capture."""
        if self.config.method == "cookie":
            parsed = urlparse(base_url)
            await context.add_cookies([{
                "name": self.config.cookie_name,
                "value": self.config.cookie_value,
                "domain": parsed.hostname or "",
                "path": "/",
            }])
        elif self.config.method == "bearer":
            await context.set_extra_http_headers({
                "Authorization": f"Bearer {self.config.bearer_token}",
            })
        elif self.config.method == "header":
            await context.set_extra_http_headers({
                self.config.header_name: self.config.header_value,
            })

    def is_auth_redirect(self, original_url: str, final_url: str) -> bool:
        """Detect if a response redirected to the login page."""
        if not self.config.login_url:
            return False
        login_path = self.config.login_url
        final_parsed = urlparse(final_url)
        original_parsed = urlparse(original_url)
        if final_parsed.path.rstrip("/") == login_path.rstrip("/"):
            return final_parsed.path != original_parsed.path
        return False

    async def check_auth_indicator(self, page: Page) -> bool:
        """Check if the auth_indicator selector is present on the page."""
        if not self.config.auth_indicator:
            return False
        try:
            element = await page.query_selector(self.config.auth_indicator)
            return element is not None
        except Exception:
            return False
