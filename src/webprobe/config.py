"""Configuration loading: YAML file + Pydantic v2 validation."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field


class AuthCredential(BaseModel):
    """A single named credential for auth testing."""

    name: str = "default"
    method: Literal["cookie", "bearer", "header"] = "cookie"
    cookie_name: str = ""
    cookie_value: str = ""
    bearer_token: str = ""
    header_name: str = ""
    header_value: str = ""


class AuthConfig(BaseModel):
    """Authentication injection settings."""

    method: Literal["cookie", "bearer", "header", "none"] = "none"
    cookie_name: str = ""
    cookie_value: str = ""
    bearer_token: str = ""
    header_name: str = ""
    header_value: str = ""
    login_url: str = "/login"
    auth_indicator: str = ""
    credentials: list[AuthCredential] = Field(default_factory=list)


class CrawlConfig(BaseModel):
    """Crawl behavior settings."""

    max_depth: int = 10
    max_nodes: int = 500
    respect_robots: bool = True
    follow_external: bool = False
    url_exclude_patterns: list[str] = Field(default_factory=list)
    request_delay_ms: int = 100
    render_js: bool = False


class CaptureConfig(BaseModel):
    """Capture behavior settings."""

    concurrency: int = 10
    timeout_ms: int = 30000
    screenshot: bool = True
    viewport_width: int = 1280
    viewport_height: int = 720


class WebprobeConfig(BaseModel):
    """Top-level configuration."""

    auth: AuthConfig = Field(default_factory=AuthConfig)
    crawl: CrawlConfig = Field(default_factory=CrawlConfig)
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    output_dir: str = "./webprobe-runs"


_SEARCH_PATHS = [
    Path("webprobe.yaml"),
    Path.home() / ".webprobe" / "webprobe.yaml",
]


def load_config(path: str | Path | None = None) -> WebprobeConfig:
    """Load config from explicit path, ./webprobe.yaml, ~/.webprobe/webprobe.yaml, or defaults."""
    if path is not None:
        p = Path(path)
        if p.exists():
            return WebprobeConfig.model_validate(yaml.safe_load(p.read_text()) or {})
        raise FileNotFoundError(f"Config not found: {p}")

    for p in _SEARCH_PATHS:
        if p.exists():
            return WebprobeConfig.model_validate(yaml.safe_load(p.read_text()) or {})

    return WebprobeConfig()
