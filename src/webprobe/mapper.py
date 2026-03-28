"""Phase 1: Site mapping -- robots.txt, sitemap, BFS crawl, graph construction."""

from __future__ import annotations

import asyncio
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Sequence
from urllib.parse import urljoin, urlparse, urlunparse

import aiohttp

from webprobe.auth import AuthManager
from webprobe.config import WebprobeConfig
from webprobe.models import (
    AuthContext,
    DiscoveryMethod,
    Edge,
    Node,
    NodeState,
    PhaseStatus,
    SiteGraph,
    TimingData,
)


def normalize_url(url: str, base: str | None = None) -> str:
    """Normalize a URL: resolve relative, strip fragment, lowercase scheme/host, strip trailing slash."""
    if base:
        url = urljoin(base, url)
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    # Lowercase scheme and host
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    # Remove default ports
    if (scheme == "http" and netloc.endswith(":80")):
        netloc = netloc[:-3]
    elif (scheme == "https" and netloc.endswith(":443")):
        netloc = netloc[:-4]
    # Normalize path
    path = parsed.path or "/"
    # Collapse double slashes
    path = re.sub(r"/+", "/", path)
    # Strip trailing slash (except root)
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    # Rebuild without fragment
    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))


def is_same_origin(url: str, base_url: str) -> bool:
    """Check if url has same scheme+host+port as base_url."""
    a = urlparse(url)
    b = urlparse(base_url)
    return (a.scheme == b.scheme and a.netloc == b.netloc)


class _LinkExtractor(HTMLParser):
    """Extract href values from <a> tags and action from <form> tags."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []  # (href, link_text_or_empty)
        self._current_link: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = dict(attrs)
        if tag == "a" and "href" in attr_dict:
            self._current_link = attr_dict["href"] or ""
            self._current_text = []
        elif tag == "form" and "action" in attr_dict:
            action = attr_dict["action"] or ""
            if action:
                self.links.append((action, ""))

    def handle_data(self, data: str) -> None:
        if self._current_link is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_link is not None:
            text = " ".join(self._current_text).strip()
            self.links.append((self._current_link, text))
            self._current_link = None
            self._current_text = []


def extract_links(html: str) -> list[tuple[str, str]]:
    """Extract (href, link_text) pairs from HTML."""
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.links


def parse_robots_txt(text: str, base_url: str) -> tuple[list[str], list[str]]:
    """Parse robots.txt. Returns (disallowed_paths, sitemap_urls)."""
    disallowed: list[str] = []
    sitemaps: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
        elif line.lower().startswith("sitemap:"):
            url = line.split(":", 1)[1].strip()
            # "sitemap:" split on first colon takes "//..." so rejoin
            if not url.startswith("http"):
                url = "sitemap:" + url
                url = url.split(":", 1)[1].strip()
            if url:
                sitemaps.append(url)
    return disallowed, sitemaps


def parse_sitemap(xml_text: str) -> list[str]:
    """Parse a sitemap XML, handling both sitemap indexes and regular sitemaps."""
    urls: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return urls
    # Strip namespace for easier parsing
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"
    # Sitemap index
    for sm in root.findall(f"{ns}sitemap"):
        loc = sm.find(f"{ns}loc")
        if loc is not None and loc.text:
            urls.append(loc.text.strip())
    # URL set
    for url_elem in root.findall(f"{ns}url"):
        loc = url_elem.find(f"{ns}loc")
        if loc is not None and loc.text:
            urls.append(loc.text.strip())
    return urls


async def _fetch(
    session: aiohttp.ClientSession,
    url: str,
    delay_ms: int = 0,
) -> tuple[int, str, str, float]:
    """Fetch a URL. Returns (status, body, final_url, duration_ms)."""
    if delay_ms > 0:
        await asyncio.sleep(delay_ms / 1000)
    start = time.monotonic()
    try:
        async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            body = await resp.text(errors="replace")
            duration = (time.monotonic() - start) * 1000
            return resp.status, body, str(resp.url), duration
    except Exception as e:
        duration = (time.monotonic() - start) * 1000
        return 0, "", url, duration


async def _crawl_pass(
    base_url: str,
    seed_urls: Sequence[str],
    config: WebprobeConfig,
    auth_manager: AuthManager | None = None,
    auth_context: AuthContext = AuthContext.anonymous,
    disallowed_paths: Sequence[str] = (),
) -> tuple[dict[str, Node], list[Edge]]:
    """BFS crawl. Returns (nodes_dict, edges_list)."""
    nodes: dict[str, Node] = {}
    edges: list[Edge] = []
    visited: set[str] = set()
    queue: asyncio.Queue[tuple[str, int, DiscoveryMethod]] = asyncio.Queue()

    # Seed the queue
    root_norm = normalize_url(base_url)
    queue.put_nowait((root_norm, 0, DiscoveryMethod.crawl))
    for seed in seed_urls:
        norm = normalize_url(seed)
        if norm and norm not in visited:
            queue.put_nowait((norm, 0, DiscoveryMethod.sitemap))

    exclude_patterns = [re.compile(p) for p in config.crawl.url_exclude_patterns]

    async with aiohttp.ClientSession() as session:
        if auth_manager and auth_manager.has_auth:
            auth_manager.apply_to_session(session)

        while not queue.empty() and len(nodes) < config.crawl.max_nodes:
            url, depth, discovery = queue.get_nowait()
            norm = normalize_url(url)
            if not norm or norm in visited:
                continue
            if not is_same_origin(norm, base_url) and not config.crawl.follow_external:
                continue
            if depth > config.crawl.max_depth:
                continue
            # Check robots.txt disallow
            if config.crawl.respect_robots and disallowed_paths:
                parsed = urlparse(norm)
                if any(parsed.path.startswith(d) for d in disallowed_paths):
                    continue
            # Check exclude patterns
            if any(p.search(norm) for p in exclude_patterns):
                continue

            visited.add(norm)

            status, body, final_url, duration = await _fetch(
                session, norm, config.crawl.request_delay_ms
            )

            # Determine auth requirement
            requires_auth: bool | None = None
            if auth_manager and status in (401, 403):
                requires_auth = True
            elif auth_manager and auth_manager.is_auth_redirect(norm, final_url):
                requires_auth = True

            node = Node(
                id=norm,
                state=NodeState(url=norm),
                discovered_via=discovery,
                requires_auth=requires_auth,
                auth_contexts_available=[auth_context],
                depth=depth,
            )
            nodes[norm] = node

            # Extract and queue links
            if status == 200 and body:
                for href, link_text in extract_links(body):
                    target = normalize_url(href, base=norm)
                    if not target:
                        continue
                    edges.append(Edge(
                        source=norm,
                        target=target,
                        link_text=link_text,
                        discovered_via=DiscoveryMethod.crawl,
                        auth_context=auth_context,
                    ))
                    if target not in visited:
                        queue.put_nowait((target, depth + 1, DiscoveryMethod.crawl))

    return nodes, edges


async def map_site(
    config: WebprobeConfig,
    url: str,
    framework_routes: Sequence[str] | None = None,
) -> tuple[SiteGraph, PhaseStatus]:
    """Phase 1: Map a site. Returns (SiteGraph, PhaseStatus)."""
    phase = PhaseStatus(
        phase="map",
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    start = time.monotonic()

    base_url = normalize_url(url)
    seed_urls: list[str] = []
    disallowed_paths: list[str] = []

    auth_manager = AuthManager(config.auth)

    # Fetch robots.txt
    async with aiohttp.ClientSession() as session:
        robots_url = urljoin(base_url + "/", "/robots.txt")
        status, body, _, _ = await _fetch(session, robots_url)
        if status == 200 and body:
            disallowed_paths, sitemap_urls = parse_robots_txt(body, base_url)
            # Fetch sitemaps
            for sm_url in sitemap_urls:
                sm_status, sm_body, _, _ = await _fetch(session, sm_url)
                if sm_status == 200 and sm_body:
                    found = parse_sitemap(sm_body)
                    for u in found:
                        # Could be nested sitemap or actual URL
                        if u.endswith(".xml"):
                            nested_status, nested_body, _, _ = await _fetch(session, u)
                            if nested_status == 200 and nested_body:
                                seed_urls.extend(parse_sitemap(nested_body))
                        else:
                            seed_urls.append(u)

    # Add framework-discovered routes
    if framework_routes:
        for route in framework_routes:
            full = normalize_url(route, base=base_url)
            if full:
                seed_urls.append(full)

    # Pass 1: Anonymous crawl
    anon_nodes, anon_edges = await _crawl_pass(
        base_url, seed_urls, config,
        auth_manager=auth_manager,
        auth_context=AuthContext.anonymous,
        disallowed_paths=disallowed_paths,
    )

    # Pass 2: Authenticated crawl (if auth configured)
    auth_nodes: dict[str, Node] = {}
    auth_edges: list[Edge] = []
    if auth_manager.has_auth:
        auth_nodes, auth_edges = await _crawl_pass(
            base_url, seed_urls, config,
            auth_manager=auth_manager,
            auth_context=AuthContext.authenticated,
            disallowed_paths=disallowed_paths,
        )

    # Merge results
    merged_nodes: dict[str, Node] = {}
    for nid, node in anon_nodes.items():
        merged_nodes[nid] = node

    for nid, node in auth_nodes.items():
        if nid in merged_nodes:
            # Node found in both passes -- accessible without auth
            existing = merged_nodes[nid]
            existing.requires_auth = False
            if AuthContext.authenticated not in existing.auth_contexts_available:
                existing.auth_contexts_available.append(AuthContext.authenticated)
        else:
            # Only found in auth pass -- requires auth
            node.requires_auth = True
            merged_nodes[nid] = node

    # Nodes only in anon pass that redirected to login: already marked requires_auth=True
    # Nodes only in anon pass with no redirect: mark as public
    for nid, node in merged_nodes.items():
        if node.requires_auth is None:
            node.requires_auth = False

    # Merge edges (deduplicate by source+target+auth_context)
    edge_set: set[tuple[str, str, str]] = set()
    merged_edges: list[Edge] = []
    for edge in anon_edges + auth_edges:
        key = (edge.source, edge.target, edge.auth_context)
        if key not in edge_set:
            edge_set.add(key)
            merged_edges.append(edge)

    graph = SiteGraph(
        nodes=merged_nodes,
        edges=merged_edges,
        root_url=base_url,
        seed_urls=seed_urls,
    )

    duration = (time.monotonic() - start) * 1000
    phase.status = "completed"
    phase.completed_at = datetime.now(timezone.utc).isoformat()
    phase.duration_ms = duration

    return graph, phase
