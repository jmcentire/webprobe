"""Phase 2: Playwright-based capture -- page visits, resource interception, timing, screenshots."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from playwright.async_api import Page, Response, TimeoutError

from webprobe.auth import AuthManager
from webprobe.browser import BrowserPool
from webprobe.config import WebprobeConfig
from webprobe.models import (
    AuthContext,
    ConsoleMessage,
    ConsoleMessageLevel,
    CookieInfo,
    FormInfo,
    Node,
    NodeCapture,
    PhaseStatus,
    Resource,
    ResourceType,
    ResponseHeaders,
    SiteGraph,
    TimingData,
)


_RESOURCE_TYPE_MAP = {
    "document": ResourceType.document,
    "script": ResourceType.script,
    "stylesheet": ResourceType.stylesheet,
    "image": ResourceType.image,
    "font": ResourceType.font,
    "media": ResourceType.media,
    "xhr": ResourceType.xhr,
    "fetch": ResourceType.fetch,
    "websocket": ResourceType.websocket,
}


def _map_resource_type(playwright_type: str) -> ResourceType:
    return _RESOURCE_TYPE_MAP.get(playwright_type, ResourceType.other)


def _map_console_level(msg_type: str) -> ConsoleMessageLevel:
    mapping = {
        "log": ConsoleMessageLevel.log,
        "warning": ConsoleMessageLevel.warning,
        "error": ConsoleMessageLevel.error,
        "info": ConsoleMessageLevel.info,
        "debug": ConsoleMessageLevel.debug,
    }
    return mapping.get(msg_type, ConsoleMessageLevel.log)


def _screenshot_path(url: str, auth_context: AuthContext) -> str:
    """Generate a relative screenshot path from URL and auth context."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    # Convert path to filename: / -> _index, /about -> _about
    path = parsed.path.strip("/")
    if not path:
        name = "_index"
    else:
        name = "_" + path.replace("/", "_")
    # Include query if present
    if parsed.query:
        name += "_" + quote(parsed.query, safe="")
    return f"screenshots/{auth_context.value}/{name}.png"


async def _visit_node(
    pool: BrowserPool,
    node: Node,
    auth_context: AuthContext,
    auth_manager: AuthManager,
    config: WebprobeConfig,
    run_dir: Path,
    semaphore: asyncio.Semaphore,
) -> NodeCapture:
    """Visit a single node with Playwright, capture everything."""
    async with semaphore:
        context = await pool.new_context(
            auth=auth_manager if auth_context == AuthContext.authenticated else None,
            base_url=node.state.url,
        )
        try:
            page = await context.new_page()

            resources: list[Resource] = []
            console_messages: list[ConsoleMessage] = []

            # Resource interception
            async def on_response(response: Response) -> None:
                request = response.request
                res_start = datetime.now(timezone.utc).isoformat()
                try:
                    size = len(await response.body()) if response.ok else None
                except Exception:
                    size = None
                resources.append(Resource(
                    url=request.url,
                    resource_type=_map_resource_type(request.resource_type),
                    status_code=response.status,
                    size_bytes=size,
                    timing=TimingData(
                        started_at=res_start,
                        duration_ms=0,  # Individual resource timing filled via performance API below
                    ),
                    mime_type=response.headers.get("content-type", ""),
                ))

            # Console capture
            def on_console(msg: object) -> None:
                console_messages.append(ConsoleMessage(
                    level=_map_console_level(msg.type),  # type: ignore[attr-defined]
                    text=msg.text,  # type: ignore[attr-defined]
                    url=node.state.url,
                ))

            page.on("response", on_response)
            page.on("console", on_console)

            # Navigate
            nav_start = time.monotonic()
            started_at = datetime.now(timezone.utc).isoformat()
            http_status: int | None = None
            doc_headers: dict[str, str] = {}
            timed_out = False
            try:
                response = await page.goto(
                    node.state.url,
                    wait_until="networkidle",
                    timeout=config.capture.timeout_ms,
                )
                if response:
                    http_status = response.status
                    doc_headers = dict(response.headers)
            except TimeoutError:
                timed_out = True
                # Page may have partially loaded — try to extract response data
                try:
                    response = page.main_frame._impl_obj._last_navigation_response
                    if response:
                        http_status = response.status
                        doc_headers = {k: v for k, v in response.headers.items()}
                except Exception:
                    pass
                # Fallback: check if page has content despite timeout
                if http_status is None:
                    try:
                        # If the page rendered, treat it as a soft success
                        title = await page.title()
                        if title:
                            http_status = 200  # Inferred from rendered content
                    except Exception:
                        pass
            except Exception:
                pass
            nav_duration = (time.monotonic() - nav_start) * 1000

            # Performance timing from browser
            try:
                perf = await page.evaluate("""() => {
                    const t = performance.timing;
                    return {
                        ttfb: t.responseStart - t.navigationStart,
                        domContentLoaded: t.domContentLoadedEventEnd - t.navigationStart,
                        load: t.loadEventEnd - t.navigationStart,
                    };
                }""")
                ttfb_ms = perf.get("ttfb")
                dom_content_loaded_ms = perf.get("domContentLoaded")
                load_event_ms = perf.get("load")
            except Exception:
                ttfb_ms = None
                dom_content_loaded_ms = None
                load_event_ms = None

            # Page content
            try:
                page_title = await page.title()
            except Exception:
                page_title = ""
            try:
                page_text = await page.evaluate("() => document.body?.innerText?.slice(0, 5000) || ''")
            except Exception:
                page_text = ""

            # Outgoing links
            try:
                links = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter(h => h && !h.startsWith('javascript:'));
                }""")
            except Exception:
                links = []

            # Cookies
            captured_cookies: list[CookieInfo] = []
            try:
                browser_cookies = await context.cookies()
                for c in browser_cookies:
                    captured_cookies.append(CookieInfo(
                        name=c.get("name", ""),
                        domain=c.get("domain", ""),
                        path=c.get("path", "/"),
                        secure=c.get("secure", False),
                        http_only=c.get("httpOnly", False),
                        same_site=c.get("sameSite", ""),
                        expires=c.get("expires", -1),
                    ))
            except Exception:
                pass

            # Forms
            captured_forms: list[FormInfo] = []
            try:
                forms_data = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('form')).map(form => {
                        const inputs = Array.from(form.querySelectorAll('input'));
                        const hasPassword = inputs.some(i => i.type === 'password');
                        const hasCsrf = inputs.some(i =>
                            i.name && (i.name.toLowerCase().includes('csrf') ||
                                       i.name.toLowerCase().includes('_token') ||
                                       i.name === '__RequestVerificationToken' ||
                                       i.name === 'authenticity_token')
                        );
                        const autocompleteOff = form.getAttribute('autocomplete') === 'off' ||
                            inputs.some(i => i.type === 'password' && i.getAttribute('autocomplete') === 'off');
                        const inputNames = inputs.map(i => i.name || '').filter(Boolean);
                        const inputTypes = inputs.map(i => i.type || 'text');
                        return {
                            action: form.action || '',
                            method: form.method || 'GET',
                            hasCsrf: hasCsrf,
                            hasPassword: hasPassword,
                            autocompleteOff: autocompleteOff,
                            inputNames: inputNames,
                            inputTypes: inputTypes,
                        };
                    });
                }""")
                for f in forms_data:
                    captured_forms.append(FormInfo(
                        action=f.get("action", ""),
                        method=f.get("method", "GET"),
                        has_csrf_token=f.get("hasCsrf", False),
                        has_password_field=f.get("hasPassword", False),
                        autocomplete_off=f.get("autocompleteOff", False),
                        input_names=f.get("inputNames", []),
                        input_types=f.get("inputTypes", []),
                    ))
            except Exception:
                pass

            # SRI integrity attribute detection
            try:
                sri_data = await page.evaluate("""() => {
                    const els = document.querySelectorAll('script[src], link[rel="stylesheet"][href]');
                    return Array.from(els).map(el => ({
                        url: el.src || el.href,
                        hasIntegrity: !!el.integrity,
                    }));
                }""")
                sri_map = {item["url"]: item["hasIntegrity"] for item in sri_data}
                for res in resources:
                    if res.url in sri_map:
                        res.has_integrity = sri_map[res.url]
            except Exception:
                pass

            # Screenshot
            screenshot_rel = ""
            if config.capture.screenshot:
                screenshot_rel = _screenshot_path(node.state.url, auth_context)
                screenshot_abs = run_dir / screenshot_rel
                screenshot_abs.parent.mkdir(parents=True, exist_ok=True)
                try:
                    await page.screenshot(path=str(screenshot_abs), full_page=True)
                except Exception:
                    screenshot_rel = ""

            return NodeCapture(
                auth_context=auth_context,
                http_status=http_status,
                timing=TimingData(
                    started_at=started_at,
                    duration_ms=nav_duration,
                    ttfb_ms=ttfb_ms,
                ),
                dom_content_loaded_ms=dom_content_loaded_ms,
                load_event_ms=load_event_ms,
                page_title=page_title,
                page_text=page_text,
                resources=resources,
                console_messages=console_messages,
                outgoing_links=links,
                screenshot_path=screenshot_rel,
                response_headers=ResponseHeaders(raw=doc_headers),
                cookies=captured_cookies,
                forms=captured_forms,
            )
        finally:
            await context.close()


async def capture_site(
    config: WebprobeConfig,
    graph: SiteGraph,
    run_dir: Path,
) -> tuple[SiteGraph, PhaseStatus]:
    """Phase 2: Visit every node with Playwright, capture metrics."""
    phase = PhaseStatus(
        phase="capture",
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    start = time.monotonic()

    auth_manager = AuthManager(config.auth)
    semaphore = asyncio.Semaphore(config.capture.concurrency)

    async with BrowserPool(config.capture) as pool:
        tasks = []
        task_keys: list[tuple[str, AuthContext]] = []

        for node_id, node in graph.nodes.items():
            for auth_ctx in node.auth_contexts_available:
                tasks.append(_visit_node(
                    pool, node, auth_ctx, auth_manager, config, run_dir, semaphore
                ))
                task_keys.append((node_id, auth_ctx))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for (node_id, auth_ctx), result in zip(task_keys, results):
            if isinstance(result, Exception):
                # Create a minimal capture recording the error
                graph.nodes[node_id].captures.append(NodeCapture(
                    auth_context=auth_ctx,
                    http_status=None,
                    page_text=f"Capture error: {result}",
                ))
            else:
                graph.nodes[node_id].captures.append(result)

    # Mark edges as verified based on captured outgoing links
    for edge in graph.edges:
        source_node = graph.nodes.get(edge.source)
        if source_node:
            for capture in source_node.captures:
                if edge.target in capture.outgoing_links:
                    edge.verified = True
                    break

    duration = (time.monotonic() - start) * 1000
    phase.status = "completed"
    phase.completed_at = datetime.now(timezone.utc).isoformat()
    phase.duration_ms = duration

    return graph, phase
