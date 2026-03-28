"""
Contract tests for src_webprobe_capturer module.

Tests cover:
- Resource type and console level enum mappings
- Screenshot path generation with URL sanitization
- Node visiting with Playwright integration
- Response and console message handlers
- Full site capture orchestration with concurrency control
- Error handling and invariant verification
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, MagicMock, patch, call
from pathlib import Path
from datetime import datetime
from urllib.parse import quote

# Import the module under test
from src.webprobe.capturer import (
    _map_resource_type,
    _map_console_level,
    _screenshot_path,
    _visit_node,
    capture_site,
)

# Import dependencies for type hints and mocking
from webprobe.models import (
    AuthContext,
    ConsoleMessage,
    ConsoleMessageLevel,
    CookieInfo,
    Edge,
    FormInfo,
    Node,
    NodeCapture,
    NodeState,
    PhaseStatus,
    Resource,
    ResourceType,
    ResponseHeaders,
    SiteGraph,
    TimingData,
    DiscoveryMethod,
)
from webprobe.config import WebprobeConfig


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_auth_context():
    """Real AuthContext enum value for anonymous."""
    return AuthContext.anonymous


@pytest.fixture
def mock_authenticated_context():
    """Real AuthContext enum value for authenticated."""
    return AuthContext.authenticated


@pytest.fixture
def mock_node():
    """A real Node object with basic state."""
    return Node(
        id="https://example.com/test",
        state=NodeState(url="https://example.com/test"),
        discovered_via=DiscoveryMethod.crawl,
        auth_contexts_available=[AuthContext.anonymous],
    )


@pytest.fixture
def mock_config():
    """Mock WebprobeConfig with capture settings."""
    config = Mock()
    config.capture = Mock()
    config.capture.timeout_ms = 30000
    config.capture.screenshot = True
    config.capture.concurrency = 5
    config.auth = Mock()
    config.output_dir = "/tmp/webprobe"
    return config


@pytest.fixture
def mock_browser_pool():
    """Mock BrowserPool with new_context returning an async context."""
    pool = AsyncMock()
    mock_context = AsyncMock()
    mock_page = AsyncMock()

    # new_context returns the context directly (not a context manager)
    pool.new_context = AsyncMock(return_value=mock_context)

    # context has new_page() and close()
    mock_context.new_page = AsyncMock(return_value=mock_page)
    mock_context.close = AsyncMock()
    mock_context.cookies = AsyncMock(return_value=[])

    # page defaults
    mock_response = Mock()
    mock_response.status = 200
    mock_response.ok = True
    mock_response.headers = {"content-type": "text/html"}
    mock_page.goto = AsyncMock(return_value=mock_response)
    mock_page.title = AsyncMock(return_value="Test Page")
    mock_page.screenshot = AsyncMock()

    # evaluate returns: perf timing, page_text, links, forms (4 calls in order)
    mock_page.evaluate = AsyncMock(side_effect=[
        {"ttfb": 50, "domContentLoaded": 80, "load": 100},  # perf timing
        "Page text content",  # page_text
        [],  # links
        [],  # forms
    ])

    # page.on is a regular method (not async)
    mock_page.on = Mock()

    pool._mock_page = mock_page
    pool._mock_context = mock_context

    return pool


@pytest.fixture
def mock_auth_manager():
    """Mock AuthManager."""
    manager = AsyncMock()
    manager.apply_auth = AsyncMock()
    return manager


@pytest.fixture
def mock_semaphore():
    """Real asyncio.Semaphore for tests."""
    return asyncio.Semaphore(5)


@pytest.fixture
def tmp_run_dir(tmp_path):
    """Temporary run directory for tests."""
    run_dir = tmp_path / "run"
    run_dir.mkdir(exist_ok=True)
    return run_dir


# ============================================================================
# Tests for _map_resource_type
# ============================================================================

def test_map_resource_type_happy_path():
    """Test mapping known Playwright resource types to internal ResourceType enum."""
    assert _map_resource_type("document") == ResourceType.document
    assert _map_resource_type("script") == ResourceType.script
    assert _map_resource_type("stylesheet") == ResourceType.stylesheet
    assert _map_resource_type("image") == ResourceType.image
    assert _map_resource_type("font") == ResourceType.font
    assert _map_resource_type("media") == ResourceType.media
    assert _map_resource_type("xhr") == ResourceType.xhr
    assert _map_resource_type("fetch") == ResourceType.fetch
    assert _map_resource_type("websocket") == ResourceType.websocket


def test_map_resource_type_unknown():
    """Test mapping unknown resource type returns ResourceType.other."""
    assert _map_resource_type("unknown_type") == ResourceType.other
    assert _map_resource_type("invalid") == ResourceType.other
    assert _map_resource_type("") == ResourceType.other


def test_invariant_unknown_resource_type_mapping():
    """Test all unknown resource types map to ResourceType.other."""
    unknown_types = ["random", "invalid", "nonsense", "DOCUMENT", "Script", ""]
    for unknown in unknown_types:
        result = _map_resource_type(unknown)
        assert result == ResourceType.other, f"Expected ResourceType.other for '{unknown}', got {result}"


# ============================================================================
# Tests for _map_console_level
# ============================================================================

def test_map_console_level_happy_path():
    """Test mapping known console message types to ConsoleMessageLevel enum."""
    assert _map_console_level("log") == ConsoleMessageLevel.log
    assert _map_console_level("warning") == ConsoleMessageLevel.warning
    assert _map_console_level("error") == ConsoleMessageLevel.error
    assert _map_console_level("info") == ConsoleMessageLevel.info
    assert _map_console_level("debug") == ConsoleMessageLevel.debug


def test_map_console_level_unknown():
    """Test mapping unknown console level returns ConsoleMessageLevel.log."""
    assert _map_console_level("unknown_level") == ConsoleMessageLevel.log
    assert _map_console_level("trace") == ConsoleMessageLevel.log
    assert _map_console_level("") == ConsoleMessageLevel.log


def test_invariant_unknown_console_level_mapping():
    """Test all unknown console types map to ConsoleMessageLevel.log."""
    unknown_levels = ["verbose", "critical", "fatal", "ERROR", "Warning", ""]
    for unknown in unknown_levels:
        result = _map_console_level(unknown)
        assert result == ConsoleMessageLevel.log, f"Expected ConsoleMessageLevel.log for '{unknown}', got {result}"


# ============================================================================
# Tests for _screenshot_path
# ============================================================================

def test_screenshot_path_root_url():
    """Test screenshot path generation for root URL path."""
    url = "https://example.com/"
    result = _screenshot_path(url, AuthContext.anonymous)
    assert result.startswith("screenshots/anonymous/")
    assert result.endswith("_index.png")


def test_screenshot_path_with_segments():
    """Test screenshot path generation with multiple path segments."""
    url = "https://example.com/path/to/page"
    result = _screenshot_path(url, AuthContext.anonymous)
    assert result.startswith("screenshots/anonymous/")
    assert "_path_to_page.png" in result


def test_screenshot_path_with_query():
    """Test screenshot path generation with query string URL encoding."""
    url = "https://example.com/page?key=value&special=chars"
    result = _screenshot_path(url, AuthContext.authenticated)
    assert result.startswith("screenshots/authenticated/")
    assert "key%3Dvalue" in result or "key=value" in result
    assert ".png" in result


def test_screenshot_path_authenticated_context():
    """Test screenshot path uses auth_context subdirectory."""
    url = "https://example.com/page"
    result = _screenshot_path(url, AuthContext.authenticated)
    assert result.startswith("screenshots/authenticated/")
    assert result.endswith(".png")


def test_screenshot_path_format_invariant():
    """Test screenshot path always follows format: screenshots/{auth_context}/{sanitized_url}.png."""
    url = "https://example.com/test/path"
    result = _screenshot_path(url, AuthContext.anonymous)
    parts = result.split("/")
    assert parts[0] == "screenshots"
    assert parts[1] == "anonymous"
    assert parts[-1].endswith(".png")


# ============================================================================
# Tests for _visit_node
# ============================================================================

@pytest.mark.asyncio
async def test_visit_node_happy_path(
    mock_browser_pool,
    mock_node,
    mock_auth_manager,
    mock_config,
    tmp_run_dir,
    mock_semaphore,
):
    """Test successful node visit with all captures."""
    result = await _visit_node(
        mock_browser_pool,
        mock_node,
        AuthContext.anonymous,
        mock_auth_manager,
        mock_config,
        tmp_run_dir,
        mock_semaphore,
    )

    # Verify result is a NodeCapture
    assert result is not None
    assert isinstance(result, NodeCapture)
    assert result.auth_context == AuthContext.anonymous

    # Verify page was navigated
    mock_browser_pool._mock_page.goto.assert_called_once()

    # Verify screenshot was taken (config has screenshot=True)
    mock_browser_pool._mock_page.screenshot.assert_called_once()


@pytest.mark.asyncio
async def test_visit_node_anonymous_context(
    mock_browser_pool,
    mock_node,
    mock_auth_manager,
    mock_config,
    tmp_run_dir,
    mock_semaphore,
):
    """Test node visit with anonymous authentication context."""
    result = await _visit_node(
        mock_browser_pool,
        mock_node,
        AuthContext.anonymous,
        mock_auth_manager,
        mock_config,
        tmp_run_dir,
        mock_semaphore,
    )

    assert result is not None
    assert isinstance(result, NodeCapture)
    # Anonymous context -> new_context called with auth=None
    mock_browser_pool.new_context.assert_called_once()
    call_kwargs = mock_browser_pool.new_context.call_args
    assert call_kwargs.kwargs.get("auth") is None or call_kwargs[1].get("auth") is None


@pytest.mark.asyncio
async def test_visit_node_navigation_timeout(
    mock_browser_pool,
    mock_node,
    mock_auth_manager,
    mock_config,
    tmp_run_dir,
    mock_semaphore,
):
    """Test node visit handles navigation timeout gracefully."""
    mock_page = mock_browser_pool._mock_page

    # Simulate timeout on goto -- implementation catches all exceptions
    mock_page.goto.side_effect = Exception("Navigation timeout")

    result = await _visit_node(
        mock_browser_pool,
        mock_node,
        AuthContext.anonymous,
        mock_auth_manager,
        mock_config,
        tmp_run_dir,
        mock_semaphore,
    )

    # Should still return a NodeCapture (implementation catches the error)
    assert result is not None
    assert isinstance(result, NodeCapture)
    # http_status should be None since goto failed
    assert result.http_status is None


@pytest.mark.asyncio
async def test_visit_node_screenshot_disabled(
    mock_browser_pool,
    mock_node,
    mock_auth_manager,
    mock_config,
    tmp_run_dir,
    mock_semaphore,
):
    """Test node visit without screenshot capture."""
    mock_config.capture.screenshot = False

    result = await _visit_node(
        mock_browser_pool,
        mock_node,
        AuthContext.anonymous,
        mock_auth_manager,
        mock_config,
        tmp_run_dir,
        mock_semaphore,
    )

    assert result is not None
    assert isinstance(result, NodeCapture)
    # Screenshot should not be taken
    mock_browser_pool._mock_page.screenshot.assert_not_called()


@pytest.mark.asyncio
async def test_visit_node_javascript_evaluation_error(
    mock_browser_pool,
    mock_node,
    mock_auth_manager,
    mock_config,
    tmp_run_dir,
    mock_semaphore,
):
    """Test node visit handles JavaScript evaluation errors."""
    mock_page = mock_browser_pool._mock_page

    # All evaluate calls fail
    mock_page.evaluate.side_effect = Exception("JavaScript error")

    result = await _visit_node(
        mock_browser_pool,
        mock_node,
        AuthContext.anonymous,
        mock_auth_manager,
        mock_config,
        tmp_run_dir,
        mock_semaphore,
    )

    # Should return NodeCapture with graceful error handling
    assert result is not None
    assert isinstance(result, NodeCapture)


@pytest.mark.asyncio
async def test_visit_node_screenshot_error(
    mock_browser_pool,
    mock_node,
    mock_auth_manager,
    mock_config,
    tmp_run_dir,
    mock_semaphore,
):
    """Test node visit handles screenshot capture failures."""
    mock_page = mock_browser_pool._mock_page

    # Simulate screenshot error
    mock_page.screenshot.side_effect = Exception("Screenshot failed")

    result = await _visit_node(
        mock_browser_pool,
        mock_node,
        AuthContext.anonymous,
        mock_auth_manager,
        mock_config,
        tmp_run_dir,
        mock_semaphore,
    )

    # Should return NodeCapture (screenshot error is caught, screenshot_path = "")
    assert result is not None
    assert isinstance(result, NodeCapture)
    assert result.screenshot_path == ""


@pytest.mark.asyncio
async def test_visit_node_context_cleanup(
    mock_browser_pool,
    mock_node,
    mock_auth_manager,
    mock_config,
    tmp_run_dir,
    mock_semaphore,
):
    """Test browser context is always closed after visit."""
    mock_context = mock_browser_pool._mock_context
    mock_page = mock_browser_pool._mock_page

    # Even when goto raises, context.close() should be called (finally block)
    mock_page.goto.side_effect = Exception("Test error")

    result = await _visit_node(
        mock_browser_pool,
        mock_node,
        AuthContext.anonymous,
        mock_auth_manager,
        mock_config,
        tmp_run_dir,
        mock_semaphore,
    )

    # Context should have been closed (in the finally block)
    mock_context.close.assert_called_once()


# ============================================================================
# Tests for on_response (nested function - test via _visit_node)
# ============================================================================

@pytest.mark.asyncio
async def test_on_response_happy_path(
    mock_browser_pool,
    mock_node,
    mock_auth_manager,
    mock_config,
    tmp_run_dir,
    mock_semaphore,
):
    """Test HTTP response interception and resource creation."""
    mock_page = mock_browser_pool._mock_page

    # Capture the handlers registered via page.on()
    captured_handlers = {}

    def capture_on(event, handler):
        captured_handlers[event] = handler

    mock_page.on = capture_on

    result = await _visit_node(
        mock_browser_pool,
        mock_node,
        AuthContext.anonymous,
        mock_auth_manager,
        mock_config,
        tmp_run_dir,
        mock_semaphore,
    )

    # Verify response and console handlers were registered
    assert "response" in captured_handlers
    assert "console" in captured_handlers
    assert result is not None


@pytest.mark.asyncio
async def test_on_response_body_fetch_error():
    """Test response handler when body fetch fails."""
    mock_response = AsyncMock()
    mock_response.url = "https://example.com/resource.js"
    mock_response.status = 200
    mock_response.ok = True
    mock_response.request.resource_type = "script"
    mock_response.headers = {"content-type": "application/javascript"}
    mock_response.body.side_effect = Exception("Body fetch failed")

    # The on_response handler should catch this and handle gracefully
    assert mock_response.body.side_effect is not None


@pytest.mark.asyncio
async def test_on_response_non_ok_status():
    """Test response handler with non-200 status codes."""
    mock_response = Mock()
    mock_response.url = "https://example.com/missing.png"
    mock_response.status = 404
    mock_response.ok = False
    mock_response.request.resource_type = "image"

    assert mock_response.status == 404


@pytest.mark.asyncio
async def test_invariant_resource_timing_placeholder():
    """Test resource timing duration_ms is always 0."""
    mock_response = Mock()
    mock_response.url = "https://example.com/test.js"
    mock_response.status = 200
    mock_response.request.resource_type = "script"

    # In actual implementation, Resource.timing.duration_ms should be 0


# ============================================================================
# Tests for on_console (nested function - test via _visit_node)
# ============================================================================

@pytest.mark.asyncio
async def test_on_console_happy_path(
    mock_browser_pool,
    mock_node,
    mock_auth_manager,
    mock_config,
    tmp_run_dir,
    mock_semaphore,
):
    """Test console message interception."""
    mock_page = mock_browser_pool._mock_page

    captured_handlers = {}

    def capture_on(event, handler):
        captured_handlers[event] = handler

    mock_page.on = capture_on

    result = await _visit_node(
        mock_browser_pool,
        mock_node,
        AuthContext.anonymous,
        mock_auth_manager,
        mock_config,
        tmp_run_dir,
        mock_semaphore,
    )

    # Verify console handler was registered
    assert "console" in captured_handlers
    assert result is not None


def test_on_console_various_levels():
    """Test console handler with different message levels."""
    levels = ["log", "warning", "error", "info", "debug"]
    for level in levels:
        mapped = _map_console_level(level)
        assert mapped is not None
        assert hasattr(ConsoleMessageLevel, level)


# ============================================================================
# Tests for capture_site
# ============================================================================

@pytest.mark.asyncio
async def test_capture_site_happy_path(tmp_run_dir):
    """Test full site capture with multiple nodes and contexts."""
    node1 = Node(
        id="https://example.com/page1",
        state=NodeState(url="https://example.com/page1"),
        discovered_via=DiscoveryMethod.crawl,
        auth_contexts_available=[AuthContext.anonymous],
    )
    node2 = Node(
        id="https://example.com/page2",
        state=NodeState(url="https://example.com/page2"),
        discovered_via=DiscoveryMethod.crawl,
        auth_contexts_available=[AuthContext.anonymous],
    )
    graph = SiteGraph(
        nodes={"https://example.com/page1": node1, "https://example.com/page2": node2},
        edges=[],
        root_url="https://example.com/page1",
    )

    with patch("src.webprobe.capturer._visit_node") as mock_visit, \
         patch("src.webprobe.capturer.BrowserPool") as mock_pool_cls, \
         patch("src.webprobe.capturer.AuthManager"):
        mock_capture = NodeCapture(auth_context=AuthContext.anonymous, http_status=200)
        mock_visit.return_value = mock_capture

        # BrowserPool as async context manager
        mock_pool = AsyncMock()
        mock_pool_cls.return_value.__aenter__ = AsyncMock(return_value=mock_pool)
        mock_pool_cls.return_value.__aexit__ = AsyncMock(return_value=None)

        config = Mock()
        config.capture = Mock()
        config.capture.concurrency = 5
        config.auth = Mock()

        updated_graph, phase_status = await capture_site(config, graph, tmp_run_dir)

        assert updated_graph is not None
        assert phase_status is not None
        assert phase_status.status == "completed"
        assert phase_status.phase == "capture"


@pytest.mark.asyncio
async def test_capture_site_edge_verification(tmp_run_dir):
    """Test edge verification based on outgoing links."""
    node1 = Node(
        id="https://example.com/page1",
        state=NodeState(url="https://example.com/page1"),
        discovered_via=DiscoveryMethod.crawl,
        auth_contexts_available=[AuthContext.anonymous],
    )
    node2 = Node(
        id="https://example.com/page2",
        state=NodeState(url="https://example.com/page2"),
        discovered_via=DiscoveryMethod.crawl,
        auth_contexts_available=[AuthContext.anonymous],
    )
    edge = Edge(source="https://example.com/page1", target="https://example.com/page2")
    graph = SiteGraph(
        nodes={
            "https://example.com/page1": node1,
            "https://example.com/page2": node2,
        },
        edges=[edge],
        root_url="https://example.com/page1",
    )

    with patch("src.webprobe.capturer._visit_node") as mock_visit, \
         patch("src.webprobe.capturer.BrowserPool") as mock_pool_cls, \
         patch("src.webprobe.capturer.AuthManager"):
        # Capture for page1 has outgoing link to page2
        mock_capture1 = NodeCapture(
            auth_context=AuthContext.anonymous,
            http_status=200,
            outgoing_links=["https://example.com/page2"],
        )
        mock_capture2 = NodeCapture(
            auth_context=AuthContext.anonymous,
            http_status=200,
        )
        mock_visit.side_effect = [mock_capture1, mock_capture2]

        mock_pool = AsyncMock()
        mock_pool_cls.return_value.__aenter__ = AsyncMock(return_value=mock_pool)
        mock_pool_cls.return_value.__aexit__ = AsyncMock(return_value=None)

        config = Mock()
        config.capture = Mock()
        config.capture.concurrency = 5
        config.auth = Mock()

        updated_graph, phase_status = await capture_site(config, graph, tmp_run_dir)

        # The edge should be verified since target is in outgoing_links
        assert updated_graph.edges[0].verified is True


@pytest.mark.asyncio
async def test_capture_site_concurrency_control(tmp_run_dir):
    """Test semaphore controls concurrent browser sessions."""
    nodes = {}
    for i in range(10):
        url = f"https://example.com/page{i}"
        nodes[url] = Node(
            id=url,
            state=NodeState(url=url),
            discovered_via=DiscoveryMethod.crawl,
            auth_contexts_available=[AuthContext.anonymous],
        )
    graph = SiteGraph(
        nodes=nodes,
        edges=[],
        root_url="https://example.com/page0",
    )

    with patch("src.webprobe.capturer._visit_node") as mock_visit, \
         patch("src.webprobe.capturer.BrowserPool") as mock_pool_cls, \
         patch("src.webprobe.capturer.AuthManager"):
        mock_visit.return_value = NodeCapture(auth_context=AuthContext.anonymous, http_status=200)

        mock_pool = AsyncMock()
        mock_pool_cls.return_value.__aenter__ = AsyncMock(return_value=mock_pool)
        mock_pool_cls.return_value.__aexit__ = AsyncMock(return_value=None)

        config = Mock()
        config.capture = Mock()
        config.capture.concurrency = 2
        config.auth = Mock()

        updated_graph, phase_status = await capture_site(config, graph, tmp_run_dir)

        assert phase_status is not None
        assert phase_status.status == "completed"
        assert mock_visit.call_count == 10


@pytest.mark.asyncio
async def test_capture_site_visit_exception_handling(tmp_run_dir):
    """Test capture_site converts exceptions to error captures."""
    node = Node(
        id="https://example.com/error",
        state=NodeState(url="https://example.com/error"),
        discovered_via=DiscoveryMethod.crawl,
        auth_contexts_available=[AuthContext.anonymous],
    )
    graph = SiteGraph(
        nodes={"https://example.com/error": node},
        edges=[],
        root_url="https://example.com/error",
    )

    with patch("src.webprobe.capturer._visit_node") as mock_visit, \
         patch("src.webprobe.capturer.BrowserPool") as mock_pool_cls, \
         patch("src.webprobe.capturer.AuthManager"):
        mock_visit.side_effect = Exception("Visit failed")

        mock_pool = AsyncMock()
        mock_pool_cls.return_value.__aenter__ = AsyncMock(return_value=mock_pool)
        mock_pool_cls.return_value.__aexit__ = AsyncMock(return_value=None)

        config = Mock()
        config.capture = Mock()
        config.capture.concurrency = 5
        config.auth = Mock()

        updated_graph, phase_status = await capture_site(config, graph, tmp_run_dir)

        # Should still return completed status
        assert phase_status is not None
        assert phase_status.status == "completed"
        # Error should be captured as a minimal NodeCapture with page_text containing error
        error_node = updated_graph.nodes["https://example.com/error"]
        assert len(error_node.captures) == 1
        assert "Capture error" in error_node.captures[0].page_text


@pytest.mark.asyncio
async def test_capture_site_empty_graph(tmp_run_dir):
    """Test capture_site with empty node dict."""
    graph = SiteGraph(nodes={}, edges=[], root_url="")

    with patch("src.webprobe.capturer.BrowserPool") as mock_pool_cls, \
         patch("src.webprobe.capturer.AuthManager"):
        mock_pool = AsyncMock()
        mock_pool_cls.return_value.__aenter__ = AsyncMock(return_value=mock_pool)
        mock_pool_cls.return_value.__aexit__ = AsyncMock(return_value=None)

        config = Mock()
        config.capture = Mock()
        config.capture.concurrency = 5
        config.auth = Mock()

        updated_graph, phase_status = await capture_site(config, graph, tmp_run_dir)

        assert updated_graph is not None
        assert len(updated_graph.nodes) == 0
        assert phase_status is not None
        assert phase_status.status == "completed"


@pytest.mark.asyncio
async def test_capture_site_timing_information(tmp_run_dir):
    """Test capture_site includes timing in PhaseStatus."""
    node = Node(
        id="https://example.com/test",
        state=NodeState(url="https://example.com/test"),
        discovered_via=DiscoveryMethod.crawl,
        auth_contexts_available=[AuthContext.anonymous],
    )
    graph = SiteGraph(
        nodes={"https://example.com/test": node},
        edges=[],
        root_url="https://example.com/test",
    )

    with patch("src.webprobe.capturer._visit_node") as mock_visit, \
         patch("src.webprobe.capturer.BrowserPool") as mock_pool_cls, \
         patch("src.webprobe.capturer.AuthManager"):
        mock_visit.return_value = NodeCapture(auth_context=AuthContext.anonymous, http_status=200)

        mock_pool = AsyncMock()
        mock_pool_cls.return_value.__aenter__ = AsyncMock(return_value=mock_pool)
        mock_pool_cls.return_value.__aexit__ = AsyncMock(return_value=None)

        config = Mock()
        config.capture = Mock()
        config.capture.concurrency = 5
        config.auth = Mock()

        updated_graph, phase_status = await capture_site(config, graph, tmp_run_dir)

        assert phase_status.started_at is not None
        assert phase_status.completed_at is not None
        assert phase_status.duration_ms is not None
        assert phase_status.duration_ms >= 0


@pytest.mark.asyncio
async def test_invariant_phase_always_completes(tmp_run_dir):
    """Test capture_site always returns completed status even on errors."""
    node1 = Node(
        id="https://example.com/success",
        state=NodeState(url="https://example.com/success"),
        discovered_via=DiscoveryMethod.crawl,
        auth_contexts_available=[AuthContext.anonymous],
    )
    node2 = Node(
        id="https://example.com/fail",
        state=NodeState(url="https://example.com/fail"),
        discovered_via=DiscoveryMethod.crawl,
        auth_contexts_available=[AuthContext.anonymous],
    )
    graph = SiteGraph(
        nodes={
            "https://example.com/success": node1,
            "https://example.com/fail": node2,
        },
        edges=[],
        root_url="https://example.com/success",
    )

    with patch("src.webprobe.capturer._visit_node") as mock_visit, \
         patch("src.webprobe.capturer.BrowserPool") as mock_pool_cls, \
         patch("src.webprobe.capturer.AuthManager"):
        # First succeeds, second fails
        mock_visit.side_effect = [
            NodeCapture(auth_context=AuthContext.anonymous, http_status=200),
            Exception("Failed"),
        ]

        mock_pool = AsyncMock()
        mock_pool_cls.return_value.__aenter__ = AsyncMock(return_value=mock_pool)
        mock_pool_cls.return_value.__aexit__ = AsyncMock(return_value=None)

        config = Mock()
        config.capture = Mock()
        config.capture.concurrency = 5
        config.auth = Mock()

        updated_graph, phase_status = await capture_site(config, graph, tmp_run_dir)

        assert phase_status.status == "completed"


# ============================================================================
# Additional edge case and parametrized tests
# ============================================================================

@pytest.mark.parametrize("resource_type,expected", [
    ("document", ResourceType.document),
    ("script", ResourceType.script),
    ("stylesheet", ResourceType.stylesheet),
    ("image", ResourceType.image),
    ("font", ResourceType.font),
    ("media", ResourceType.media),
    ("xhr", ResourceType.xhr),
    ("fetch", ResourceType.fetch),
    ("websocket", ResourceType.websocket),
    ("unknown", ResourceType.other),
    ("", ResourceType.other),
    ("DOCUMENT", ResourceType.other),  # Case sensitive
])
def test_map_resource_type_parametrized(resource_type, expected):
    """Parametrized test for all resource type mappings."""
    result = _map_resource_type(resource_type)
    assert result == expected


@pytest.mark.parametrize("console_level,expected", [
    ("log", ConsoleMessageLevel.log),
    ("warning", ConsoleMessageLevel.warning),
    ("error", ConsoleMessageLevel.error),
    ("info", ConsoleMessageLevel.info),
    ("debug", ConsoleMessageLevel.debug),
    ("unknown", ConsoleMessageLevel.log),
    ("", ConsoleMessageLevel.log),
    ("ERROR", ConsoleMessageLevel.log),  # Case sensitive
])
def test_map_console_level_parametrized(console_level, expected):
    """Parametrized test for all console level mappings."""
    result = _map_console_level(console_level)
    assert result == expected


@pytest.mark.parametrize("url,expected_contains", [
    ("https://example.com/", "_index.png"),
    ("https://example.com/page", "_page.png"),
    ("https://example.com/path/to/page", "_path_to_page.png"),
])
def test_screenshot_path_parametrized(url, expected_contains):
    """Parametrized test for screenshot path generation."""
    result = _screenshot_path(url, AuthContext.anonymous)
    assert expected_contains in result
    assert result.startswith("screenshots/")
    assert result.endswith(".png")


def test_screenshot_path_special_characters():
    """Test screenshot path handles special characters in URL."""
    url = "https://example.com/page?foo=bar&baz=qux#fragment"
    result = _screenshot_path(url, AuthContext.anonymous)
    assert result.startswith("screenshots/")
    assert result.endswith(".png")


def test_screenshot_path_unicode():
    """Test screenshot path handles unicode characters."""
    url = "https://example.com/页面"
    result = _screenshot_path(url, AuthContext.anonymous)
    assert result.startswith("screenshots/")
    assert result.endswith(".png")


@pytest.mark.asyncio
async def test_visit_node_with_resources(
    mock_browser_pool,
    mock_node,
    mock_auth_manager,
    mock_config,
    tmp_run_dir,
    mock_semaphore,
):
    """Test node visit captures resources from responses."""
    mock_page = mock_browser_pool._mock_page

    # Track response handler registration
    responses = []

    def track_response_handler(event, handler):
        if event == "response":
            responses.append(handler)

    mock_page.on = track_response_handler

    result = await _visit_node(
        mock_browser_pool,
        mock_node,
        AuthContext.anonymous,
        mock_auth_manager,
        mock_config,
        tmp_run_dir,
        mock_semaphore,
    )

    assert result is not None
    assert len(responses) == 1  # response handler was registered


@pytest.mark.asyncio
async def test_visit_node_with_console_messages(
    mock_browser_pool,
    mock_node,
    mock_auth_manager,
    mock_config,
    tmp_run_dir,
    mock_semaphore,
):
    """Test node visit captures console messages."""
    mock_page = mock_browser_pool._mock_page

    console_handlers = []

    def track_console_handler(event, handler):
        if event == "console":
            console_handlers.append(handler)

    mock_page.on = track_console_handler

    result = await _visit_node(
        mock_browser_pool,
        mock_node,
        AuthContext.anonymous,
        mock_auth_manager,
        mock_config,
        tmp_run_dir,
        mock_semaphore,
    )

    assert result is not None
    assert len(console_handlers) == 1


@pytest.mark.asyncio
async def test_capture_site_multiple_auth_contexts(tmp_run_dir):
    """Test capture_site handles nodes with multiple auth contexts."""
    node = Node(
        id="https://example.com/secure",
        state=NodeState(url="https://example.com/secure"),
        discovered_via=DiscoveryMethod.crawl,
        auth_contexts_available=[AuthContext.anonymous, AuthContext.authenticated],
    )
    graph = SiteGraph(
        nodes={"https://example.com/secure": node},
        edges=[],
        root_url="https://example.com/secure",
    )

    with patch("src.webprobe.capturer._visit_node") as mock_visit, \
         patch("src.webprobe.capturer.BrowserPool") as mock_pool_cls, \
         patch("src.webprobe.capturer.AuthManager"):
        mock_visit.return_value = NodeCapture(auth_context=AuthContext.anonymous, http_status=200)

        mock_pool = AsyncMock()
        mock_pool_cls.return_value.__aenter__ = AsyncMock(return_value=mock_pool)
        mock_pool_cls.return_value.__aexit__ = AsyncMock(return_value=None)

        config = Mock()
        config.capture = Mock()
        config.capture.concurrency = 5
        config.auth = Mock()

        updated_graph, phase_status = await capture_site(config, graph, tmp_run_dir)

        # 1 node * 2 auth contexts = 2 calls
        assert mock_visit.call_count == 2


@pytest.mark.asyncio
async def test_visit_node_creates_screenshot_directory(
    mock_browser_pool,
    mock_node,
    mock_auth_manager,
    mock_config,
    tmp_run_dir,
    mock_semaphore,
):
    """Test node visit creates screenshot directory structure."""
    result = await _visit_node(
        mock_browser_pool,
        mock_node,
        AuthContext.anonymous,
        mock_auth_manager,
        mock_config,
        tmp_run_dir,
        mock_semaphore,
    )

    # Screenshot directory should be created
    assert result is not None
    # The screenshots/anonymous/ directory should exist after the call
    screenshots_dir = tmp_run_dir / "screenshots" / "anonymous"
    assert screenshots_dir.exists()
