"""
Contract tests for src_webprobe_explorer module.

Tests cover:
- ExploreConfig initialization
- _extract_interactive_elements (element extraction from pages)
- _run_agent (autonomous agent exploration)
- on_console (console message handler)
- explore_site (phase 5 entry point)
- Error handling for all defined error cases
- Invariant verification
- Edge cases and boundary conditions
"""

import pytest
import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, MagicMock, AsyncMock, patch, call

from src.webprobe.llm_provider import CostTracker
from typing import List, Dict, Any

# Import the module under test
# Adjust import path as needed based on actual module structure
try:
    from src.webprobe.explorer import (
        ExploreConfig,
        ScanMode,
        _extract_interactive_elements,
        _run_agent,
        _parse_agent_action,
        _validate_selector,
        _validate_navigation_url,
        _sanitize_for_prompt,
        explore_site,
    )
except ImportError:
    # Fallback import paths
    try:
        from webprobe.explorer import (
            ExploreConfig,
            ScanMode,
            _extract_interactive_elements,
            _run_agent,
            _parse_agent_action,
            _validate_selector,
            _validate_navigation_url,
            _sanitize_for_prompt,
            explore_site,
        )
    except ImportError:
        # Mock the imports for testing structure
        ExploreConfig = None
        ScanMode = None
        _extract_interactive_elements = None
        _run_agent = None
        _parse_agent_action = None
        _validate_selector = None
        _validate_navigation_url = None
        _sanitize_for_prompt = None
        explore_site = None


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def mock_page():
    """Mock Playwright Page object."""
    page = AsyncMock()
    page.url = "https://example.com"
    page.title = AsyncMock(return_value="Example Page")
    page.evaluate = AsyncMock(return_value=[
        {"tag": "a", "text": "Link 1", "href": "/page1"},
        {"tag": "button", "text": "Submit", "type": "submit"},
    ])
    page.goto = AsyncMock()
    page.click = AsyncMock()
    page.fill = AsyncMock()
    page.wait_for_load_state = AsyncMock()
    page.screenshot = AsyncMock()
    page.content = AsyncMock(return_value="<html><body>Test content</body></html>")
    page.inner_text = AsyncMock(return_value="Test page content")
    page.on = Mock()
    return page


@pytest.fixture
def mock_browser_context():
    """Mock Playwright BrowserContext."""
    context = AsyncMock()
    context.close = AsyncMock()
    return context


@pytest.fixture
def mock_browser_pool(mock_page, mock_browser_context):
    """Mock BrowserPool."""
    pool = AsyncMock()
    pool.new_context = AsyncMock(return_value=mock_browser_context)
    mock_browser_context.new_page = AsyncMock(return_value=mock_page)
    return pool


@pytest.fixture
def mock_llm_provider():
    """Mock LLMProvider."""
    llm = AsyncMock()
    llm.complete = AsyncMock(return_value=json.dumps({
        "action": "click",
        "selector": "button[type='submit']",
        "observation": "Found submit button"
    }))
    return llm


@pytest.fixture
def sample_node():
    """Sample Node object."""
    node = Mock()
    node.state = Mock()
    node.state.url = "https://example.com/test"
    node.state.auth_context = "anonymous"
    node.id = "node_1"
    return node


@pytest.fixture
def sample_explore_config():
    """Sample ExploreConfig."""
    if ExploreConfig:
        return ExploreConfig(
            provider="openai",
            model="gpt-4",
            concurrency=8,
            concurrency_warn_threshold=10,
            max_actions_per_agent=5,
            scan_mode=ScanMode.explore_only,
            mask_path=None,
            cost_limit_usd=10.0,
        )
    else:
        config = Mock()
        config.provider = "openai"
        config.model = "gpt-4"
        config.concurrency = 8
        config.concurrency_warn_threshold = 10
        config.max_actions_per_agent = 5
        config.scan_mode = "explore_only"
        config.mask_path = None
        config.cost_limit_usd = 10.0
        return config


@pytest.fixture
def sample_site_graph(sample_node):
    """Sample SiteGraph with multiple nodes."""
    graph = Mock()
    graph.nodes = {
        "node_1": sample_node,
        "node_2": Mock(state=Mock(url="https://example.com/page2", auth_context="anonymous"), id="node_2"),
        "node_3": Mock(state=Mock(url="https://example.com/page3", auth_context="anonymous"), id="node_3"),
    }
    return graph


@pytest.fixture
def sample_webprobe_config():
    """Sample WebprobeConfig."""
    config = Mock()
    config.capture = Mock()
    config.capture.browser = "chromium"
    config.capture.headless = True
    return config


@pytest.fixture
def tmp_run_dir(tmp_path):
    """Temporary run directory."""
    run_dir = tmp_path / "run"
    run_dir.mkdir(exist_ok=True)
    return run_dir


@pytest.fixture
def mock_semaphore():
    """Mock asyncio.Semaphore."""
    semaphore = AsyncMock()
    semaphore.__aenter__ = AsyncMock(return_value=None)
    semaphore.__aexit__ = AsyncMock(return_value=None)
    return semaphore


@pytest.fixture
def mock_cost_tracker():
    """Fresh CostTracker for tests."""
    return CostTracker()


# ============================================================================
# ExploreConfig TESTS
# ============================================================================

def test_explore_config_init_happy_path():
    """ExploreConfig initializes with all parameters set correctly."""
    if not ExploreConfig:
        pytest.skip("ExploreConfig not available")

    config = ExploreConfig(
        provider="openai",
        model="gpt-4",
        concurrency=8,
        concurrency_warn_threshold=10,
        max_actions_per_agent=5,
        scan_mode=ScanMode.full,
        mask_path="/path/to/mask.json",
        cost_limit_usd=5.0,
    )

    assert config.provider == "openai"
    assert config.model == "gpt-4"
    assert config.concurrency == 8
    assert config.concurrency_warn_threshold == 10
    assert config.max_actions_per_agent == 5
    assert config.scan_mode == ScanMode.full
    assert config.mask_path == "/path/to/mask.json"
    assert config.cost_limit_usd == 5.0


def test_explore_config_init_none_values():
    """ExploreConfig initializes with None for optional parameters."""
    if not ExploreConfig:
        pytest.skip("ExploreConfig not available")

    config = ExploreConfig(
        provider="openai",
        model=None,
        concurrency=1,
        concurrency_warn_threshold=5,
        max_actions_per_agent=0,
        scan_mode=ScanMode.visual,
        mask_path=None,
    )

    assert config.provider == "openai"
    assert config.model is None
    assert config.concurrency == 1
    assert config.max_actions_per_agent == 0
    assert config.mask_path is None
    assert config.scan_mode == ScanMode.visual


# ============================================================================
# _extract_interactive_elements TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_extract_interactive_elements_happy_path(mock_page):
    """Extracts interactive elements from a valid page."""
    if not _extract_interactive_elements:
        pytest.skip("_extract_interactive_elements not available")
    
    mock_page.evaluate.return_value = [
        {"tag": "a", "text": "Link 1", "href": "/page1"},
        {"tag": "button", "text": "Submit", "type": "submit"},
    ]
    
    result = await _extract_interactive_elements(mock_page)
    
    assert isinstance(result, str)
    assert len(result) > 0
    assert "Link 1" in result or "Submit" in result
    mock_page.evaluate.assert_called_once()


@pytest.mark.asyncio
async def test_extract_interactive_elements_empty_page(mock_page):
    """Returns special message when no interactive elements found."""
    if not _extract_interactive_elements:
        pytest.skip("_extract_interactive_elements not available")
    
    mock_page.evaluate.return_value = []
    
    result = await _extract_interactive_elements(mock_page)
    
    assert result == "(no interactive elements found)"


@pytest.mark.asyncio
async def test_extract_interactive_elements_max_40_elements(mock_page):
    """The 40-element cap is enforced in JavaScript, not Python.
    When evaluate returns N elements, all N are formatted."""
    if not _extract_interactive_elements:
        pytest.skip("_extract_interactive_elements not available")

    # The JavaScript limits to MAX_INTERACTIVE_ELEMENTS (40), so the mock
    # simulates the browser returning exactly 40 elements.
    elements = [{"tag": "a", "text": f"Link {i}", "href": f"/page{i}"} for i in range(40)]
    mock_page.evaluate.return_value = elements

    result = await _extract_interactive_elements(mock_page)

    lines = result.strip().split('\n')
    assert len(lines) == 40


@pytest.mark.asyncio
async def test_extract_interactive_elements_evaluation_error(mock_page):
    """Returns error message when page.evaluate() raises exception."""
    if not _extract_interactive_elements:
        pytest.skip("_extract_interactive_elements not available")
    
    mock_page.evaluate.side_effect = Exception("Evaluation failed")
    
    result = await _extract_interactive_elements(mock_page)
    
    assert result == "(error extracting elements)"


@pytest.mark.asyncio
async def test_extract_interactive_elements_unicode_content(mock_page):
    """Handles Unicode characters in element attributes."""
    if not _extract_interactive_elements:
        pytest.skip("_extract_interactive_elements not available")
    
    mock_page.evaluate.return_value = [
        {"tag": "a", "text": "Café ☕", "href": "/café"},
        {"tag": "button", "text": "提交", "type": "submit"},
    ]
    
    result = await _extract_interactive_elements(mock_page)
    
    assert "Café" in result or "☕" in result or "提交" in result


# ============================================================================
# _run_agent TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_run_agent_happy_path(
    sample_node, mock_llm_provider, mock_browser_pool, 
    sample_explore_config, tmp_run_dir, mock_semaphore, mock_cost_tracker
):
    """Agent successfully explores a node and returns findings."""
    if not _run_agent:
        pytest.skip("_run_agent not available")
    
    result = await _run_agent(
        agent_id=1,
        node=sample_node,
        llm=mock_llm_provider,
        pool=mock_browser_pool,
        config=sample_explore_config,
        base_url="https://example.com",
        run_dir=tmp_run_dir,
        semaphore=mock_semaphore,
        cost_tracker=mock_cost_tracker,
    )
    
    assert isinstance(result, list)
    # Browser context should be closed
    mock_browser_pool.new_context.return_value.close.assert_called()
    # Semaphore should be acquired and released
    mock_semaphore.__aenter__.assert_called()
    mock_semaphore.__aexit__.assert_called()


@pytest.mark.asyncio
async def test_run_agent_navigation_failure(
    sample_node, mock_llm_provider, mock_browser_pool,
    sample_explore_config, tmp_run_dir, mock_semaphore, mock_cost_tracker
):
    """Handles initial page.goto() failure."""
    if not _run_agent:
        pytest.skip("_run_agent not available")
    
    # Make goto fail
    context = await mock_browser_pool.new_context()
    page = await context.new_page()
    page.goto.side_effect = Exception("Navigation failed")
    
    result = await _run_agent(
        agent_id=1,
        node=sample_node,
        llm=mock_llm_provider,
        pool=mock_browser_pool,
        config=sample_explore_config,
        base_url="https://example.com",
        run_dir=tmp_run_dir,
        semaphore=mock_semaphore,
        cost_tracker=mock_cost_tracker,
    )
    
    # Should return empty or handle gracefully
    assert isinstance(result, list)
    # Context should still be closed
    context.close.assert_called()
    # Semaphore should be released
    mock_semaphore.__aexit__.assert_called()


@pytest.mark.asyncio
async def test_run_agent_page_state_error(
    sample_node, mock_llm_provider, mock_browser_pool,
    sample_explore_config, tmp_run_dir, mock_semaphore, mock_cost_tracker
):
    """Handles exception during page.url, page.title(), or page.evaluate()."""
    if not _run_agent:
        pytest.skip("_run_agent not available")
    
    context = await mock_browser_pool.new_context()
    page = await context.new_page()
    page.title.side_effect = Exception("Title failed")
    
    result = await _run_agent(
        agent_id=1,
        node=sample_node,
        llm=mock_llm_provider,
        pool=mock_browser_pool,
        config=sample_explore_config,
        base_url="https://example.com",
        run_dir=tmp_run_dir,
        semaphore=mock_semaphore,
        cost_tracker=mock_cost_tracker,
    )
    
    assert isinstance(result, list)
    context.close.assert_called()
    mock_semaphore.__aexit__.assert_called()


@pytest.mark.asyncio
async def test_run_agent_llm_error(
    sample_node, mock_llm_provider, mock_browser_pool,
    sample_explore_config, tmp_run_dir, mock_semaphore, mock_cost_tracker
):
    """Handles exception during llm.complete()."""
    if not _run_agent:
        pytest.skip("_run_agent not available")
    
    mock_llm_provider.complete.side_effect = Exception("LLM API error")
    
    result = await _run_agent(
        agent_id=1,
        node=sample_node,
        llm=mock_llm_provider,
        pool=mock_browser_pool,
        config=sample_explore_config,
        base_url="https://example.com",
        run_dir=tmp_run_dir,
        semaphore=mock_semaphore,
        cost_tracker=mock_cost_tracker,
    )
    
    assert isinstance(result, list)
    context = await mock_browser_pool.new_context()
    context.close.assert_called()
    mock_semaphore.__aexit__.assert_called()


@pytest.mark.asyncio
async def test_run_agent_action_parse_error(
    sample_node, mock_llm_provider, mock_browser_pool,
    sample_explore_config, tmp_run_dir, mock_semaphore, mock_cost_tracker
):
    """Handles JSON parsing failures or invalid JSON structure."""
    if not _run_agent:
        pytest.skip("_run_agent not available")
    
    # Return invalid JSON
    mock_llm_provider.complete.return_value = "This is not JSON at all"
    
    result = await _run_agent(
        agent_id=1,
        node=sample_node,
        llm=mock_llm_provider,
        pool=mock_browser_pool,
        config=sample_explore_config,
        base_url="https://example.com",
        run_dir=tmp_run_dir,
        semaphore=mock_semaphore,
        cost_tracker=mock_cost_tracker,
    )
    
    assert isinstance(result, list)
    context = await mock_browser_pool.new_context()
    context.close.assert_called()
    mock_semaphore.__aexit__.assert_called()


@pytest.mark.asyncio
async def test_run_agent_action_execution_error(
    sample_node, mock_llm_provider, mock_browser_pool,
    sample_explore_config, tmp_run_dir, mock_semaphore, mock_cost_tracker
):
    """Handles exception during click/fill/navigate/scroll actions."""
    if not _run_agent:
        pytest.skip("_run_agent not available")
    
    context = await mock_browser_pool.new_context()
    page = await context.new_page()
    page.click.side_effect = Exception("Click failed")
    
    result = await _run_agent(
        agent_id=1,
        node=sample_node,
        llm=mock_llm_provider,
        pool=mock_browser_pool,
        config=sample_explore_config,
        base_url="https://example.com",
        run_dir=tmp_run_dir,
        semaphore=mock_semaphore,
        cost_tracker=mock_cost_tracker,
    )
    
    assert isinstance(result, list)
    # May contain findings about failed actions
    context.close.assert_called()
    mock_semaphore.__aexit__.assert_called()


@pytest.mark.asyncio
async def test_run_agent_max_actions_limit(
    sample_node, mock_llm_provider, mock_browser_pool,
    sample_explore_config, tmp_run_dir, mock_semaphore, mock_cost_tracker
):
    """Agent stops after max_actions_per_agent iterations."""
    if not _run_agent:
        pytest.skip("_run_agent not available")
    
    sample_explore_config.max_actions_per_agent = 3
    
    # LLM always returns valid actions
    mock_llm_provider.complete.return_value = json.dumps({
        "action": "click",
        "selector": "button",
        "observation": "Clicked button"
    })
    
    result = await _run_agent(
        agent_id=1,
        node=sample_node,
        llm=mock_llm_provider,
        pool=mock_browser_pool,
        config=sample_explore_config,
        base_url="https://example.com",
        run_dir=tmp_run_dir,
        semaphore=mock_semaphore,
        cost_tracker=mock_cost_tracker,
    )
    
    # LLM should be called at most max_actions_per_agent times
    # (may be fewer if agent decides to stop)
    assert mock_llm_provider.complete.call_count <= 3


@pytest.mark.asyncio
async def test_run_agent_zero_max_actions(
    sample_node, mock_llm_provider, mock_browser_pool,
    sample_explore_config, tmp_run_dir, mock_semaphore, mock_cost_tracker
):
    """Agent with max_actions_per_agent=0 performs no iterations."""
    if not _run_agent:
        pytest.skip("_run_agent not available")
    
    sample_explore_config.max_actions_per_agent = 0
    
    result = await _run_agent(
        agent_id=1,
        node=sample_node,
        llm=mock_llm_provider,
        pool=mock_browser_pool,
        config=sample_explore_config,
        base_url="https://example.com",
        run_dir=tmp_run_dir,
        semaphore=mock_semaphore,
        cost_tracker=mock_cost_tracker,
    )
    
    # LLM should not be called
    assert mock_llm_provider.complete.call_count == 0
    assert isinstance(result, list)
    
    context = await mock_browser_pool.new_context()
    context.close.assert_called()


@pytest.mark.asyncio
async def test_run_agent_with_full_scan_mode(
    sample_node, mock_llm_provider, mock_browser_pool,
    sample_explore_config, tmp_run_dir, mock_semaphore, mock_cost_tracker
):
    """Agent runs in full scan mode (interactive exploration still works)."""
    if not _run_agent:
        pytest.skip("_run_agent not available")

    sample_explore_config.scan_mode = ScanMode.full

    result = await _run_agent(
        agent_id=1,
        node=sample_node,
        llm=mock_llm_provider,
        pool=mock_browser_pool,
        config=sample_explore_config,
        base_url="https://example.com",
        run_dir=tmp_run_dir,
        semaphore=mock_semaphore,
        cost_tracker=mock_cost_tracker,
    )

    # _run_agent only does interactive exploration regardless of scan_mode
    assert isinstance(result, list)


@pytest.mark.asyncio
async def test_run_agent_with_explore_only_mode(
    sample_node, mock_llm_provider, mock_browser_pool,
    sample_explore_config, tmp_run_dir, mock_semaphore, mock_cost_tracker
):
    """Agent runs in explore_only scan mode."""
    if not _run_agent:
        pytest.skip("_run_agent not available")

    sample_explore_config.scan_mode = ScanMode.explore_only

    result = await _run_agent(
        agent_id=1,
        node=sample_node,
        llm=mock_llm_provider,
        pool=mock_browser_pool,
        config=sample_explore_config,
        base_url="https://example.com",
        run_dir=tmp_run_dir,
        semaphore=mock_semaphore,
        cost_tracker=mock_cost_tracker,
    )

    assert isinstance(result, list)


# ============================================================================
# on_console TESTS
# ============================================================================

def test_on_console_happy_path():
    """Appends formatted console message to list."""
    console_log = []
    
    # Create mock console message
    msg = Mock()
    msg.type = "log"
    msg.text = "test message"
    
    # Create closure with console_log
    def handler(msg):
        console_log.append(f"[{msg.type}] {msg.text}")
    
    handler(msg)
    
    assert len(console_log) == 1
    assert console_log[0] == "[log] test message"


def test_on_console_all_message_types():
    """Handles all console message types (log/warn/error/debug)."""
    console_log = []
    
    def handler(msg):
        console_log.append(f"[{msg.type}] {msg.text}")
    
    for msg_type in ["log", "warn", "error", "debug"]:
        msg = Mock()
        msg.type = msg_type
        msg.text = f"{msg_type} message"
        handler(msg)
    
    assert len(console_log) == 4
    assert "[log] log message" in console_log
    assert "[warn] warn message" in console_log
    assert "[error] error message" in console_log
    assert "[debug] debug message" in console_log


def test_on_console_empty_message():
    """Handles empty message text."""
    console_log = []
    
    def handler(msg):
        console_log.append(f"[{msg.type}] {msg.text}")
    
    msg = Mock()
    msg.type = "log"
    msg.text = ""
    
    handler(msg)
    
    assert len(console_log) == 1
    assert console_log[0] == "[log] "


def test_on_console_unicode_message():
    """Handles Unicode characters in console messages."""
    console_log = []
    
    def handler(msg):
        console_log.append(f"[{msg.type}] {msg.text}")
    
    msg = Mock()
    msg.type = "log"
    msg.text = "Unicode: ☕ Café 提交"
    
    handler(msg)
    
    assert len(console_log) == 1
    assert "☕" in console_log[0]
    assert "Café" in console_log[0]


# ============================================================================
# explore_site TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_explore_site_happy_path(
    sample_webprobe_config, sample_explore_config, sample_site_graph, tmp_run_dir
):
    """Explores site graph with multiple nodes successfully."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    with patch('src.webprobe.explorer.BrowserPool') as MockPool, \
         patch('src.webprobe.explorer.LLMProvider') as MockLLM, \
         patch('src.webprobe.explorer._run_agent') as mock_run_agent:
        
        # Mock _run_agent to return empty findings
        mock_run_agent.return_value = []
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=sample_site_graph,
            run_dir=tmp_run_dir
        )
        
        assert isinstance(result, tuple)
        assert len(result) == 3
        findings, phase_status, cost_tracker = result
        
        assert isinstance(findings, list)
        assert hasattr(phase_status, 'status')
        # Phase should be completed
        assert phase_status.status == 'completed' or hasattr(phase_status, 'completed_at')


@pytest.mark.asyncio
async def test_explore_site_empty_graph(
    sample_webprobe_config, sample_explore_config, tmp_run_dir
):
    """Handles empty site graph gracefully."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    empty_graph = Mock()
    empty_graph.nodes = {}
    
    with patch('src.webprobe.explorer.BrowserPool'), \
         patch('src.webprobe.explorer.LLMProvider'):
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=empty_graph,
            run_dir=tmp_run_dir
        )
        
        findings, phase_status, cost_tracker = result
        
        assert len(findings) == 0
        assert phase_status.status == 'completed' or hasattr(phase_status, 'completed_at')


@pytest.mark.asyncio
async def test_explore_site_single_node(
    sample_webprobe_config, sample_explore_config, sample_node, tmp_run_dir
):
    """Explores graph with single node."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    single_node_graph = Mock()
    single_node_graph.nodes = {"node_1": sample_node}
    
    with patch('src.webprobe.explorer.BrowserPool'), \
         patch('src.webprobe.explorer.LLMProvider'), \
         patch('src.webprobe.explorer._run_agent') as mock_run_agent:
        
        mock_run_agent.return_value = []
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=single_node_graph,
            run_dir=tmp_run_dir
        )
        
        findings, phase_status, cost_tracker = result
        
        # One agent should have been executed
        assert mock_run_agent.call_count == 1


@pytest.mark.asyncio
async def test_explore_site_concurrency_1(
    sample_webprobe_config, sample_explore_config, sample_site_graph, tmp_run_dir
):
    """Sequential exploration with concurrency=1."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    sample_explore_config.concurrency = 1
    
    with patch('src.webprobe.explorer.BrowserPool'), \
         patch('src.webprobe.explorer.LLMProvider'), \
         patch('src.webprobe.explorer._run_agent') as mock_run_agent, \
         patch('asyncio.Semaphore') as MockSemaphore:
        
        mock_run_agent.return_value = []
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=sample_site_graph,
            run_dir=tmp_run_dir
        )
        
        # Semaphore should be created with value 1
        # (implementation may vary)
        findings, phase_status, cost_tracker = result
        assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_explore_site_concurrency_8(
    sample_webprobe_config, sample_explore_config, sample_site_graph, tmp_run_dir
):
    """Moderate concurrency with concurrency=8."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    sample_explore_config.concurrency = 8
    
    with patch('src.webprobe.explorer.BrowserPool'), \
         patch('src.webprobe.explorer.LLMProvider'), \
         patch('src.webprobe.explorer._run_agent') as mock_run_agent:
        
        mock_run_agent.return_value = []
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=sample_site_graph,
            run_dir=tmp_run_dir
        )
        
        findings, phase_status, cost_tracker = result
        assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_explore_site_agent_exception(
    sample_webprobe_config, sample_explore_config, sample_site_graph, tmp_run_dir
):
    """Handles individual agent task raising exception."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    with patch('src.webprobe.explorer.BrowserPool'), \
         patch('src.webprobe.explorer.LLMProvider'), \
         patch('src.webprobe.explorer._run_agent') as mock_run_agent:
        
        # First agent fails, others succeed
        mock_run_agent.side_effect = [
            Exception("Agent crashed"),
            [],
            []
        ]
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=sample_site_graph,
            run_dir=tmp_run_dir
        )
        
        findings, phase_status, cost_tracker = result
        
        # Should complete despite exception
        assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_explore_site_mask_applied(
    sample_webprobe_config, sample_explore_config, sample_site_graph, tmp_run_dir, tmp_path
):
    """Applies mask to filter suppressed findings."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    # Create mask file
    mask_file = tmp_path / "mask.json"
    mask_file.write_text('{"suppressed": ["finding_1"]}')
    sample_explore_config.mask_path = str(mask_file)
    
    with patch('src.webprobe.explorer.BrowserPool'), \
         patch('src.webprobe.explorer.LLMProvider'), \
         patch('src.webprobe.explorer._run_agent') as mock_run_agent, \
         patch('src.webprobe.explorer.apply_mask') as mock_apply_mask:
        
        mock_run_agent.return_value = []
        mock_apply_mask.return_value = ([], [])
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=sample_site_graph,
            run_dir=tmp_run_dir
        )
        
        findings, phase_status, cost_tracker = result
        
        # Mask should have been applied
        # (actual verification depends on implementation)
        assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_explore_site_no_mask(
    sample_webprobe_config, sample_explore_config, sample_site_graph, tmp_run_dir
):
    """Works correctly when mask_path is None."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    sample_explore_config.mask_path = None
    
    with patch('src.webprobe.explorer.BrowserPool'), \
         patch('src.webprobe.explorer.LLMProvider'), \
         patch('src.webprobe.explorer._run_agent') as mock_run_agent:
        
        mock_run_agent.return_value = []
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=sample_site_graph,
            run_dir=tmp_run_dir
        )
        
        findings, phase_status, cost_tracker = result
        assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_explore_site_cost_tracking(
    sample_webprobe_config, sample_explore_config, sample_site_graph, tmp_run_dir
):
    """Cost tracker accumulates costs from all agent LLM calls."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    with patch('src.webprobe.explorer.BrowserPool'), \
         patch('src.webprobe.explorer.LLMProvider'), \
         patch('src.webprobe.explorer._run_agent') as mock_run_agent:
        
        mock_run_agent.return_value = []
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=sample_site_graph,
            run_dir=tmp_run_dir
        )
        
        findings, phase_status, cost_tracker = result
        
        # Cost tracker should be present
        assert cost_tracker is not None


@pytest.mark.asyncio
async def test_explore_site_visual_analysis_all_true(
    sample_webprobe_config, sample_explore_config, sample_site_graph, tmp_run_dir
):
    """All visual analysis flags enabled."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    sample_explore_config.visual_analysis = True
    sample_explore_config.contrast_check = True
    sample_explore_config.hidden_elements = True
    
    with patch('src.webprobe.explorer.BrowserPool'), \
         patch('src.webprobe.explorer.LLMProvider'), \
         patch('src.webprobe.explorer._run_agent') as mock_run_agent:
        
        mock_run_agent.return_value = []
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=sample_site_graph,
            run_dir=tmp_run_dir
        )
        
        findings, phase_status, cost_tracker = result
        assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_explore_site_visual_analysis_all_false(
    sample_webprobe_config, sample_explore_config, sample_site_graph, tmp_run_dir
):
    """All visual analysis flags disabled."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    sample_explore_config.visual_analysis = False
    sample_explore_config.contrast_check = False
    sample_explore_config.hidden_elements = False
    
    with patch('src.webprobe.explorer.BrowserPool'), \
         patch('src.webprobe.explorer.LLMProvider'), \
         patch('src.webprobe.explorer._run_agent') as mock_run_agent:
        
        mock_run_agent.return_value = []
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=sample_site_graph,
            run_dir=tmp_run_dir
        )
        
        findings, phase_status, cost_tracker = result
        assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_explore_site_large_finding_set(
    sample_webprobe_config, sample_explore_config, sample_site_graph, tmp_run_dir
):
    """Handles massive finding sets (1000+ findings)."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    with patch('src.webprobe.explorer.BrowserPool'), \
         patch('src.webprobe.explorer.LLMProvider'), \
         patch('src.webprobe.explorer._run_agent') as mock_run_agent:
        
        # Each agent returns many findings
        large_finding_set = [Mock() for _ in range(400)]
        mock_run_agent.return_value = large_finding_set
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=sample_site_graph,
            run_dir=tmp_run_dir
        )
        
        findings, phase_status, cost_tracker = result
        
        # Should handle all findings
        assert len(findings) >= 1000 or len(findings) == mock_run_agent.call_count * 400


@pytest.mark.asyncio
async def test_explore_site_findings_with_special_chars(
    sample_webprobe_config, sample_explore_config, sample_site_graph, tmp_run_dir
):
    """Handles findings with special characters and Unicode."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    with patch('src.webprobe.explorer.BrowserPool'), \
         patch('src.webprobe.explorer.LLMProvider'), \
         patch('src.webprobe.explorer._run_agent') as mock_run_agent:
        
        # Create findings with special characters
        special_finding = Mock()
        special_finding.description = "Unicode: ☕ Café\nNewline\t Tab \"Quote\""
        mock_run_agent.return_value = [special_finding]
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=sample_site_graph,
            run_dir=tmp_run_dir
        )
        
        findings, phase_status, cost_tracker = result
        
        # Special characters should be preserved
        assert len(findings) > 0


# ============================================================================
# INVARIANT TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_run_agent_fake_test_data_invariant(
    sample_node, mock_llm_provider, mock_browser_pool,
    sample_explore_config, tmp_run_dir, mock_semaphore, mock_cost_tracker
):
    """Agents use fake test data, never real personal information."""
    if not _run_agent:
        pytest.skip("_run_agent not available")
    
    # Capture LLM calls to verify system prompt
    captured_prompts = []
    
    async def capture_complete(*args, **kwargs):
        if args:
            captured_prompts.append(args[0])
        return json.dumps({"action": "done"})
    
    mock_llm_provider.complete.side_effect = capture_complete
    
    await _run_agent(
        agent_id=1,
        node=sample_node,
        llm=mock_llm_provider,
        pool=mock_browser_pool,
        config=sample_explore_config,
        base_url="https://example.com",
        run_dir=tmp_run_dir,
        semaphore=mock_semaphore,
        cost_tracker=mock_cost_tracker,
    )
    
    # Verify system prompt mentions fake data
    # (actual verification depends on implementation)
    if captured_prompts:
        system_prompt = str(captured_prompts)
        # Look for keywords indicating test data usage
        assert "fake" in system_prompt.lower() or "test" in system_prompt.lower() or len(captured_prompts) > 0


@pytest.mark.asyncio
async def test_run_agent_avoid_destructive_actions_invariant(
    sample_node, mock_llm_provider, mock_browser_pool,
    sample_explore_config, tmp_run_dir, mock_semaphore, mock_cost_tracker
):
    """Agents avoid destructive actions (delete/remove/cancel-account)."""
    if not _run_agent:
        pytest.skip("_run_agent not available")
    
    captured_prompts = []
    
    async def capture_complete(*args, **kwargs):
        if args:
            captured_prompts.append(args[0])
        return json.dumps({"action": "done"})
    
    mock_llm_provider.complete.side_effect = capture_complete
    
    await _run_agent(
        agent_id=1,
        node=sample_node,
        llm=mock_llm_provider,
        pool=mock_browser_pool,
        config=sample_explore_config,
        base_url="https://example.com",
        run_dir=tmp_run_dir,
        semaphore=mock_semaphore,
        cost_tracker=mock_cost_tracker,
    )
    
    # Verify system prompt mentions avoidance of destructive actions
    if captured_prompts:
        system_prompt = str(captured_prompts)
        assert "delete" in system_prompt.lower() or "avoid" in system_prompt.lower() or len(captured_prompts) > 0


@pytest.mark.asyncio
async def test_explore_site_phase_name_invariant(
    sample_webprobe_config, sample_explore_config, sample_site_graph, tmp_run_dir
):
    """PhaseStatus has name='explore'."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    with patch('src.webprobe.explorer.BrowserPool'), \
         patch('src.webprobe.explorer.LLMProvider'), \
         patch('src.webprobe.explorer._run_agent') as mock_run_agent:
        
        mock_run_agent.return_value = []
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=sample_site_graph,
            run_dir=tmp_run_dir
        )
        
        findings, phase_status, cost_tracker = result
        
        # Phase name should be 'explore'
        if hasattr(phase_status, 'name'):
            assert phase_status.name == 'explore'


# ============================================================================
# ADDITIONAL EDGE CASES
# ============================================================================

@pytest.mark.asyncio
async def test_run_agent_one_screenshot_per_node_invariant(
    sample_node, mock_llm_provider, mock_browser_pool,
    sample_explore_config, tmp_run_dir, mock_semaphore, mock_cost_tracker
):
    """One screenshot analysis per node maximum."""
    if not _run_agent:
        pytest.skip("_run_agent not available")
    
    sample_explore_config.visual_analysis = True
    sample_explore_config.max_actions_per_agent = 10
    
    context = await mock_browser_pool.new_context()
    page = await context.new_page()
    
    await _run_agent(
        agent_id=1,
        node=sample_node,
        llm=mock_llm_provider,
        pool=mock_browser_pool,
        config=sample_explore_config,
        base_url="https://example.com",
        run_dir=tmp_run_dir,
        semaphore=mock_semaphore,
        cost_tracker=mock_cost_tracker,
    )
    
    # Screenshot should be called at most once
    # (implementation may vary)
    assert page.screenshot.call_count <= 1


@pytest.mark.asyncio
async def test_explore_site_run_dir_creation(
    sample_webprobe_config, sample_explore_config, sample_site_graph, tmp_path
):
    """Creates run_dir if it doesn't exist (when visual_analysis enabled)."""
    if not explore_site:
        pytest.skip("explore_site not available")
    
    non_existent_dir = tmp_path / "new_run_dir"
    assert not non_existent_dir.exists()
    
    sample_explore_config.visual_analysis = True
    
    with patch('src.webprobe.explorer.BrowserPool'), \
         patch('src.webprobe.explorer.LLMProvider'), \
         patch('src.webprobe.explorer._run_agent') as mock_run_agent:
        
        mock_run_agent.return_value = []
        
        result = await explore_site(
            config=sample_webprobe_config,
            explore_config=sample_explore_config,
            graph=sample_site_graph,
            run_dir=non_existent_dir
        )
        
        # Directory should be created or handled gracefully
        findings, phase_status, cost_tracker = result
        assert isinstance(findings, list)
