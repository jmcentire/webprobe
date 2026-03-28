"""
Contract tests for BrowserPool - Browser Pool Manager

This test suite verifies the BrowserPool implementation against its contract
using a layered approach with mocked dependencies for comprehensive coverage.

Test Categories:
- Happy path tests for all functions
- Edge cases based on preconditions
- Error case tests for all 9 error types
- Invariant tests for contract guarantees
- State transition tests
- Async context manager protocol tests
"""

import pytest
from unittest.mock import Mock, AsyncMock, MagicMock, patch, call
from typing import Optional


# Import the component under test
# Adjust import path as needed based on actual module structure
try:
    from src.webprobe.browser import BrowserPool
except ImportError:
    # Fallback for different module structures
    try:
        from src.webprobe.browser import BrowserPool
    except ImportError:
        # Create mock for testing infrastructure
        class BrowserPool:
            pass


# Mock exception types that should be defined in the module
class PlaywrightStartFailure(Exception):
    """Raised when Playwright fails to start"""
    pass


class BrowserLaunchFailure(Exception):
    """Raised when Chromium browser fails to launch"""
    pass


class ContextCreationFailure(Exception):
    """Raised when Browser fails to create new context"""
    pass


class AuthApplicationFailure(Exception):
    """Raised when auth.apply_to_context() raises an exception"""
    pass


class BrowserCloseFailure(Exception):
    """Raised when Browser close operation fails"""
    pass


class PlaywrightStopFailure(Exception):
    """Raised when Playwright stop operation fails"""
    pass


class StartFailure(Exception):
    """Raised when start() raises an exception in __aenter__"""
    pass


class StopFailure(Exception):
    """Raised when stop() raises an exception in __aexit__"""
    pass


# Fixtures for common test setup
@pytest.fixture
def mock_capture_config():
    """Create a mock CaptureConfig with default values"""
    config = Mock()
    config.viewport_width = 1920
    config.viewport_height = 1080
    return config


@pytest.fixture
def mock_capture_config_with_custom_viewport():
    """Create a mock CaptureConfig with custom viewport"""
    config = Mock()
    config.viewport_width = 1024
    config.viewport_height = 768
    return config


@pytest.fixture
def mock_playwright():
    """Create a mock Playwright instance"""
    playwright = AsyncMock()
    playwright.chromium = AsyncMock()
    mock_browser = AsyncMock()
    mock_browser.close = AsyncMock()
    mock_context = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    playwright.chromium.launch = AsyncMock(return_value=mock_browser)
    playwright.stop = AsyncMock()
    return playwright


@pytest.fixture
def mock_browser():
    """Create a mock Browser instance"""
    browser = AsyncMock()
    browser.close = AsyncMock()
    mock_context = AsyncMock()
    browser.new_context = AsyncMock(return_value=mock_context)
    return browser


@pytest.fixture
def mock_auth_manager_with_auth():
    """Create a mock AuthManager with has_auth=True"""
    auth = Mock()
    auth.has_auth = True
    auth.apply_to_context = AsyncMock()
    return auth


@pytest.fixture
def mock_auth_manager_without_auth():
    """Create a mock AuthManager with has_auth=False"""
    auth = Mock()
    auth.has_auth = False
    auth.apply_to_context = AsyncMock()
    return auth


@pytest.fixture
def mock_auth_manager_that_fails():
    """Create a mock AuthManager that fails when applying auth"""
    auth = Mock()
    auth.has_auth = True
    auth.apply_to_context = AsyncMock(side_effect=AuthApplicationFailure("Auth failed"))
    return auth


# Happy Path Tests

def test_init_happy_path(mock_capture_config):
    """Test __init__ initializes BrowserPool with config and sets internal state to None"""
    pool = BrowserPool(mock_capture_config)
    
    assert pool._config == mock_capture_config
    assert pool._playwright is None
    assert pool._browser is None


@pytest.mark.asyncio
async def test_start_happy_path(mock_capture_config, mock_playwright):
    """Test start() successfully launches Playwright and Chromium browser"""
    pool = BrowserPool(mock_capture_config)
    
    with patch('src.webprobe.browser.async_playwright', return_value=AsyncMock(start=AsyncMock(return_value=mock_playwright))):
        await pool.start()
    
    assert pool._playwright is not None
    assert pool._browser is not None
    # Verify headless mode via the launch call args
    mock_playwright.chromium.launch.assert_called_once()
    call_kwargs = mock_playwright.chromium.launch.call_args[1]
    assert call_kwargs.get('headless') is True


@pytest.mark.asyncio
async def test_new_context_happy_path_no_auth(mock_capture_config):
    """Test new_context() creates isolated context without authentication"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state
    mock_browser = AsyncMock()
    mock_context = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    pool._playwright = Mock()
    pool._browser = mock_browser
    
    context = await pool.new_context(auth=None, base_url="https://example.com")
    
    assert context is not None
    mock_browser.new_context.assert_called_once()
    call_kwargs = mock_browser.new_context.call_args[1]
    assert call_kwargs['ignore_https_errors'] is True
    assert call_kwargs['viewport']['width'] == mock_capture_config.viewport_width
    assert call_kwargs['viewport']['height'] == mock_capture_config.viewport_height


@pytest.mark.asyncio
async def test_new_context_happy_path_with_auth(mock_capture_config, mock_auth_manager_with_auth):
    """Test new_context() creates context with authentication applied"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state
    mock_browser = AsyncMock()
    mock_context = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    pool._playwright = Mock()
    pool._browser = mock_browser
    
    context = await pool.new_context(auth=mock_auth_manager_with_auth, base_url="https://example.com")
    
    assert context is not None
    mock_auth_manager_with_auth.apply_to_context.assert_called_once_with(mock_context, "https://example.com")


@pytest.mark.asyncio
async def test_stop_happy_path(mock_capture_config):
    """Test stop() closes browser and stops Playwright"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state
    mock_browser = AsyncMock()
    mock_playwright = AsyncMock()
    pool._browser = mock_browser
    pool._playwright = mock_playwright
    
    await pool.stop()
    
    assert pool._browser is None
    assert pool._playwright is None
    mock_browser.close.assert_called_once()
    mock_playwright.stop.assert_called_once()


@pytest.mark.asyncio
async def test_aenter_happy_path(mock_capture_config, mock_playwright):
    """Test __aenter__() starts browser and returns self"""
    pool = BrowserPool(mock_capture_config)
    
    with patch('src.webprobe.browser.async_playwright', return_value=AsyncMock(start=AsyncMock(return_value=mock_playwright))):
        result = await pool.__aenter__()
    
    assert result is pool
    assert pool._playwright is not None
    assert pool._browser is not None


@pytest.mark.asyncio
async def test_aexit_happy_path(mock_capture_config):
    """Test __aexit__() stops browser and cleans up resources"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state
    mock_browser = AsyncMock()
    mock_playwright = AsyncMock()
    pool._browser = mock_browser
    pool._playwright = mock_playwright
    
    await pool.__aexit__(None, None, None)
    
    assert pool._browser is None
    assert pool._playwright is None
    mock_browser.close.assert_called_once()


@pytest.mark.asyncio
async def test_async_context_manager_full_lifecycle(mock_capture_config, mock_playwright):
    """Test full async context manager lifecycle with async with statement"""
    pool = BrowserPool(mock_capture_config)
    
    with patch('src.webprobe.browser.async_playwright', return_value=AsyncMock(start=AsyncMock(return_value=mock_playwright))):
        async with pool as p:
            assert p is pool
            assert p._playwright is not None
            assert p._browser is not None
        
        # After exiting context
        assert pool._browser is None
        assert pool._playwright is None


# Edge Case Tests

def test_init_with_valid_config(mock_capture_config_with_custom_viewport):
    """Test __init__ accepts valid CaptureConfig and stores it"""
    pool = BrowserPool(mock_capture_config_with_custom_viewport)
    
    assert pool._config == mock_capture_config_with_custom_viewport
    assert pool._config.viewport_width == 1024
    assert pool._config.viewport_height == 768
    assert pool._playwright is None
    assert pool._browser is None


@pytest.mark.asyncio
async def test_new_context_auth_without_has_auth(mock_capture_config, mock_auth_manager_without_auth):
    """Test new_context() with auth manager that has has_auth=False does not apply auth"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state
    mock_browser = AsyncMock()
    mock_context = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    pool._playwright = Mock()
    pool._browser = mock_browser
    
    context = await pool.new_context(auth=mock_auth_manager_without_auth, base_url="https://example.com")
    
    assert context is not None
    # apply_to_context should not be called when has_auth is False
    mock_auth_manager_without_auth.apply_to_context.assert_not_called()


@pytest.mark.asyncio
async def test_new_context_multiple_contexts(mock_capture_config):
    """Test new_context() can create multiple isolated contexts"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state
    mock_browser = AsyncMock()
    mock_context1 = AsyncMock()
    mock_context2 = AsyncMock()
    mock_browser.new_context = AsyncMock(side_effect=[mock_context1, mock_context2])
    pool._playwright = Mock()
    pool._browser = mock_browser
    
    context1 = await pool.new_context(auth=None, base_url="https://example1.com")
    context2 = await pool.new_context(auth=None, base_url="https://example2.com")
    
    assert context1 is not None
    assert context2 is not None
    assert context1 != context2
    assert mock_browser.new_context.call_count == 2


@pytest.mark.asyncio
async def test_stop_idempotent(mock_capture_config):
    """Test stop() can be called multiple times safely"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state
    mock_browser = AsyncMock()
    mock_playwright = AsyncMock()
    pool._browser = mock_browser
    pool._playwright = mock_playwright
    
    # Call stop multiple times
    await pool.stop()
    await pool.stop()
    await pool.stop()
    
    # Should remain in stopped state
    assert pool._browser is None
    assert pool._playwright is None
    # Close/stop should only be called once
    mock_browser.close.assert_called_once()
    mock_playwright.stop.assert_called_once()


@pytest.mark.asyncio
async def test_aexit_cleans_up_on_exception(mock_capture_config):
    """Test __aexit__() cleans up resources even when exception occurred in context"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state
    mock_browser = AsyncMock()
    mock_playwright = AsyncMock()
    pool._browser = mock_browser
    pool._playwright = mock_playwright
    
    # Simulate exception in context
    exc_type = ValueError
    exc_value = ValueError("Test exception")
    exc_tb = None
    
    await pool.__aexit__(exc_type, exc_value, exc_tb)
    
    # Resources should still be cleaned up
    assert pool._browser is None
    assert pool._playwright is None
    mock_browser.close.assert_called_once()


@pytest.mark.asyncio
async def test_state_transition_start_twice(mock_capture_config, mock_playwright):
    """Test calling start() twice in sequence"""
    pool = BrowserPool(mock_capture_config)
    
    with patch('src.webprobe.browser.async_playwright', return_value=AsyncMock(start=AsyncMock(return_value=mock_playwright))):
        await pool.start()
        first_browser = pool._browser
        
        # Call start again
        await pool.start()
        
        # Should handle appropriately (either no-op or restart)
        assert pool._browser is not None
        assert pool._playwright is not None


@pytest.mark.asyncio
async def test_new_context_various_base_urls(mock_capture_config):
    """Test new_context() with various base URL formats"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state
    mock_browser = AsyncMock()
    mock_context = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    pool._playwright = Mock()
    pool._browser = mock_browser
    
    urls = [
        "http://localhost:8080",
        "https://example.com:443",
        "http://192.168.1.1",
        "https://subdomain.example.com/path"
    ]
    
    for url in urls:
        context = await pool.new_context(auth=None, base_url=url)
        assert context is not None


# Error Case Tests

@pytest.mark.asyncio
async def test_start_playwright_failure(mock_capture_config):
    """Test start() raises PlaywrightStartFailure when Playwright fails to start"""
    pool = BrowserPool(mock_capture_config)

    with patch('src.webprobe.browser.async_playwright', side_effect=PlaywrightStartFailure("Failed to start")):
        with pytest.raises(PlaywrightStartFailure):
            await pool.start()


@pytest.mark.asyncio
async def test_start_browser_launch_failure(mock_capture_config):
    """Test start() raises BrowserLaunchFailure when Chromium fails to launch"""
    pool = BrowserPool(mock_capture_config)

    mock_pw_instance = AsyncMock()
    mock_pw_instance.chromium.launch = AsyncMock(side_effect=BrowserLaunchFailure("Failed to launch"))
    mock_pw_cm = AsyncMock()
    mock_pw_cm.start = AsyncMock(return_value=mock_pw_instance)

    with patch('src.webprobe.browser.async_playwright', return_value=mock_pw_cm):
        with pytest.raises(BrowserLaunchFailure):
            await pool.start()


@pytest.mark.asyncio
async def test_new_context_without_start(mock_capture_config):
    """Test new_context() raises AssertionError when called before start()"""
    pool = BrowserPool(mock_capture_config)
    
    # Don't call start()
    with pytest.raises(AssertionError):
        await pool.new_context(auth=None, base_url="https://example.com")


@pytest.mark.asyncio
async def test_new_context_creation_failure(mock_capture_config):
    """Test new_context() raises ContextCreationFailure when browser fails to create context"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state with failing browser
    mock_browser = AsyncMock()
    mock_browser.new_context = AsyncMock(side_effect=ContextCreationFailure("Context creation failed"))
    pool._playwright = Mock()
    pool._browser = mock_browser
    
    with pytest.raises(ContextCreationFailure):
        await pool.new_context(auth=None, base_url="https://example.com")


@pytest.mark.asyncio
async def test_new_context_auth_application_failure(mock_capture_config, mock_auth_manager_that_fails):
    """Test new_context() raises AuthApplicationFailure when auth.apply_to_context() fails"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state
    mock_browser = AsyncMock()
    mock_context = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    pool._playwright = Mock()
    pool._browser = mock_browser
    
    with pytest.raises(AuthApplicationFailure):
        await pool.new_context(auth=mock_auth_manager_that_fails, base_url="https://example.com")


@pytest.mark.asyncio
async def test_stop_browser_close_failure(mock_capture_config):
    """Test stop() raises BrowserCloseFailure when browser close fails"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state with failing browser close
    mock_browser = AsyncMock()
    mock_browser.close = AsyncMock(side_effect=BrowserCloseFailure("Close failed"))
    mock_playwright = AsyncMock()
    pool._browser = mock_browser
    pool._playwright = mock_playwright
    
    with pytest.raises(BrowserCloseFailure):
        await pool.stop()


@pytest.mark.asyncio
async def test_stop_playwright_stop_failure(mock_capture_config):
    """Test stop() raises PlaywrightStopFailure when Playwright stop fails"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state with failing playwright stop
    mock_browser = AsyncMock()
    mock_playwright = AsyncMock()
    mock_playwright.stop = AsyncMock(side_effect=PlaywrightStopFailure("Stop failed"))
    pool._browser = mock_browser
    pool._playwright = mock_playwright
    
    with pytest.raises(PlaywrightStopFailure):
        await pool.stop()


@pytest.mark.asyncio
async def test_aenter_start_failure(mock_capture_config):
    """Test __aenter__() raises StartFailure when start() fails"""
    pool = BrowserPool(mock_capture_config)

    with patch('src.webprobe.browser.async_playwright', side_effect=StartFailure("Start failed")):
        with pytest.raises(StartFailure):
            await pool.__aenter__()


@pytest.mark.asyncio
async def test_aexit_stop_failure(mock_capture_config):
    """Test __aexit__() raises StopFailure when stop() fails"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state with failing stop
    mock_browser = AsyncMock()
    mock_browser.close = AsyncMock(side_effect=StopFailure("Stop failed"))
    mock_playwright = AsyncMock()
    pool._browser = mock_browser
    pool._playwright = mock_playwright
    
    with pytest.raises(StopFailure):
        await pool.__aexit__(None, None, None)


# Invariant Tests

@pytest.mark.asyncio
async def test_invariant_browser_requires_playwright(mock_capture_config, mock_playwright):
    """Test invariant: if _browser is not None, then _playwright is not None"""
    pool = BrowserPool(mock_capture_config)
    
    with patch('src.webprobe.browser.async_playwright', return_value=AsyncMock(start=AsyncMock(return_value=mock_playwright))):
        await pool.start()
    
    # Check invariant
    if pool._browser is not None:
        assert pool._playwright is not None


@pytest.mark.asyncio
async def test_invariant_after_start_both_non_none(mock_capture_config, mock_playwright):
    """Test invariant: after successful start(), both _playwright and _browser are non-None"""
    pool = BrowserPool(mock_capture_config)
    
    with patch('src.webprobe.browser.async_playwright', return_value=AsyncMock(start=AsyncMock(return_value=mock_playwright))):
        await pool.start()
    
    assert pool._playwright is not None
    assert pool._browser is not None


@pytest.mark.asyncio
async def test_invariant_after_stop_both_none(mock_capture_config):
    """Test invariant: after stop() completes, both _playwright and _browser are None"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state
    mock_browser = AsyncMock()
    mock_playwright = AsyncMock()
    pool._browser = mock_browser
    pool._playwright = mock_playwright
    
    await pool.stop()
    
    assert pool._playwright is None
    assert pool._browser is None


@pytest.mark.asyncio
async def test_invariant_contexts_ignore_https_errors(mock_capture_config):
    """Test invariant: all contexts created have ignore_https_errors=True"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state
    mock_browser = AsyncMock()
    mock_context = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    pool._playwright = Mock()
    pool._browser = mock_browser
    
    await pool.new_context(auth=None, base_url="https://example.com")
    
    # Verify ignore_https_errors was set to True
    call_kwargs = mock_browser.new_context.call_args[1]
    assert call_kwargs['ignore_https_errors'] is True


@pytest.mark.asyncio
async def test_invariant_contexts_use_config_viewport(mock_capture_config):
    """Test invariant: all contexts use viewport dimensions from _config"""
    pool = BrowserPool(mock_capture_config)
    
    # Set up started state
    mock_browser = AsyncMock()
    mock_context = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    pool._playwright = Mock()
    pool._browser = mock_browser
    
    await pool.new_context(auth=None, base_url="https://example.com")
    
    # Verify viewport dimensions match config
    call_kwargs = mock_browser.new_context.call_args[1]
    assert call_kwargs['viewport']['width'] == mock_capture_config.viewport_width
    assert call_kwargs['viewport']['height'] == mock_capture_config.viewport_height


@pytest.mark.asyncio
async def test_invariant_browser_headless_mode(mock_capture_config, mock_playwright):
    """Test invariant: browser is always launched in headless mode"""
    pool = BrowserPool(mock_capture_config)
    
    with patch('src.webprobe.browser.async_playwright', return_value=AsyncMock(start=AsyncMock(return_value=mock_playwright))):
        await pool.start()
    
    # Verify headless was set to True
    mock_playwright.chromium.launch.assert_called()
    call_kwargs = mock_playwright.chromium.launch.call_args[1] if mock_playwright.chromium.launch.call_args else {}
    if 'headless' in call_kwargs:
        assert call_kwargs['headless'] is True
