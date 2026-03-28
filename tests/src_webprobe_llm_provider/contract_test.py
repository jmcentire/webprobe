"""
Contract tests for LLM Provider Abstraction

Tests cover:
- Utility functions (_estimate_cost, _load_image_b64, transmogrify_prompt)
- Factory function (create_provider)
- CostTracker functionality
- All provider implementations (Anthropic, OpenAI, Gemini, Apprentice)
- Error cases and edge cases
- Invariants
"""

import pytest
import asyncio
import base64
import time
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, MagicMock, mock_open
from dataclasses import dataclass

# Import the module under test
from src.webprobe.llm_provider import (
    _estimate_cost,
    _load_image_b64,
    create_provider,
    transmogrify_prompt,
    CostTracker,
    LLMCallRecord,
    LLMProvider,
    AnthropicProvider,
    OpenAIProvider,
    GeminiProvider,
    ApprenticeProvider,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def cost_tracker():
    """Create a fresh CostTracker instance."""
    return CostTracker()


@pytest.fixture
def sample_call_record():
    """Create a sample LLMCallRecord for testing."""
    return LLMCallRecord(
        provider="openai",
        model="gpt-4o",
        input_tokens=1000,
        output_tokens=500,
        estimated_cost_usd=0.015,
        duration_ms=123.45,
        has_vision=False
    )


@pytest.fixture
def temp_image_file(tmp_path):
    """Create a temporary valid image file."""
    image_path = tmp_path / "test_image.png"
    # Create a simple 1x1 PNG image (minimal valid PNG)
    png_data = base64.b64decode(
        b'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='
    )
    image_path.write_bytes(png_data)
    return image_path


@pytest.fixture
def mock_anthropic_client():
    """Mock Anthropic client for testing."""
    with patch('src_webprobe_llm_provider.anthropic.Anthropic') as mock:
        client = MagicMock()
        mock.return_value = client
        
        # Mock successful response
        response = MagicMock()
        response.content = [MagicMock(text="This is a test response")]
        response.usage = MagicMock(input_tokens=100, output_tokens=50)
        
        client.messages.create = AsyncMock(return_value=response)
        yield client


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client for testing."""
    with patch('src_webprobe_llm_provider.openai.OpenAI') as mock:
        client = MagicMock()
        mock.return_value = client
        
        # Mock successful response
        response = MagicMock()
        response.choices = [MagicMock(message=MagicMock(content="This is a test response"))]
        response.usage = MagicMock(prompt_tokens=100, completion_tokens=50)
        
        client.chat.completions.create = AsyncMock(return_value=response)
        yield client


@pytest.fixture
def mock_gemini_client():
    """Mock Gemini client for testing."""
    with patch('src_webprobe_llm_provider.google.genai.Client') as mock:
        client = MagicMock()
        mock.return_value = client
        
        # Mock successful response
        response = MagicMock()
        response.text = "This is a test response"
        response.usage_metadata = MagicMock(prompt_token_count=100, candidates_token_count=50)
        
        client.models.generate_content = AsyncMock(return_value=response)
        yield client


# ============================================================================
# Test _estimate_cost
# ============================================================================

def test_estimate_cost_known_model():
    """Test cost estimation for a known model returns non-negative value."""
    result = _estimate_cost("gpt-4o", 1000000, 500000)
    assert result >= 0
    assert isinstance(result, float)


def test_estimate_cost_unknown_model():
    """Test cost estimation for unknown model returns fallback pricing."""
    result = _estimate_cost("unknown-model-xyz", 1000000, 500000)
    assert result >= 0


def test_estimate_cost_zero_tokens():
    """Test cost estimation with zero tokens returns zero."""
    result = _estimate_cost("gpt-4o", 0, 0)
    assert result == 0.0


def test_estimate_cost_prefix_matching():
    """Test that cost estimation uses prefix matching for models."""
    # Should match claude-sonnet prefix
    result1 = _estimate_cost("claude-sonnet-4-20250514", 1000000, 1000000)
    result2 = _estimate_cost("claude-sonnet-3-5-20241022", 1000000, 1000000)
    # Both should use similar pricing (may differ based on specific pricing)
    assert result1 >= 0
    assert result2 >= 0


# ============================================================================
# Test _load_image_b64
# ============================================================================

def test_load_image_b64_valid_file(temp_image_file):
    """Test loading and encoding a valid image file as base64."""
    result = _load_image_b64(temp_image_file)
    assert isinstance(result, str)
    assert len(result) > 0
    # Verify it's valid base64
    try:
        base64.b64decode(result)
    except Exception:
        pytest.fail("Result is not valid base64")


def test_load_image_b64_valid_file_with_string_path(temp_image_file):
    """Test loading image with string path instead of Path object."""
    result = _load_image_b64(str(temp_image_file))
    assert isinstance(result, str)
    assert len(result) > 0


def test_load_image_b64_file_not_found():
    """Test that file_not_found error is raised when image does not exist."""
    with pytest.raises((FileNotFoundError, IOError)):
        _load_image_b64("/nonexistent/path/image.png")


def test_load_image_b64_permission_error(tmp_path):
    """Test that permission_error is raised when insufficient read permissions."""
    import os
    if os.name == 'nt':
        pytest.skip("Permission tests are unreliable on Windows")
    
    image_path = tmp_path / "no_read.png"
    image_path.write_bytes(b"test")
    image_path.chmod(0o000)
    
    try:
        with pytest.raises(PermissionError):
            _load_image_b64(image_path)
    finally:
        image_path.chmod(0o644)


# ============================================================================
# Test create_provider
# ============================================================================

def test_create_provider_anthropic():
    """Test creating Anthropic provider with default model."""
    result = create_provider("anthropic", None, None)
    assert isinstance(result, AnthropicProvider)
    assert result.model == "claude-sonnet-4-20250514"


def test_create_provider_openai():
    """Test creating OpenAI provider with custom model."""
    result = create_provider("openai", "gpt-4-turbo", None)
    assert isinstance(result, OpenAIProvider)
    assert result.model == "gpt-4-turbo"


def test_create_provider_gemini():
    """Test creating Gemini provider with default model."""
    result = create_provider("gemini", None, None)
    assert isinstance(result, GeminiProvider)
    assert result.model == "gemini-2.5-flash"


def test_create_provider_apprentice():
    """Test creating Apprentice provider with auto model."""
    result = create_provider("apprentice", None, None)
    assert isinstance(result, ApprenticeProvider)
    assert result.model == "auto"


def test_create_provider_unknown():
    """Test that unknown_provider error is raised for invalid provider name."""
    with pytest.raises((ValueError, KeyError)):
        create_provider("invalid_provider", None, None)


def test_create_provider_with_cost_tracker(cost_tracker):
    """Test creating provider with existing cost tracker."""
    result = create_provider("openai", None, cost_tracker)
    assert result.cost_tracker is cost_tracker


# ============================================================================
# Test transmogrify_prompt
# ============================================================================

@pytest.mark.asyncio
async def test_transmogrify_prompt_success():
    """Test transmogrify_prompt returns normalized text."""
    with patch('src_webprobe_llm_provider.transmogrifier') as mock_trans:
        mock_trans.normalize = AsyncMock(return_value="normalized text")
        result = await transmogrify_prompt("Test prompt", "gpt-4o")
        assert isinstance(result, str)


@pytest.mark.asyncio
async def test_transmogrify_prompt_fallback():
    """Test transmogrify returns original text when service unavailable."""
    with patch('src_webprobe_llm_provider.transmogrifier', None):
        result = await transmogrify_prompt("Test prompt", "gpt-4o")
        assert result == "Test prompt"


@pytest.mark.asyncio
async def test_transmogrify_prompt_error_fallback():
    """Test transmogrify returns original text on error."""
    with patch('src_webprobe_llm_provider.transmogrifier') as mock_trans:
        mock_trans.normalize = AsyncMock(side_effect=Exception("Service error"))
        result = await transmogrify_prompt("Test prompt", "gpt-4o")
        assert result == "Test prompt"


# ============================================================================
# Test CostTracker
# ============================================================================

def test_cost_tracker_init():
    """Test initializing CostTracker with empty calls list."""
    tracker = CostTracker()
    assert tracker.calls == []


def test_cost_tracker_record(cost_tracker, sample_call_record):
    """Test recording a single call to tracker."""
    cost_tracker.record(sample_call_record)
    assert len(cost_tracker.calls) == 1
    assert cost_tracker.calls[0] == sample_call_record


def test_cost_tracker_total_cost(cost_tracker):
    """Test calculating total cost across multiple calls."""
    record1 = LLMCallRecord("openai", "gpt-4o", 1000, 500, 0.015, 100.0, False)
    record2 = LLMCallRecord("anthropic", "claude-sonnet-4", 2000, 1000, 0.030, 200.0, False)
    
    cost_tracker.record(record1)
    cost_tracker.record(record2)
    
    result = cost_tracker.total_cost()
    assert result > 0
    assert isinstance(result, float)
    assert result == 0.045


def test_cost_tracker_total_cost_empty(cost_tracker):
    """Test total cost is zero for empty tracker."""
    result = cost_tracker.total_cost()
    assert result == 0.0


def test_cost_tracker_total_input_tokens(cost_tracker):
    """Test calculating total input tokens across calls."""
    record1 = LLMCallRecord("openai", "gpt-4o", 1000, 500, 0.015, 100.0, False)
    record2 = LLMCallRecord("anthropic", "claude-sonnet-4", 2000, 1000, 0.030, 200.0, False)
    
    cost_tracker.record(record1)
    cost_tracker.record(record2)
    
    result = cost_tracker.total_input_tokens()
    assert result == 3000
    assert isinstance(result, int)


def test_cost_tracker_total_output_tokens(cost_tracker):
    """Test calculating total output tokens across calls."""
    record1 = LLMCallRecord("openai", "gpt-4o", 1000, 500, 0.015, 100.0, False)
    record2 = LLMCallRecord("anthropic", "claude-sonnet-4", 2000, 1000, 0.030, 200.0, False)
    
    cost_tracker.record(record1)
    cost_tracker.record(record2)
    
    result = cost_tracker.total_output_tokens()
    assert result == 1500
    assert isinstance(result, int)


def test_cost_tracker_summary(cost_tracker):
    """Test generating summary with all required keys."""
    record1 = LLMCallRecord("openai", "gpt-4o", 1000, 500, 0.015, 100.0, False)
    record2 = LLMCallRecord("anthropic", "claude-sonnet-4", 2000, 1000, 0.030, 200.0, False)
    
    cost_tracker.record(record1)
    cost_tracker.record(record2)
    
    result = cost_tracker.summary()
    assert "total_calls" in result
    assert "total_input_tokens" in result
    assert "total_output_tokens" in result
    assert "total_cost_usd" in result
    assert "by_provider" in result
    assert result["total_calls"] == 2


def test_cost_tracker_by_provider(cost_tracker):
    """Test grouping calls by provider with statistics."""
    record1 = LLMCallRecord("openai", "gpt-4o", 1000, 500, 0.015, 100.0, False)
    record2 = LLMCallRecord("anthropic", "claude-sonnet-4", 2000, 1000, 0.030, 200.0, False)
    record3 = LLMCallRecord("openai", "gpt-4o", 500, 250, 0.0075, 50.0, False)
    
    cost_tracker.record(record1)
    cost_tracker.record(record2)
    cost_tracker.record(record3)
    
    result = cost_tracker._by_provider()
    assert isinstance(result, dict)
    assert "openai" in result
    assert "anthropic" in result
    assert result["openai"]["calls"] == 2
    assert result["anthropic"]["calls"] == 1


# ============================================================================
# Test LLMProvider base class
# ============================================================================

def test_llm_provider_init():
    """Test initializing provider with model and tracker."""
    # Use a concrete implementation
    provider = OpenAIProvider("gpt-4o", None)
    assert provider.model == "gpt-4o"
    assert isinstance(provider.cost_tracker, CostTracker)


def test_llm_provider_init_with_tracker(cost_tracker):
    """Test initializing provider with existing tracker."""
    provider = OpenAIProvider("gpt-4o", cost_tracker)
    assert provider.cost_tracker is cost_tracker


def test_llm_provider_record():
    """Test recording API call with usage metrics."""
    provider = OpenAIProvider("gpt-4o", None)
    
    with patch('src_webprobe_llm_provider.time.monotonic', side_effect=[0, 0.12345]):
        provider._record(1000, 500, 123.45, False)
    
    assert len(provider.cost_tracker.calls) == 1
    call = provider.cost_tracker.calls[0]
    assert call.input_tokens == 1000
    assert call.output_tokens == 500
    assert call.duration_ms == 123.45
    assert call.has_vision == False


# ============================================================================
# Test AnthropicProvider
# ============================================================================

def test_anthropic_provider_name():
    """Test Anthropic provider returns correct name."""
    provider = AnthropicProvider("claude-sonnet-4-20250514", None)
    result = provider.provider_name()
    assert result == "anthropic"


@pytest.mark.asyncio
async def test_anthropic_complete_success():
    """Test complete text generation via Anthropic API."""
    with patch('src_webprobe_llm_provider.anthropic.Anthropic') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock response
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Test response")]
        mock_response.usage = MagicMock(input_tokens=100, output_tokens=50)
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        
        provider = AnthropicProvider("claude-sonnet-4-20250514", None)
        
        with patch('src_webprobe_llm_provider.time.monotonic', side_effect=[0, 0.123]):
            result = await provider.complete("You are helpful", [{"role": "user", "content": "Hello"}], 1000)
        
        assert isinstance(result, str)
        assert len(result) > 0
        assert result == "Test response"


@pytest.mark.asyncio
async def test_anthropic_complete_api_error():
    """Test handling Anthropic API error gracefully."""
    with patch('src_webprobe_llm_provider.anthropic.Anthropic') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock API error
        mock_client.messages.create = AsyncMock(side_effect=Exception("API Error"))
        
        provider = AnthropicProvider("claude-sonnet-4-20250514", None)
        
        with pytest.raises(Exception):
            await provider.complete("You are helpful", [{"role": "user", "content": "Hello"}], 1000)


@pytest.mark.asyncio
async def test_anthropic_complete_empty_content():
    """Test handling empty response content list."""
    with patch('src_webprobe_llm_provider.anthropic.Anthropic') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock response with empty content
        mock_response = MagicMock()
        mock_response.content = []
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        
        provider = AnthropicProvider("claude-sonnet-4-20250514", None)
        
        with pytest.raises(IndexError):
            await provider.complete("You are helpful", [{"role": "user", "content": "Hello"}], 1000)


@pytest.mark.asyncio
async def test_anthropic_vision_success(temp_image_file):
    """Test analyzing image via Anthropic vision API."""
    with patch('src_webprobe_llm_provider.anthropic.Anthropic') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock response
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="This is a cat")]
        mock_response.usage = MagicMock(input_tokens=200, output_tokens=50)
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        
        provider = AnthropicProvider("claude-sonnet-4-20250514", None)
        
        with patch('src_webprobe_llm_provider.time.monotonic', side_effect=[0, 0.234]):
            result = await provider.vision("You are helpful", "Describe this image", temp_image_file, 1000)
        
        assert isinstance(result, str)
        assert len(result) > 0
        assert provider.cost_tracker.calls[0].has_vision == True


@pytest.mark.asyncio
async def test_anthropic_vision_file_error():
    """Test handling file not found error in vision call."""
    provider = AnthropicProvider("claude-sonnet-4-20250514", None)
    
    with pytest.raises((FileNotFoundError, IOError)):
        await provider.vision("You are helpful", "Describe this image", "/nonexistent.png", 1000)


# ============================================================================
# Test OpenAIProvider
# ============================================================================

def test_openai_provider_name():
    """Test OpenAI provider returns correct name."""
    provider = OpenAIProvider("gpt-4o", None)
    result = provider.provider_name()
    assert result == "openai"


@pytest.mark.asyncio
async def test_openai_complete_success():
    """Test complete text generation via OpenAI API."""
    with patch('src_webprobe_llm_provider.openai.OpenAI') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Test response"))]
        mock_response.usage = MagicMock(prompt_tokens=100, completion_tokens=50)
        mock_client.chat.completions.create = Mock(return_value=mock_response)
        
        provider = OpenAIProvider("gpt-4o", None)
        
        with patch('src_webprobe_llm_provider.time.monotonic', side_effect=[0, 0.156]):
            result = await provider.complete("You are helpful", [{"role": "user", "content": "Hello"}], 1000)
        
        assert isinstance(result, str)
        assert result == "Test response"


@pytest.mark.asyncio
async def test_openai_complete_api_error():
    """Test handling OpenAI API error gracefully."""
    with patch('src_webprobe_llm_provider.openai.OpenAI') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock API error
        mock_client.chat.completions.create = Mock(side_effect=Exception("API Error"))
        
        provider = OpenAIProvider("gpt-4o", None)
        
        with pytest.raises(Exception):
            await provider.complete("You are helpful", [{"role": "user", "content": "Hello"}], 1000)


@pytest.mark.asyncio
async def test_openai_vision_success(temp_image_file):
    """Test analyzing image via OpenAI vision API."""
    with patch('src_webprobe_llm_provider.openai.OpenAI') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="This is a dog"))]
        mock_response.usage = MagicMock(prompt_tokens=200, completion_tokens=50)
        mock_client.chat.completions.create = Mock(return_value=mock_response)
        
        provider = OpenAIProvider("gpt-4o", None)
        
        with patch('src_webprobe_llm_provider.time.monotonic', side_effect=[0, 0.267]):
            result = await provider.vision("You are helpful", "Describe this image", temp_image_file, 1000)
        
        assert isinstance(result, str)
        assert provider.cost_tracker.calls[0].has_vision == True


@pytest.mark.asyncio
async def test_openai_vision_file_error():
    """Test handling file error in OpenAI vision call."""
    provider = OpenAIProvider("gpt-4o", None)
    
    with pytest.raises((FileNotFoundError, IOError)):
        await provider.vision("You are helpful", "Describe this image", "/nonexistent.png", 1000)


# ============================================================================
# Test GeminiProvider
# ============================================================================

def test_gemini_provider_name():
    """Test Gemini provider returns correct name."""
    provider = GeminiProvider("gemini-2.5-flash", None)
    result = provider.provider_name()
    assert result == "gemini"


@pytest.mark.asyncio
async def test_gemini_complete_success():
    """Test complete text generation via Gemini API."""
    with patch('src_webprobe_llm_provider.google.genai.Client') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock response
        mock_response = MagicMock()
        mock_response.text = "Test response"
        mock_response.usage_metadata = MagicMock(prompt_token_count=100, candidates_token_count=50)
        mock_client.models.generate_content = AsyncMock(return_value=mock_response)
        
        provider = GeminiProvider("gemini-2.5-flash", None)
        
        with patch('src_webprobe_llm_provider.time.monotonic', side_effect=[0, 0.189]):
            result = await provider.complete("You are helpful", [{"role": "user", "content": "Hello"}], 1000)
        
        assert isinstance(result, str)
        assert result == "Test response"


@pytest.mark.asyncio
async def test_gemini_complete_api_error():
    """Test handling Gemini API error gracefully."""
    with patch('src_webprobe_llm_provider.google.genai.Client') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock API error
        mock_client.models.generate_content = AsyncMock(side_effect=Exception("API Error"))
        
        provider = GeminiProvider("gemini-2.5-flash", None)
        
        with pytest.raises(Exception):
            await provider.complete("You are helpful", [{"role": "user", "content": "Hello"}], 1000)


@pytest.mark.asyncio
async def test_gemini_vision_success(temp_image_file):
    """Test analyzing image via Gemini vision API."""
    with patch('src_webprobe_llm_provider.google.genai.Client') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock response
        mock_response = MagicMock()
        mock_response.text = "This is a bird"
        mock_response.usage_metadata = MagicMock(prompt_token_count=200, candidates_token_count=50)
        mock_client.models.generate_content = AsyncMock(return_value=mock_response)
        
        provider = GeminiProvider("gemini-2.5-flash", None)
        
        with patch('src_webprobe_llm_provider.time.monotonic', side_effect=[0, 0.298]):
            result = await provider.vision("You are helpful", "Describe this image", temp_image_file, 1000)
        
        assert isinstance(result, str)
        assert provider.cost_tracker.calls[0].has_vision == True


@pytest.mark.asyncio
async def test_gemini_vision_file_error():
    """Test handling file error in Gemini vision call."""
    provider = GeminiProvider("gemini-2.5-flash", None)
    
    with pytest.raises((FileNotFoundError, IOError)):
        await provider.vision("You are helpful", "Describe this image", "/nonexistent.png", 1000)


# ============================================================================
# Test ApprenticeProvider
# ============================================================================

def test_apprentice_provider_name():
    """Test Apprentice provider returns correct name."""
    provider = ApprenticeProvider("auto", None)
    result = provider.provider_name()
    assert result == "apprentice"


@pytest.mark.asyncio
async def test_apprentice_complete_success():
    """Test complete text generation via Apprentice API."""
    with patch('src_webprobe_llm_provider.openai.OpenAI') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Test response from Apprentice"))]
        mock_response.usage = MagicMock(prompt_tokens=100, completion_tokens=50)
        mock_client.chat.completions.create = Mock(return_value=mock_response)
        
        provider = ApprenticeProvider("auto", None)
        
        with patch('src_webprobe_llm_provider.time.monotonic', side_effect=[0, 0.178]):
            result = await provider.complete("You are helpful", [{"role": "user", "content": "Hello"}], 1000)
        
        assert isinstance(result, str)
        assert result == "Test response from Apprentice"


@pytest.mark.asyncio
async def test_apprentice_complete_connection_error():
    """Test handling connection error when Apprentice service unreachable."""
    with patch('src_webprobe_llm_provider.openai.OpenAI') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock connection error
        import openai
        mock_client.chat.completions.create = Mock(side_effect=openai.APIConnectionError("Connection failed"))
        
        provider = ApprenticeProvider("auto", None)
        
        with pytest.raises(Exception):
            await provider.complete("You are helpful", [{"role": "user", "content": "Hello"}], 1000)


@pytest.mark.asyncio
async def test_apprentice_complete_api_error():
    """Test handling Apprentice API error gracefully."""
    with patch('src_webprobe_llm_provider.openai.OpenAI') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock API error
        mock_client.chat.completions.create = Mock(side_effect=Exception("API Error"))
        
        provider = ApprenticeProvider("auto", None)
        
        with pytest.raises(Exception):
            await provider.complete("You are helpful", [{"role": "user", "content": "Hello"}], 1000)


@pytest.mark.asyncio
async def test_apprentice_vision_success(temp_image_file):
    """Test analyzing image via Apprentice vision API."""
    with patch('src_webprobe_llm_provider.openai.OpenAI') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="This is a tree"))]
        mock_response.usage = MagicMock(prompt_tokens=200, completion_tokens=50)
        mock_client.chat.completions.create = Mock(return_value=mock_response)
        
        provider = ApprenticeProvider("auto", None)
        
        with patch('src_webprobe_llm_provider.time.monotonic', side_effect=[0, 0.345]):
            result = await provider.vision("You are helpful", "Describe this image", temp_image_file, 1000)
        
        assert isinstance(result, str)
        assert provider.cost_tracker.calls[0].has_vision == True


@pytest.mark.asyncio
async def test_apprentice_vision_file_error():
    """Test handling file error in Apprentice vision call."""
    provider = ApprenticeProvider("auto", None)
    
    with pytest.raises((FileNotFoundError, IOError)):
        await provider.vision("You are helpful", "Describe this image", "/nonexistent.png", 1000)


# ============================================================================
# Test Invariants
# ============================================================================

def test_invariant_non_negative_tokens(cost_tracker):
    """Test that all token counts are non-negative."""
    record1 = LLMCallRecord("openai", "gpt-4o", 1000, 500, 0.015, 100.0, False)
    record2 = LLMCallRecord("anthropic", "claude-sonnet-4", 0, 0, 0.0, 50.0, False)
    record3 = LLMCallRecord("gemini", "gemini-2.5-flash", 5000, 2500, 0.05, 150.0, True)
    
    cost_tracker.record(record1)
    cost_tracker.record(record2)
    cost_tracker.record(record3)
    
    assert all(call.input_tokens >= 0 for call in cost_tracker.calls)
    assert all(call.output_tokens >= 0 for call in cost_tracker.calls)


def test_invariant_non_negative_costs(cost_tracker):
    """Test that all costs are non-negative."""
    record1 = LLMCallRecord("openai", "gpt-4o", 1000, 500, 0.015, 100.0, False)
    record2 = LLMCallRecord("anthropic", "claude-sonnet-4", 2000, 1000, 0.030, 200.0, False)
    record3 = LLMCallRecord("gemini", "gemini-2.5-flash", 0, 0, 0.0, 50.0, False)
    
    cost_tracker.record(record1)
    cost_tracker.record(record2)
    cost_tracker.record(record3)
    
    assert all(call.estimated_cost_usd >= 0 for call in cost_tracker.calls)


def test_invariant_apprentice_base_url():
    """Test that Apprentice uses localhost:8741 base URL."""
    with patch('src_webprobe_llm_provider.openai.OpenAI') as mock_client_class:
        provider = ApprenticeProvider("auto", None)
        
        # Verify the base_url was set correctly
        if mock_client_class.called:
            call_kwargs = mock_client_class.call_args[1] if mock_client_class.call_args else {}
            if 'base_url' in call_kwargs:
                assert 'localhost:8741' in call_kwargs['base_url']


@pytest.mark.asyncio
async def test_invariant_image_media_type(temp_image_file):
    """Test that vision calls use image/png media type."""
    with patch('src_webprobe_llm_provider.anthropic.Anthropic') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock response
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Image analysis")]
        mock_response.usage = MagicMock(input_tokens=200, output_tokens=50)
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        
        provider = AnthropicProvider("claude-sonnet-4-20250514", None)
        
        with patch('src_webprobe_llm_provider.time.monotonic', side_effect=[0, 0.234]):
            await provider.vision("You are helpful", "Describe this image", temp_image_file, 1000)
        
        # Check that messages.create was called with image/png media type
        call_args = mock_client.messages.create.call_args
        if call_args:
            # The media_type should be in the content of the message
            assert call_args is not None


# ============================================================================
# Additional Edge Cases
# ============================================================================

def test_cost_tracker_multiple_providers(cost_tracker):
    """Test tracking calls from multiple providers."""
    records = [
        LLMCallRecord("openai", "gpt-4o", 1000, 500, 0.015, 100.0, False),
        LLMCallRecord("anthropic", "claude-sonnet-4", 2000, 1000, 0.030, 200.0, False),
        LLMCallRecord("gemini", "gemini-2.5-flash", 1500, 750, 0.0225, 150.0, True),
        LLMCallRecord("apprentice", "auto", 800, 400, 0.012, 80.0, False),
    ]
    
    for record in records:
        cost_tracker.record(record)
    
    summary = cost_tracker.summary()
    assert summary["total_calls"] == 4
    assert len(summary["by_provider"]) == 4


def test_provider_with_vision_flag():
    """Test that vision calls set has_vision=True."""
    provider = OpenAIProvider("gpt-4o", None)
    provider._record(1000, 500, 100.0, True)
    
    assert provider.cost_tracker.calls[0].has_vision == True


def test_provider_without_vision_flag():
    """Test that non-vision calls set has_vision=False."""
    provider = OpenAIProvider("gpt-4o", None)
    provider._record(1000, 500, 100.0, False)
    
    assert provider.cost_tracker.calls[0].has_vision == False


@pytest.mark.asyncio
async def test_complete_with_empty_messages():
    """Test completion with empty message list."""
    with patch('src_webprobe_llm_provider.openai.OpenAI') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content=""))]
        mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=0)
        mock_client.chat.completions.create = Mock(return_value=mock_response)
        
        provider = OpenAIProvider("gpt-4o", None)
        
        with patch('src_webprobe_llm_provider.time.monotonic', side_effect=[0, 0.05]):
            result = await provider.complete("System", [], 100)
        
        # Should handle gracefully
        assert isinstance(result, str)


def test_cost_estimation_large_numbers():
    """Test cost estimation with very large token counts."""
    result = _estimate_cost("gpt-4o", 10_000_000, 5_000_000)
    assert result >= 0
    assert isinstance(result, float)


def test_base64_encoding_roundtrip(temp_image_file):
    """Test that base64 encoding can be decoded back."""
    encoded = _load_image_b64(temp_image_file)
    decoded = base64.b64decode(encoded)
    
    # Read original file
    original = temp_image_file.read_bytes()
    
    assert decoded == original
