# === LLM Provider Abstraction (src_webprobe_llm_provider) v1 ===
#  Dependencies: base64, time, abc, dataclasses, pathlib, typing, pydantic, anthropic, openai, google.genai, transmogrifier.core
# Multi-provider LLM abstraction with vision support, cost tracking, and transmogrifier integration. Provides unified interface for Claude (Anthropic), OpenAI, Gemini, and Apprentice LLM providers with automatic cost estimation, token tracking, and vision capabilities for image analysis.

# Module invariants:
#   - _PRICING dictionary contains fixed pricing data for known models (USD per 1M tokens)
#   - Default provider models: anthropic='claude-sonnet-4-20250514', openai='gpt-4o', gemini='gemini-2.5-flash', apprentice='auto'
#   - Image media type hardcoded as 'image/png' for all vision calls
#   - Apprentice base URL is 'http://localhost:8741/v1'
#   - All token counts and costs are non-negative
#   - Duration measurements use time.monotonic() and are converted to milliseconds

class LLMCallRecord:
    """Record of a single LLM API call with cost and usage metrics"""
    provider: str                            # required, Provider name (anthropic, openai, gemini, apprentice)
    model: str                               # required, Model identifier
    input_tokens: int = 0                    # optional, Number of input tokens
    output_tokens: int = 0                   # optional, Number of output tokens
    estimated_cost_usd: float = 0.0          # optional, Estimated cost in USD
    duration_ms: float = 0.0                 # optional, Call duration in milliseconds
    has_vision: bool = false                 # optional, Whether the call involved vision/image analysis

class CostTracker:
    """Accumulates LLM call records for cost and usage reporting"""
    calls: list[LLMCallRecord]               # required, List of recorded API calls

class LLMProvider:
    """Abstract base class for LLM providers with vision and text capabilities"""
    model: str                               # required, Model identifier
    cost_tracker: CostTracker                # required, Cost tracker instance

class AnthropicProvider:
    """Claude API provider implementation"""
    pass

class OpenAIProvider:
    """OpenAI-compatible provider (OpenAI, Azure, local)"""
    pass

class GeminiProvider:
    """Google Gemini provider implementation"""
    pass

class ApprenticeProvider:
    """Apprentice adaptive routing provider (routes between local and frontier models)"""
    pass

def _estimate_cost(
    model: str,
    input_tokens: int,
    output_tokens: int,
) -> float:
    """
    Estimates API call cost in USD based on model and token counts. Uses prefix matching against known pricing table, falls back to mid-range pricing for unknown models.

    Postconditions:
      - Returns non-negative cost estimate in USD

    Side effects: none
    Idempotent: no
    """
    ...

def _load_image_b64(
    path: str | Path,
) -> str:
    """
    Loads an image file and encodes it as base64 string

    Postconditions:
      - Returns base64-encoded image data as string

    Errors:
      - file_not_found (FileNotFoundError): Image file does not exist
      - permission_error (PermissionError): Insufficient permissions to read file

    Side effects: Reads file from disk
    Idempotent: no
    """
    ...

def create_provider(
    provider: str = anthropic,
    model: str | None = None,
    cost_tracker: CostTracker | None = None,
) -> LLMProvider:
    """
    Factory function that creates an LLM provider instance by name with optional model and cost tracker

    Postconditions:
      - Returns initialized LLMProvider instance

    Errors:
      - unknown_provider (ValueError): provider not in ['anthropic', 'openai', 'gemini', 'apprentice']

    Side effects: none
    Idempotent: no
    """
    ...

async def transmogrify_prompt(
    text: str,
    model: str,
) -> str:
    """
    Normalizes prompt register via transmogrifier if available. Falls back to returning original text if transmogrifier unavailable or errors.

    Postconditions:
      - Returns normalized text or original text on error

    Side effects: May call transmogrifier.core.Transmogrifier.translate
    Idempotent: no
    """
    ...

def CostTracker.__init__() -> None:
    """
    Initializes empty cost tracker with no recorded calls

    Postconditions:
      - self.calls is empty list

    Side effects: none
    Idempotent: no
    """
    ...

def CostTracker.record(
    call: LLMCallRecord,
) -> None:
    """
    Records a single LLM API call to the tracker

    Postconditions:
      - call appended to self.calls

    Side effects: Mutates self.calls list
    Idempotent: no
    """
    ...

def CostTracker.total_cost() -> float:
    """
    Property that computes total estimated cost across all recorded calls

    Postconditions:
      - Returns sum of all estimated_cost_usd values

    Side effects: none
    Idempotent: no
    """
    ...

def CostTracker.total_input_tokens() -> int:
    """
    Property that computes total input tokens across all recorded calls

    Postconditions:
      - Returns sum of all input_tokens values

    Side effects: none
    Idempotent: no
    """
    ...

def CostTracker.total_output_tokens() -> int:
    """
    Property that computes total output tokens across all recorded calls

    Postconditions:
      - Returns sum of all output_tokens values

    Side effects: none
    Idempotent: no
    """
    ...

def CostTracker.summary() -> dict:
    """
    Generates summary dictionary with aggregate statistics across all calls

    Postconditions:
      - Returns dict with keys: total_calls, total_input_tokens, total_output_tokens, total_cost_usd, by_provider

    Side effects: none
    Idempotent: no
    """
    ...

def CostTracker._by_provider() -> dict:
    """
    Internal method that groups calls by provider and computes per-provider statistics

    Postconditions:
      - Returns dict mapping provider names to dicts with calls, cost_usd, tokens

    Side effects: none
    Idempotent: no
    """
    ...

def LLMProvider.__init__(
    model: str,
    cost_tracker: CostTracker | None = None,
) -> None:
    """
    Initializes LLM provider with model identifier and optional cost tracker

    Postconditions:
      - self.model set to model parameter
      - self.cost_tracker set to provided or new CostTracker

    Side effects: none
    Idempotent: no
    """
    ...

async def LLMProvider.complete(
    system: str,
    messages: list[dict],
    max_tokens: int = 4096,
) -> str:
    """
    Abstract method for text completion. Must be implemented by subclasses.

    Postconditions:
      - Returns generated text completion

    Side effects: Makes API call to LLM provider, Records call to cost tracker
    Idempotent: no
    """
    ...

async def LLMProvider.vision(
    system: str,
    prompt: str,
    image_path: str | Path,
    max_tokens: int = 4096,
) -> str:
    """
    Abstract method for image analysis with text prompt. Must be implemented by subclasses.

    Postconditions:
      - Returns generated text analysis of image

    Side effects: Reads image file, Makes API call to LLM provider, Records call to cost tracker
    Idempotent: no
    """
    ...

def LLMProvider._record(
    input_tokens: int,
    output_tokens: int,
    duration_ms: float,
    has_vision: bool = False,
) -> None:
    """
    Internal method to record an LLM API call with usage metrics

    Postconditions:
      - LLMCallRecord created and added to cost_tracker

    Side effects: Mutates cost_tracker.calls
    Idempotent: no
    """
    ...

def LLMProvider.provider_name() -> str:
    """
    Abstract property returning provider name string. Must be implemented by subclasses.

    Postconditions:
      - Returns provider identifier string

    Side effects: none
    Idempotent: no
    """
    ...

def AnthropicProvider.provider_name() -> str:
    """
    Property returning 'anthropic' as provider identifier

    Postconditions:
      - Returns 'anthropic'

    Side effects: none
    Idempotent: no
    """
    ...

async def AnthropicProvider.complete(
    system: str,
    messages: list[dict],
    max_tokens: int = 4096,
) -> str:
    """
    Text completion using Claude API via Anthropic SDK

    Postconditions:
      - Returns text from response.content[0].text
      - Records usage to cost tracker

    Errors:
      - api_error (anthropic.APIError): Anthropic API returns error
      - index_error (IndexError): response.content is empty

    Side effects: Creates AsyncAnthropic client, Makes API call, Records metrics
    Idempotent: no
    """
    ...

async def AnthropicProvider.vision(
    system: str,
    prompt: str,
    image_path: str | Path,
    max_tokens: int = 4096,
) -> str:
    """
    Image analysis using Claude vision API

    Postconditions:
      - Returns text from response.content[0].text
      - Records usage with has_vision=True

    Errors:
      - file_error (FileNotFoundError | PermissionError): Image file not found or unreadable
      - api_error (anthropic.APIError): Anthropic API returns error
      - index_error (IndexError): response.content is empty

    Side effects: Reads image file, Creates AsyncAnthropic client, Makes API call, Records metrics
    Idempotent: no
    """
    ...

def OpenAIProvider.provider_name() -> str:
    """
    Property returning 'openai' as provider identifier

    Postconditions:
      - Returns 'openai'

    Side effects: none
    Idempotent: no
    """
    ...

async def OpenAIProvider.complete(
    system: str,
    messages: list[dict],
    max_tokens: int = 4096,
) -> str:
    """
    Text completion using OpenAI-compatible API

    Postconditions:
      - Returns message content or empty string
      - Records usage to cost tracker

    Errors:
      - api_error (openai.APIError): OpenAI API returns error

    Side effects: Creates AsyncOpenAI client, Makes API call, Records metrics
    Idempotent: no
    """
    ...

async def OpenAIProvider.vision(
    system: str,
    prompt: str,
    image_path: str | Path,
    max_tokens: int = 4096,
) -> str:
    """
    Image analysis using OpenAI vision API

    Postconditions:
      - Returns message content or empty string
      - Records usage with has_vision=True

    Errors:
      - file_error (FileNotFoundError | PermissionError): Image file not found or unreadable
      - api_error (openai.APIError): OpenAI API returns error

    Side effects: Reads image file, Creates AsyncOpenAI client, Makes API call, Records metrics
    Idempotent: no
    """
    ...

def GeminiProvider.provider_name() -> str:
    """
    Property returning 'gemini' as provider identifier

    Postconditions:
      - Returns 'gemini'

    Side effects: none
    Idempotent: no
    """
    ...

async def GeminiProvider.complete(
    system: str,
    messages: list[dict],
    max_tokens: int = 4096,
) -> str:
    """
    Text completion using Google Gemini API

    Postconditions:
      - Returns response.text or empty string
      - Records usage to cost tracker

    Errors:
      - api_error (google.genai.errors.ClientError): Gemini API returns error

    Side effects: Creates genai.Client, Converts messages to Gemini format, Makes API call, Records metrics
    Idempotent: no
    """
    ...

async def GeminiProvider.vision(
    system: str,
    prompt: str,
    image_path: str | Path,
    max_tokens: int = 4096,
) -> str:
    """
    Image analysis using Google Gemini vision API

    Postconditions:
      - Returns response.text or empty string
      - Records usage with has_vision=True

    Errors:
      - file_error (FileNotFoundError | PermissionError): Image file not found or unreadable
      - api_error (google.genai.errors.ClientError): Gemini API returns error

    Side effects: Reads image file, Creates genai.Client, Makes API call, Records metrics
    Idempotent: no
    """
    ...

def ApprenticeProvider.provider_name() -> str:
    """
    Property returning 'apprentice' as provider identifier

    Postconditions:
      - Returns 'apprentice'

    Side effects: none
    Idempotent: no
    """
    ...

async def ApprenticeProvider.complete(
    system: str,
    messages: list[dict],
    max_tokens: int = 4096,
) -> str:
    """
    Text completion using Apprentice adaptive routing via OpenAI-compatible API on localhost:8741

    Preconditions:
      - Apprentice service running on localhost:8741

    Postconditions:
      - Returns message content or empty string
      - Records usage to cost tracker

    Errors:
      - connection_error (openai.APIConnectionError): Apprentice service not reachable
      - api_error (openai.APIError): Apprentice API returns error

    Side effects: Creates AsyncOpenAI client with base_url=http://localhost:8741/v1, Makes API call, Records metrics
    Idempotent: no
    """
    ...

async def ApprenticeProvider.vision(
    system: str,
    prompt: str,
    image_path: str | Path,
    max_tokens: int = 4096,
) -> str:
    """
    Image analysis using Apprentice API (falls back to frontier model for vision tasks)

    Preconditions:
      - Apprentice service running on localhost:8741

    Postconditions:
      - Returns message content or empty string
      - Records usage with has_vision=True

    Errors:
      - file_error (FileNotFoundError | PermissionError): Image file not found or unreadable
      - connection_error (openai.APIConnectionError): Apprentice service not reachable
      - api_error (openai.APIError): Apprentice API returns error

    Side effects: Reads image file, Creates AsyncOpenAI client with base_url=http://localhost:8741/v1, Makes API call, Records metrics
    Idempotent: no
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['LLMCallRecord', 'CostTracker', 'LLMProvider', 'AnthropicProvider', 'OpenAIProvider', 'GeminiProvider', 'ApprenticeProvider', '_estimate_cost', '_load_image_b64', 'create_provider', 'transmogrify_prompt', 'FileNotFoundError | PermissionError']
