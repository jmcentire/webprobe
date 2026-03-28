# === Webprobe LLM-Driven Exploration (src_webprobe_explorer) v1 ===
#  Dependencies: asyncio, json, time, datetime, pathlib, webprobe.browser, webprobe.config, webprobe.llm_provider, webprobe.mask, webprobe.models, webprobe.visual
# Phase 5 of the webprobe security auditor: concurrent LLM agents autonomously explore UI features, interact with web pages, and discover security issues through visual analysis, accessibility checks, and intelligent navigation.

# Module invariants:
#   - _AGENT_SYSTEM constant defines the agent's role and behavior rules
#   - _AGENT_OBSERVE constant template for formatting agent observations
#   - Agents use fake test data, never real personal information
#   - Agents avoid destructive actions (delete/remove/cancel-account)
#   - Maximum 40 interactive elements extracted per page
#   - Text truncated to 2000 characters for LLM context
#   - Href attributes truncated to 80 characters
#   - Console log limited to last 10 messages per iteration
#   - One screenshot analysis per node maximum
#   - SecurityFinding severity for agent observations is medium
#   - SecurityFinding severity for failed actions is low
#   - SecurityFinding category defaults to information_disclosure
#   - AuthContext defaults to anonymous for agent-generated findings
#   - Navigation timeout is 30000ms for initial load, 15000ms for agent navigation
#   - Click/fill timeout is 5000ms
#   - Networkidle wait state used after clicks
#   - Scroll delta is 500 pixels
#   - Phase name is 'explore'

class ExploreConfig:
    """Configuration for the LLM exploration phase controlling concurrency, analysis types, and agent behavior"""
    provider: str = anthropic                # optional, LLM provider name (e.g., anthropic, openai, gemini)
    model: str | None = None                 # optional, Specific model to use, or None for provider default
    concurrency: int = 5                     # optional, Number of concurrent exploration agents
    concurrency_warn_threshold: int = 20     # optional, Threshold to warn about high concurrency
    max_actions_per_agent: int = 20          # optional, Maximum actions each agent can perform
    visual_analysis: bool = True             # optional, Enable LLM-based visual screenshot analysis
    contrast_check: bool = True              # optional, Enable accessibility contrast checking
    hidden_elements: bool = True             # optional, Enable hidden elements detection
    mask_path: str | None = None             # optional, Path to mask file for filtering findings

async def _extract_interactive_elements(
    page: object,
) -> str:
    """
    Extracts a formatted summary of interactive elements from a browser page using JavaScript evaluation. Finds up to 40 visible interactive elements (links, buttons, inputs, roles, etc.) and returns their attributes as formatted text.

    Preconditions:
      - page must be a valid Playwright Page object
      - page must have an evaluate() method

    Postconditions:
      - Returns newline-separated list of interactive element descriptions
      - Returns '(no interactive elements found)' if list is empty
      - Returns '(error extracting elements)' on exception
      - Maximum 40 elements returned
      - Only visible elements included (display != 'none', visibility != 'hidden')

    Errors:
      - evaluation_error (Exception): Exception during page.evaluate()
          return_value: (error extracting elements)

    Side effects: Executes JavaScript in the browser page context
    Idempotent: no
    """
    ...

async def _run_agent(
    agent_id: int,
    node: Node,
    llm: LLMProvider,
    pool: BrowserPool,
    config: ExploreConfig,
    base_url: str,
    run_dir: Path,
    semaphore: asyncio.Semaphore,
) -> list[SecurityFinding]:
    """
    Runs a single autonomous exploration agent on a node. Performs visual analysis, accessibility checks, and LLM-driven interactive exploration with up to max_actions_per_agent iterations. Returns all security findings discovered.

    Preconditions:
      - pool must be a valid BrowserPool
      - node.state.url must be a valid URL
      - run_dir must exist if visual_analysis is enabled
      - semaphore must be a valid asyncio.Semaphore

    Postconditions:
      - Returns list of SecurityFinding objects (may be empty)
      - Browser context is closed before return
      - Semaphore is released (via async context manager)

    Errors:
      - navigation_failure (Exception): Initial page.goto() fails
          return_value: empty findings list
      - page_state_error (Exception): Exception during page.url, page.title(), or page.evaluate()
          behavior: breaks exploration loop
      - llm_error (Exception): Exception during llm.complete() or transmogrify_prompt()
          behavior: breaks exploration loop
      - action_parse_error (ValueError | json.JSONDecodeError): JSON parsing fails or response doesn't contain valid JSON
          behavior: breaks exploration loop
      - action_execution_error (Exception): Exception during click/fill/navigate/scroll
          behavior: creates low severity SecurityFinding, continues loop

    Side effects: Creates and closes browser context, Navigates browser pages, Performs clicks, fills, scrolls on web pages, Calls LLM APIs for decisions and visual analysis, Reads screenshot files from disk if visual_analysis enabled
    Idempotent: no
    """
    ...

def on_console(
    msg: object,
) -> None:
    """
    Event handler that captures console messages from the browser page and appends them to console_log list with type prefix.

    Preconditions:
      - msg must have .type and .text attributes

    Postconditions:
      - Appends formatted string to console_log list in enclosing scope

    Side effects: Mutates console_log list in parent scope
    Idempotent: no
    """
    ...

async def explore_site(
    config: WebprobeConfig,
    explore_config: ExploreConfig,
    graph: SiteGraph,
    run_dir: Path,
) -> tuple[list[SecurityFinding], PhaseStatus, CostTracker]:
    """
    Phase 5 entry point: orchestrates concurrent LLM-driven exploration of all nodes in the site graph. Creates one agent per node, collects findings, applies masking, and tracks costs.

    Preconditions:
      - config.capture must be valid for BrowserPool
      - graph.nodes must be a dict of Node objects
      - run_dir must exist

    Postconditions:
      - Returns tuple of (masked findings, phase status, cost tracker)
      - phase.status is 'completed'
      - phase.completed_at and phase.duration_ms are set
      - All browser contexts are closed
      - Findings have mask applied (suppressed findings filtered out)

    Errors:
      - agent_exception (Exception): Individual agent task raises exception
          behavior: exception captured by asyncio.gather(return_exceptions=True), findings from failed agent skipped

    Side effects: Creates and manages browser pool, Spawns concurrent agent tasks, Creates LLM provider instance, Loads mask configuration from file if mask_path specified, Tracks LLM API costs
    Idempotent: no
    """
    ...

def __init__(
    self: ExploreConfig,
    provider: str = anthropic,
    model: str | None = None,
    concurrency: int = 5,
    concurrency_warn_threshold: int = 20,
    max_actions_per_agent: int = 20,
    visual_analysis: bool = True,
    contrast_check: bool = True,
    hidden_elements: bool = True,
    mask_path: str | None = None,
) -> None:
    """
    Initializes ExploreConfig with exploration phase settings including LLM provider, concurrency, analysis toggles, and agent behavior limits.

    Postconditions:
      - All instance attributes are set to provided or default values

    Side effects: Initializes instance attributes
    Idempotent: no
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['ExploreConfig', '_extract_interactive_elements', '_run_agent', 'on_console', 'explore_site']
