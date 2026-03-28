"""Phase 5: LLM-driven exploration -- concurrent agents discover and test UI features.

Architecture (post-Advocate review):
- Computational checks (contrast, hidden elements) run ONCE across all nodes, not per-agent
- LLM agents handle only interactive exploration and vision analysis
- Each analysis type has independent error handling (one failure doesn't kill others)
- Selectors and URLs from LLM are validated before execution
- Page content is sanitized before prompt injection
- Cost limits enforced with emergency stop
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

from webprobe.browser import BrowserPool
from webprobe.config import WebprobeConfig
from webprobe.llm_provider import CostTracker, LLMProvider, create_provider, transmogrify_prompt
from webprobe.mask import apply_mask, load_mask
from webprobe.models import (
    AuthContext,
    Node,
    PhaseStatus,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
    SiteGraph,
)
from webprobe.visual import analyze_screenshot, check_contrast_from_page, detect_hidden_elements

logger = logging.getLogger("webprobe.explorer")

# ---- Constants (formerly magic numbers) ----

PAGE_LOAD_TIMEOUT_MS = 30_000
INTERACTION_TIMEOUT_MS = 5_000
NAVIGATION_TIMEOUT_MS = 15_000
NETWORKIDLE_TIMEOUT_MS = 10_000
SCROLL_DELTA_PX = 500
SCROLL_SETTLE_S = 0.5
MAX_INTERACTIVE_ELEMENTS = 40
MAX_PAGE_TEXT_CHARS = 2_000
MAX_CONSOLE_LINES = 10
MAX_TITLE_CHARS = 80
DEFAULT_COST_LIMIT_USD = 10.0


# ---- Explore config ----


class ScanMode(str, Enum):
    """Replaces boolean soup -- three clear modes."""
    full = "full"          # Computational checks + LLM vision + LLM exploration
    visual = "visual"      # Computational checks + LLM vision only (no interactive exploration)
    explore_only = "explore_only"  # LLM exploration only (skip computational checks)


class ExploreConfig:
    """Configuration for the exploration phase."""

    def __init__(
        self,
        provider: str = "anthropic",
        model: str | None = None,
        concurrency: int = 5,
        concurrency_warn_threshold: int = 20,
        max_actions_per_agent: int = 20,
        scan_mode: ScanMode = ScanMode.full,
        mask_path: str | None = None,
        cost_limit_usd: float = DEFAULT_COST_LIMIT_USD,
    ) -> None:
        self.provider = provider
        self.model = model
        self.concurrency = concurrency
        self.concurrency_warn_threshold = concurrency_warn_threshold
        self.max_actions_per_agent = max_actions_per_agent
        self.scan_mode = scan_mode
        self.mask_path = mask_path
        self.cost_limit_usd = cost_limit_usd


# ---- Selector and URL validation (Red Team fixes) ----


_SAFE_SELECTOR_RE = re.compile(
    r'^[a-zA-Z0-9\s\-_\.\#\[\]="\':,>+~*()@]+$'
)

_DANGEROUS_SELECTORS = {"script", "style", "meta", "link", "head", "html"}


def _validate_selector(selector: str) -> bool:
    """Reject selectors that look like injection attempts."""
    if not selector or len(selector) > 200:
        return False
    if not _SAFE_SELECTOR_RE.match(selector):
        return False
    tag = selector.split("[")[0].split(".")[0].split("#")[0].strip().lower()
    if tag in _DANGEROUS_SELECTORS:
        return False
    return True


def _validate_navigation_url(url: str, base_url: str) -> bool:
    """Only allow same-origin HTTP(S) navigation."""
    try:
        parsed = urlparse(url)
        base = urlparse(base_url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if parsed.hostname != base.hostname:
        return False
    return True


def _sanitize_for_prompt(text: str, max_len: int = 2000) -> str:
    """Strip content that could be prompt injection from page text."""
    truncated = text[:max_len]
    # Remove common prompt injection patterns
    truncated = re.sub(r'(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?)', '[REDACTED]', truncated)
    truncated = re.sub(r'(?i)you\s+are\s+now\s+', '[REDACTED]', truncated)
    truncated = re.sub(r'(?i)system\s*:\s*', '[REDACTED]', truncated)
    return truncated


# ---- Agent system prompt ----


_AGENT_SYSTEM = """You are an autonomous web testing agent. You have a browser open to a page.
Your job is to explore the page, interact with UI elements, and discover issues.

You receive:
- The current page URL
- The page's visible text content (truncated)
- A list of interactive elements on the page

For each turn, respond with a JSON action:
{"action": "click", "selector": "css selector", "reason": "why"}
{"action": "fill", "selector": "css selector", "value": "test input", "reason": "why"}
{"action": "scroll", "direction": "down|up", "reason": "why"}
{"action": "done", "reason": "finished exploring this page"}

Rules:
- NEVER submit real personal data. Use obviously fake test data (test@example.com, "Test User", etc.)
- NEVER click delete/remove/cancel-account buttons
- DO try form validation: empty submissions, very long strings, special characters
- DO check interactive elements: dropdowns, tabs, modals, accordions
- Report what you observe after each action

After each action, you'll receive the result. Keep exploring until you've thoroughly tested the page or hit a dead end."""


async def _extract_interactive_elements(page: object) -> str:
    """Extract a summary of interactive elements on the page."""
    try:
        elements = await page.evaluate("""() => {
            try {
                const els = [];
                const interactives = document.querySelectorAll(
                    'a[href], button, input, select, textarea, [role="button"], [role="tab"], ' +
                    '[role="link"], [onclick], details > summary, [data-action]'
                );
                const seen = new Set();
                for (const el of interactives) {
                    if (els.length >= """ + str(MAX_INTERACTIVE_ELEMENTS) + """) break;
                    try {
                        const style = getComputedStyle(el);
                        if (style.display === 'none' || style.visibility === 'hidden') continue;
                    } catch(e) { continue; }
                    const desc = {
                        tag: el.tagName.toLowerCase(),
                        type: el.type || '',
                        text: (el.innerText || el.value || el.placeholder || '').slice(0, 50),
                        href: el.href || '',
                        name: el.name || '',
                        id: el.id || '',
                        role: el.getAttribute('role') || '',
                    };
                    const key = JSON.stringify(desc);
                    if (seen.has(key)) continue;
                    seen.add(key);
                    els.push(desc);
                }
                return els;
            } catch(e) { return []; }
        }""")  # type: ignore[attr-defined]
        lines = []
        for el in elements:
            parts = [f"<{el['tag']}"]
            if el.get('type'):
                parts.append(f" type={el['type']}")
            if el.get('id'):
                parts.append(f" id={el['id']}")
            if el.get('name'):
                parts.append(f" name={el['name']}")
            if el.get('role'):
                parts.append(f" role={el['role']}")
            parts.append(">")
            if el.get('text'):
                parts.append(f" \"{el['text']}\"")
            if el.get('href'):
                parts.append(f" href={el['href'][:80]}")
            lines.append("".join(parts))
        return "\n".join(lines) if lines else "(no interactive elements found)"
    except Exception:
        return "(error extracting elements)"


def _parse_agent_action(response: str) -> dict | None:
    """Robustly extract a JSON action from LLM response. Returns None on failure."""
    text = response.strip()
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try extracting from markdown code block
    if "```" in text:
        for block in re.findall(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL):
            try:
                return json.loads(block.strip())
            except json.JSONDecodeError:
                continue
    # Try finding first { ... } pair with brace matching
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    start = -1
    return None


async def _run_agent(
    agent_id: int,
    node: Node,
    llm: LLMProvider,
    pool: BrowserPool,
    config: ExploreConfig,
    base_url: str,
    run_dir: Path,
    semaphore: asyncio.Semaphore,
    cost_tracker: CostTracker,
) -> list[SecurityFinding]:
    """Run a single LLM exploration agent on a node. Only does interactive exploration."""
    findings: list[SecurityFinding] = []

    async with semaphore:
        context = await pool.new_context()
        try:
            page = await context.new_page()
            console_log: list[str] = []

            def on_console(msg: object) -> None:
                if len(console_log) < 100:  # Bounded buffer (Adversarial fix)
                    console_log.append(f"[{msg.type}] {msg.text}")  # type: ignore[attr-defined]
            page.on("console", on_console)

            # Navigate to the node
            try:
                await page.goto(node.state.url, wait_until="networkidle", timeout=PAGE_LOAD_TIMEOUT_MS)
            except Exception as e:
                logger.warning("Agent %d: failed to load %s: %s", agent_id, node.state.url, e)
                return findings

            # LLM-driven exploration loop
            messages: list[dict] = []
            actions_taken = 0
            for action_num in range(config.max_actions_per_agent):
                # Cost limit check (Good Friend fix)
                if cost_tracker.total_cost >= config.cost_limit_usd:
                    logger.warning("Agent %d: cost limit ($%.2f) reached, stopping", agent_id, config.cost_limit_usd)
                    break

                # Gather current page state
                try:
                    url = page.url
                    title = await page.title()
                    raw_text = await page.evaluate("() => document.body?.innerText?.slice(0, 3000) || ''")
                    text = _sanitize_for_prompt(raw_text, MAX_PAGE_TEXT_CHARS)
                except Exception:
                    logger.warning("Agent %d: failed to read page state on action %d", agent_id, action_num)
                    break

                elements_str = await _extract_interactive_elements(page)
                recent_console = console_log[-MAX_CONSOLE_LINES:]
                console_str = "\n".join(recent_console) if recent_console else "(none)"
                console_log.clear()

                observation = (
                    f"URL: {url}\nPage title: {title}\n"
                    f"Visible text (first {MAX_PAGE_TEXT_CHARS} chars): {text}\n\n"
                    f"Interactive elements:\n{elements_str}\n\n"
                    f"Console messages since last action:\n{console_str}\n\n"
                    f"Choose your next action."
                )

                messages.append({"role": "user", "content": observation})

                # Ask LLM for next action
                try:
                    response = await llm.complete(_AGENT_SYSTEM, messages, max_tokens=1024)
                    messages.append({"role": "assistant", "content": response})
                except Exception as e:
                    logger.warning("Agent %d: LLM call failed: %s", agent_id, e)
                    break

                # Parse action (robust parsing -- Adversarial fix)
                action = _parse_agent_action(response)
                if action is None:
                    logger.debug("Agent %d: failed to parse action from LLM response", agent_id)
                    continue  # Skip this turn, don't abort the whole agent

                action_type = action.get("action", "done")
                reason = action.get("reason", "")

                if action_type == "done":
                    break

                # Check for agent-reported issues in the reason
                issue_keywords = ["broken", "error", "missing", "truncated", "overlapping",
                                  "can't", "doesn't work", "failed", "empty", "wrong"]
                if any(kw in reason.lower() for kw in issue_keywords):
                    findings.append(SecurityFinding(
                        category=SecurityCategory.exploration,
                        severity=SecuritySeverity.medium,
                        title=f"Agent observed: {reason[:MAX_TITLE_CHARS]}",
                        detail=f"Exploration agent #{agent_id} reported an issue while testing {url}",
                        evidence=f"action={action_type}",
                        url=url,
                        auth_context=AuthContext.anonymous,
                    ))

                # Execute action with validation (Red Team fixes)
                try:
                    if action_type == "click":
                        selector = action.get("selector", "")
                        if not _validate_selector(selector):
                            logger.debug("Agent %d: rejected unsafe selector: %s", agent_id, selector[:50])
                            continue
                        await page.click(selector, timeout=INTERACTION_TIMEOUT_MS)
                        await page.wait_for_load_state("networkidle", timeout=NETWORKIDLE_TIMEOUT_MS)
                    elif action_type == "fill":
                        selector = action.get("selector", "")
                        value = action.get("value", "")
                        if not _validate_selector(selector):
                            continue
                        if len(value) > 1000:
                            value = value[:1000]
                        await page.fill(selector, value, timeout=INTERACTION_TIMEOUT_MS)
                    elif action_type == "scroll":
                        direction = action.get("direction", "down")
                        delta = SCROLL_DELTA_PX if direction == "down" else -SCROLL_DELTA_PX
                        await page.mouse.wheel(0, delta)
                        await asyncio.sleep(SCROLL_SETTLE_S)
                    else:
                        logger.debug("Agent %d: unknown action type: %s", agent_id, action_type)
                        continue

                    actions_taken += 1
                except Exception as e:
                    findings.append(SecurityFinding(
                        category=SecurityCategory.exploration,
                        severity=SecuritySeverity.low,
                        title=f"Agent action failed: {action_type}",
                        detail=f"Action on {action.get('selector', 'N/A')[:50]} failed",
                        evidence=str(e)[:100],
                        url=url,
                        auth_context=AuthContext.anonymous,
                    ))

            logger.info("Agent %d: completed %d actions on %s, %d findings",
                        agent_id, actions_taken, node.id, len(findings))

        finally:
            await context.close()

    return findings


async def _run_computational_checks(
    graph: SiteGraph,
    pool: BrowserPool,
    run_dir: Path,
    semaphore: asyncio.Semaphore,
) -> list[SecurityFinding]:
    """Run contrast and hidden element checks ONCE across all nodes (Sage fix)."""
    findings: list[SecurityFinding] = []

    async def check_node(node: Node) -> list[SecurityFinding]:
        node_findings: list[SecurityFinding] = []
        async with semaphore:
            context = await pool.new_context()
            try:
                page = await context.new_page()
                try:
                    await page.goto(node.state.url, wait_until="networkidle", timeout=PAGE_LOAD_TIMEOUT_MS)
                except Exception:
                    return node_findings

                # Contrast (independent error handling -- Sage fix)
                try:
                    contrast = await check_contrast_from_page(page)
                    for f in contrast:
                        f.url = node.id
                        f.category = SecurityCategory.accessibility
                    node_findings.extend(contrast)
                except Exception as e:
                    logger.warning("Contrast check failed on %s: %s", node.id, e)

                # Hidden elements (independent)
                try:
                    hidden = await detect_hidden_elements(page)
                    for f in hidden:
                        f.url = node.id
                        f.category = SecurityCategory.visual
                    node_findings.extend(hidden)
                except Exception as e:
                    logger.warning("Hidden element check failed on %s: %s", node.id, e)

            finally:
                await context.close()
        return node_findings

    tasks = [check_node(node) for node in graph.nodes.values()]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            findings.extend(result)
        elif isinstance(result, Exception):
            logger.warning("Computational check failed: %s", result)

    return findings


async def _run_vision_analysis(
    graph: SiteGraph,
    llm: LLMProvider,
    run_dir: Path,
) -> list[SecurityFinding]:
    """Run LLM vision on screenshots ONCE per node (Sage fix)."""
    findings: list[SecurityFinding] = []
    for node in graph.nodes.values():
        for capture in node.captures:
            if capture.screenshot_path:
                screenshot_abs = run_dir / capture.screenshot_path
                if screenshot_abs.exists():
                    try:
                        vis = await analyze_screenshot(llm, screenshot_abs, node.id, capture.auth_context)
                        for f in vis:
                            f.category = SecurityCategory.visual
                        findings.extend(vis)
                    except Exception as e:
                        logger.warning("Vision analysis failed on %s: %s", node.id, e)
                    break  # One screenshot per node
    return findings


async def explore_site(
    config: WebprobeConfig,
    explore_config: ExploreConfig,
    graph: SiteGraph,
    run_dir: Path,
) -> tuple[list[SecurityFinding], PhaseStatus, CostTracker]:
    """Phase 5: LLM-driven exploration of the site.

    Three stages, each independent:
    1. Computational checks (contrast, hidden elements) -- once across all nodes
    2. LLM vision analysis -- once per node screenshot
    3. LLM interactive exploration -- agents explore interactively
    """
    phase = PhaseStatus(
        phase="explore",  # type: ignore[arg-type]
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    start = time.monotonic()

    cost_tracker = CostTracker()
    llm = create_provider(
        provider=explore_config.provider,
        model=explore_config.model,
        cost_tracker=cost_tracker,
    )

    mask = load_mask(explore_config.mask_path)
    semaphore = asyncio.Semaphore(explore_config.concurrency)
    all_findings: list[SecurityFinding] = []

    async with BrowserPool(config.capture) as pool:
        # Stage 1: Computational checks (fast, no LLM, run once)
        if explore_config.scan_mode in (ScanMode.full, ScanMode.visual):
            logger.info("Running computational checks across %d nodes...", len(graph.nodes))
            comp_findings = await _run_computational_checks(graph, pool, run_dir, semaphore)
            all_findings.extend(comp_findings)
            logger.info("Computational checks: %d findings", len(comp_findings))

        # Stage 2: LLM vision analysis (one call per node, run once)
        if explore_config.scan_mode in (ScanMode.full, ScanMode.visual):
            logger.info("Running vision analysis...")
            vis_findings = await _run_vision_analysis(graph, llm, run_dir)
            all_findings.extend(vis_findings)
            logger.info("Vision analysis: %d findings", len(vis_findings))

        # Stage 3: LLM interactive exploration (agents)
        if explore_config.scan_mode in (ScanMode.full, ScanMode.explore_only):
            logger.info("Launching %d exploration agents...", min(len(graph.nodes), explore_config.concurrency))
            tasks = []
            for i, node in enumerate(graph.nodes.values()):
                tasks.append(_run_agent(
                    agent_id=i,
                    node=node,
                    llm=llm,
                    pool=pool,
                    config=explore_config,
                    base_url=graph.root_url,
                    run_dir=run_dir,
                    semaphore=semaphore,
                    cost_tracker=cost_tracker,
                ))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            agent_findings = 0
            agent_errors = 0
            for result in results:
                if isinstance(result, list):
                    all_findings.extend(result)
                    agent_findings += len(result)
                elif isinstance(result, Exception):
                    agent_errors += 1
                    logger.warning("Agent failed: %s", result)

            logger.info("Exploration: %d findings, %d agent errors", agent_findings, agent_errors)

    # Apply mask
    kept, suppressed = apply_mask(all_findings, mask)
    if suppressed:
        logger.info("Masked %d findings", len(suppressed))

    duration = (time.monotonic() - start) * 1000
    phase.status = "completed"
    phase.completed_at = datetime.now(timezone.utc).isoformat()
    phase.duration_ms = duration

    return kept, phase, cost_tracker
