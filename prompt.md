# webprobe — Site State-Graph Auditor with LLM Exploration

## System Context

webprobe is a generic website testing tool that maps any site as a directed graph, captures detailed per-node metrics via headless browsers, scans for security vulnerabilities, and uses LLM-driven agents to discover visual defects and behavioral issues. It produces aggregatable JSON reports with a stable schema for cross-run diffing and trending.

The tool targets two audiences: (1) individual developers testing their own sites during development, and (2) CI/CD pipelines running automated regression checks against staging/production. It must be cheap to run mechanically and provide clear cost controls when LLM exploration is enabled.

## Consequence Map

**If the mechanical pipeline (Phases 1-4) is unreliable:**
- False positives erode trust → users ignore real findings
- False negatives miss real issues → defeats the purpose
- Slow or flaky runs → gets disabled in CI/CD

**If the LLM exploration (Phase 5) is uncontrolled:**
- Runaway API costs → surprise bills
- Destructive agent actions → data loss on the target site
- Poor prompt quality → hallucinated findings that waste developer time

**If the report schema drifts:**
- Cross-run diffs break → aggregation pipeline fails
- Historical data becomes incomparable → trending useless

## Failure Archaeology

- Phase 2 (capture) can timeout on slow pages → must degrade gracefully per-node, not abort the run
- LLM agents may hallucinate findings → severity levels and mask system provide escape valves
- Concurrent browser contexts consume memory → semaphore-based throttling is load-bearing
- Cookie/session auth expires mid-run → auth errors should be detected and reported, not silently ignored

## Dependency Landscape

- **Playwright** (Apache 2.0): Browser automation. Breaking changes in their API would require capturer.py and browser.py updates.
- **networkx** (BSD 3-Clause): Graph algorithms. Stable, minimal API surface used.
- **aiohttp** (Apache 2.0): HTTP crawling. Only used in mapper.py.
- **Anthropic/OpenAI/Google SDKs**: LLM providers. Each behind the LLMProvider abstraction, so provider-specific changes are isolated.
- **transmogrifier**: Prompt normalization. Graceful degradation if unavailable.
- **Pillow**: Image processing for visual analysis. Optional.

## Boundary Conditions

- Maximum 500 nodes per crawl (configurable, prevents runaway crawls)
- Maximum 20 actions per exploration agent per node (prevents infinite loops)
- Concurrency warning threshold at 20 agents (prevents accidental cost explosion)
- Schema version pinned, must be bumped on breaking changes
- All LLM calls logged with token counts and estimated cost
- No destructive actions: agents use fake test data, never click delete/remove

## Success Shape

A successful webprobe run:
1. Maps all reachable pages (both auth and anon contexts)
2. Captures timing, resources, headers, cookies, and forms for each page
3. Identifies real security issues (missing headers, auth boundary violations, broken links)
4. When explore is enabled: finds visual defects and behavioral issues humans would notice
5. Produces a report that is actionable without explanation
6. Costs are predictable and visible

## Trust and Authority Model

- **Mechanical pipeline** (Phases 1-4): Trusted, deterministic, no API keys needed
- **LLM exploration** (Phase 5): Untrusted output, all findings are advisory, mask system for false positives
- **Auth credentials**: User-provided, never logged in reports (config snapshot excludes secrets)
- **Target site**: Treated as untrusted (XSS in page content must not execute in our context)

## Component Topology

```
CLI (cli.py)
 ├── Config (config.py)
 ├── Mapper (mapper.py) ──── Frameworks (frameworks.py)
 │    └── Auth (auth.py)
 ├── Capturer (capturer.py)
 │    ├── Browser Pool (browser.py)
 │    └── Auth (auth.py)
 ├── Analyzer (analyzer.py)
 │    └── Security Scanner (security.py)
 ├── Explorer (explorer.py)
 │    ├── LLM Provider (llm_provider.py)
 │    ├── Visual Analyzer (visual.py)
 │    └── Mask (mask.py)
 ├── Reporter (reporter.py)
 └── Differ (differ.py)
```
