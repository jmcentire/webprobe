# webprobe Phase 5: LLM Exploratory Agent Layer

## Task

Add an LLM-driven exploration layer to webprobe that runs after the mechanical pipeline (Phases 1-4). Multiple concurrent browser agents, each driven by an LLM with vision capabilities, autonomously discover and test UI features, identify visual defects, and probe for behavioral issues that mechanical scanning cannot detect.

## Context

webprobe v0.1.0 has a four-phase mechanical pipeline: map (BFS crawl), capture (Playwright resource/timing/security collection), analyze (graph metrics, security findings), report (JSON+HTML). This works for structural and header-level issues but cannot:
- Detect visual defects (low-contrast text, broken layouts, elements hidden via CSS)
- Reason about interactive flows (multi-step forms, modal dialogs, JS-driven navigation)
- Test adversarial inputs against forms (XSS payloads, boundary values)
- Discover SPA state that isn't reachable via static link crawling

The LLM layer adds intelligent agents that receive the mechanical graph + captures and explore/test beyond what crawling finds.

## Constraints

- LLM provider must be configurable: Claude API (default), OpenAI, Gemini, Apprentice (local routing)
- Concurrency must be user-configurable; warn and require confirmation above a configurable threshold (default 20)
- Agents must use transmogrifier for prompt normalization before LLM calls
- Visual inspection must include: color contrast checking (WCAG AA/AAA), hidden-but-present element detection, layout anomaly flagging via screenshot analysis
- A "mask" system must exist for expected visual issues (known broken things the user wants to suppress)
- All findings must integrate into the existing report schema (SecurityFinding model with appropriate categories)
- No destructive actions: agents must not submit real data, delete things, or trigger irreversible state changes
- Cost tracking: every LLM call must be logged with token counts and estimated cost
- Apprentice integration: optional, for future CI/CD use where local model handles routine checks and frontier model handles novel situations

## Requirements

- Phase 5 runs after Phase 4 (or independently via `webprobe explore <run-dir>`)
- Agents receive the site graph, captures, and security findings as context
- Each agent gets a Playwright browser and an LLM to decide actions
- Coverage engine tracks explored states and assigns frontier work to idle agents
- Visual analysis uses LLM vision (screenshot analysis) + computational checks (contrast ratios)
- Mask file (YAML) lets users suppress known issues by URL pattern + finding pattern
- Findings feed into the existing AnalysisResult and HTML report
- Cost summary in report: total tokens, total estimated cost, per-agent breakdown
