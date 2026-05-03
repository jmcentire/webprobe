# webprobe — Multi-Dimensional Site Audit Pipeline

> Status: planning. The full check inventory and per-dimension breakdown lives
> in `docs/AUDIT_DIMENSIONS.md`. Constraints in `constraints.yaml`. Trust
> policy in `trust_policy.yaml`. Component map in `component_map.yaml`.
> Schema hints in `schema_hints.yaml`.

## System Context

webprobe is a Playwright-based site state-graph auditor. The original tool maps
any website as a directed graph, captures per-node DOM/headers/console/screenshots
via Playwright, scans for security issues, and produces aggregatable JSON+HTML
reports with a stable schema. An optional Phase 5 runs LLM-driven exploration
agents to find visual and behavioral defects.

This expansion adds a multi-dimensional audit pipeline on top of the existing
capture infrastructure. Where the original tool emitted a single
`SecurityFinding` stream, the expanded tool emits a unified `CheckResult`
stream across 9 audit dimensions, aggregated into a scorecard that operators
gate PRs on, monitor against, and use to replace the patchwork of
single-purpose third-party scanners they currently run separately
(Lighthouse, axe, ZAP, Cloudflare isitagentready.com, Shopify product check,
Stripe API Reviews).

Two audiences:

1. **Local developers** running webprobe against their own properties for
   pre-launch checks and exploratory audits.
2. **CI/CD pipelines** running webprobe with `--mechanical-only` (no LLM key
   needed) for PR gating with per-dimension thresholds.

## Consequence Map

**If the unified CheckResult schema drifts** (CO001, CA001):
- Dimensions diverge in subtle ways → unified scorecard breaks
- Cross-run diffs and aggregation pipelines fail silently
- Reporter can't render consistent HTML/JSON

**If the shared Artifact store contract is violated** (CA003, CA004):
- Per-dimension artifact copies cause divergent interpretations of the same
  root data
- A single missing artifact (e.g. robots.txt 503) cascades into FAILs across
  multiple dimensions instead of one consistent NOT_DETECTED

**If mechanical-only mode breaks** (CA007):
- PR gating in CI without LLM budget becomes impossible
- Operators in airgapped environments cannot use the tool

**If webprobe applies fixes itself** (CA009):
- Read-only invariant (CO002) is broken
- Fix conflicts between dimensions become webprobe's problem to resolve
- Operators lose control over what changes their site

**If LLM judgment checks are unstable** (CA024):
- PR builds flap on borderline narrative-quality calls
- CI trust erodes; the check gets disabled

**If the scorecard rolls everything into one number** (CA012):
- False precision; one critical failure averages out behind seven passes
- Different audiences (security/SRE/marketing) lose their ability to gate on
  what they care about

## Failure Archaeology

- Phase 2 (capture) timing out on slow pages — must degrade per-node, not
  abort the run; this same principle now extends to per-artifact missing
  data (CA004).
- LLM agents hallucinating findings — severity levels and the mask system
  remain the escape valves; `temperature=0` + consensus-of-N (CA024) is the
  new stability lever for judgment checks specifically.
- Schema drift breaking diff/trending — schema_version bump discipline
  (CO001) now extends to CheckResult, Artifact, Fix, and Scorecard.
- Existing `security.py` was a monolith; was already being decomposed into a
  `security/` package — that pattern continues into the per-dimension
  analyzer layout under `src_webprobe_analyzer/<dimension>/`.

## Dependency Landscape

- **Playwright** (Apache 2.0): browser automation. Required for capture and
  for the runtime-mode checks (WebMCP detection, Markdown content negotiation
  under JS rendering, accessibility via axe-core injection).
- **networkx** (BSD): graph algorithms.
- **aiohttp** (Apache 2.0): mechanical HTTP probing without browser.
- **Anthropic / OpenAI / Google SDKs**: LLM providers, behind the
  `LLMProvider` abstraction (CO006).
- **transmogrifier**: optional prompt normalization (CO007).
- **axe-core**: WCAG ruleset for the accessibility dimension (script
  injection via Playwright; no Python dep).
- **External reference scans** are *inputs to the spec*, not runtime
  dependencies: Cloudflare isitagentready.com, Shopify agent-discoverability,
  Stripe API Reviews. Webprobe does not call their services.

There is no integration with Arbiter, Baton, Sentinel, Ledger, or any other
peer project. Webprobe's `constraints.yaml`/`trust_policy.yaml` are scoped to
webprobe itself (Pact contract scaffold).

## Boundary Conditions

- **Read-only observer** (CO002, CA009): webprobe never submits real data,
  never clicks delete/cancel/remove, never applies fixes.
- **Local-first** (CA015): runs write to `runs/<timestamp>/`. No server, no
  DB, no external transmission.
- **Mechanical-only viable** (CA007): pipeline produces a useful scorecard
  with no LLM API key; LLM-only checks return SKIPPED, hybrid checks fall
  back to their mechanical precondition only.
- **Generic by default** (CO013): works on any URL; framework detection is
  optional enrichment.
- **Stable schema** (CO001): version bump required on any field change to
  Run, SiteGraph, Node, Edge, AnalysisResult, CheckResult, Artifact, or
  Scorecard.
- **Auth secret hygiene** (CO008): credentials never appear in reports,
  evidence, or artifacts; mask redacts before write.
- **License compatibility** (CO009): MIT/Apache 2.0/BSD only.

Maximum 500 nodes per crawl (configurable). Maximum 20 actions per LLM
exploration agent per node. Concurrency warning at 20 agents (CO004).

## Success Shape

A successful webprobe run with the audit expansion:

1. **Phases 1–2 (Map + Capture)**: produces a single canonical Artifact
   store containing one robots.txt, one OpenAPI document (if any), one DOM
   per URL, one JSON-LD extraction per URL, one set of headers per URL,
   one set of `/.well-known/*` probes (CA003).
2. **Phase 3 (Analyze)**: original graph metrics, broken links, auth
   boundary violations, timing outliers (preserved).
3. **Phase 3.5 (Audit)**: scheduler runs the 9 dimension analyzers against
   the Artifact store; mechanical and runtime checks parallelize, LLM checks
   resolve topologically by declared `check_dependencies` (CA013). Each
   produces a `list[CheckResult]` under the unified schema.
4. **Phase 4 (Score + Report)**: scorecard aggregates CheckResults into per-
   dimension subscores and bands plus an overall band (CA010, CA012, CA023).
   Reporter renders JSON, HTML, and scorecard.json. Fix recommendations are
   structured (`Fix(action_type, target, payload, summary, references)`,
   CA008) and emitted only — never applied (CA009).
5. **Phase 5 (Explore, optional)**: existing LLM-driven exploration agents
   continue to operate; their findings flow through the same CheckResult
   schema.
6. **Costs are predictable and visible** (CO003).
7. **Mechanical-only runs** produce a useful, gating-quality scorecard with
   no LLM API key (CA007).

## Done When

- [ ] `models.py` extended with CheckResult, Artifact, Fix, Scorecard, Evidence
      variants matching `schema_hints.yaml`
- [ ] `artifact_store.py` and shared parsers (robots_txt, sitemap, openapi,
      json_ld, meta_tags) implemented; capturer writes into the store
- [ ] DAG scheduler honors `mode` (mechanical/llm/hybrid/runtime) and
      mechanical-only mode (CA006, CA007, CA013, CA014)
- [ ] Scorecard aggregator implements per-dimension subscore + band + overall
      band per CA023 mapping
- [ ] Existing `security.py` migrated to emit CheckResult under
      `general_security` dimension
- [ ] All 9 dimension analyzers implemented to v1 check inventories from
      `docs/AUDIT_DIMENSIONS.md`:
      1. Discoverability
      2. Bot Access & Identity
      3. Agent Surface (well-known + WebMCP runtime)
      4. API Surface (OpenAPI presence + Stripe-style mechanical patterns +
         OWASP subset + hybrid LLM judgments)
      5. Structured Data (schema.org Product/Article/FAQ/Recipe/Org/Rating)
      6. Agentic Commerce (x402/MPP/UCP/ACP)
      7. Public-Facing Signals (mechanical: SEO meta + OG/Twitter; LLM:
         hero/CTA/copy/trust)
      8. Accessibility (axe-core via Playwright)
      9. General Security (migrated from existing security.py + extensions)
- [ ] Each dimension has a paired contract under `contracts/<dimension>/`
      pinning inputs, outputs, invariants, and tests (CA022)
- [ ] CLI exposes `--mechanical-only`, `--dimension <name>`, and
      `--emit-fixes-json`
- [ ] HTML report has per-dimension sections; JSON report includes scorecard
- [ ] End-to-end test against `reeve.tools` (real site) and one
      intentionally-broken fixture site
- [ ] Evidence redaction (CO008, CA005) verified — no AUTH-tier headers or
      cookies appear in any written artifact

## Trust and Authority Model

- **Mechanical, runtime, and structured-data dimensions**: deterministic;
  trusted; no API keys needed.
- **LLM-judgment sub-passes** (Public-Facing Signals copy quality, API
  Surface hierarchy review): non-deterministic; advisory; consensus-of-N
  for stability when gating CI (CA024).
- **Auth credentials**: user-provided, never logged in reports or evidence
  (CO008, CA005).
- **Target site**: treated as untrusted; XSS in page content must not
  execute in webprobe's context.

Per-dimension authority is in `trust_policy.yaml`. Field-level classifications
distinguish PUBLIC (default), PII (synthetic-only via CO002, with mask
catching real-PII leaks), AUTH (never in reports), and COMPLIANCE (audit
findings; internal until reviewed).

## Component Topology

```
CLI
 ├── Config (incl. ai_user_agent_matrix, per-dim thresholds)
 ├── Mapper ──── Frameworks
 │   └── Auth
 ├── Capturer
 │   ├── Browser Pool
 │   ├── Auth
 │   ├── Mask (redacts AUTH/PII before write)
 │   └── ArtifactStore (canonical, shared)
 │       └── Parsers (robots_txt, sitemap, openapi, json_ld, meta_tags)
 ├── Analyzer (graph metrics, broken links, etc. — preserved)
 │   └── Security (extended: emits CheckResult under general_security)
 ├── Scheduler (DAG; mode-aware; mechanical-only honoring)
 │   ├── DiscoverabilityAnalyzer
 │   ├── BotAccessAnalyzer
 │   ├── AgentSurfaceAnalyzer (uses Browser for WebMCP runtime)
 │   ├── APISurfaceAnalyzer (uses LLMProvider for hybrid checks)
 │   ├── StructuredDataAnalyzer
 │   ├── AgenticCommerceAnalyzer
 │   ├── PublicFacingSignalsAnalyzer (uses LLMProvider)
 │   └── AccessibilityAnalyzer (uses Browser for axe-core injection)
 ├── Scorecard (per-dim subscore + band + overall band)
 ├── Explorer (optional Phase 5; LLM exploration; preserved)
 │   ├── LLM Provider
 │   ├── Visual Analyzer
 │   └── Mask
 ├── Reporter (renders CheckResult + Scorecard; renders Fixes without applying)
 └── Differ (cross-run trending; preserved)
```

The 9 dimensions correspond to sibling packages under `src/webprobe/<dimension>/`,
following the same pattern as the existing `webprobe.security` package
(General Security is `webprobe.security` extended to dual-emit, not a new
package). Each dimension implements the uniform interface
`run(artifact_store, config) -> list[CheckResult]`.

webprobe uses the Pact decomposition pattern: real implementation under
`src/webprobe/<module>/`, public-API mirror under
`src/src_webprobe_<module>/<module>.py`, contract artifacts under
`contracts/src_webprobe_<module>/`, contract tests under
`tests/src_webprobe_<module>/`. The 16 existing modules already follow
this layout; new dimensions add to it.

## Architectural Pillars (the load-bearing decisions)

These are restated from `constraints.yaml` because they're the easy ones to
forget under expansion pressure:

1. **One CheckResult schema across every dimension.** No per-dimension result
   shapes. (CA001)
2. **Trinary status + SKIPPED.** PASS / FAIL / NOT_DETECTED / SKIPPED.
   Boolean pass/fail collapses too many real cases. (CA002)
3. **Shared Artifact store; checks are lenses, not owners.** (CA003)
4. **NOT_DETECTED on missing artifact, never FAIL.** (CA004)
5. **Typed evidence union, never free-form.** (CA005)
6. **Mode enum drives the scheduler.** mechanical / llm / hybrid / runtime. (CA006)
7. **Mechanical-only is a first-class mode.** (CA007)
8. **Fix recommendations are structured; webprobe never applies them.** (CA008, CA009)
9. **Dimension-internal weight; severity orthogonal.** (CA010, CA011)
10. **Per-dimension subscore + overall band; never one rolled-up number.** (CA012)
11. **DAG scheduler with explicit check_dependencies for cross-check LLM ordering.** (CA013)
12. **Hybrid precondition fail → NOT_DETECTED, never silent fallback.** (CA014)
13. **Local-first; no server, no DB.** (CA015)
14. **Configurable AI user-agent matrix; default v1 list pinned in constraints.** (CA016)
15. **Shared parsers (robots, OpenAPI, JSON-LD, meta tags); no duplicates.** (CA017)
16. **Pact contract per dimension under `contracts/<dimension>/`.** (CA022)
17. **Explicit overall-band mapping in `docs/AUDIT_DIMENSIONS.md`; operator-overridable.** (CA023)
18. **temperature=0 + consensus-of-N for LLM checks gating CI.** (CA024)
