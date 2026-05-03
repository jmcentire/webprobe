# Webprobe — Audit Dimensions Plan

> Status: planning. This document is the canonical spec for the multi-dimensional
> audit expansion. It supersedes scattered notes in `docs/audit-prime/` (those
> are the priming inputs).

## 1. Goal

Extend webprobe from a single-dimension security/SEO auditor into a comprehensive
multi-dimensional site auditor that produces a unified scorecard across 9 audit
dimensions. The scorecard replaces the patchwork of single-purpose scanners
(Lighthouse, axe, ZAP, Cloudflare isitagentready.com, Shopify product check,
Stripe API Reviews) site operators currently piece together.

Audience: site operators (engineers, SREs, marketing) running webprobe against
their own properties — locally, in CI for PR gating, and on a cadence for
ongoing monitoring.

## 2. Architectural Contracts

These are the load-bearing decisions. Pinned by `constraints.yaml`; spec'd here.

### 2.1 Unified `CheckResult`

Every dimension analyzer returns `list[CheckResult]`. Fields (see
`schema_hints.yaml` for full schema):

- `dimension`, `check_id`, `title`, `goal`
- `status` ∈ {PASS, FAIL, NOT_DETECTED, SKIPPED}
- `severity` ∈ {critical, warning, suggestion, info}
- `mode` ∈ {mechanical, llm, hybrid, runtime}
- `weight` (dimension-internal, sums to 1.0 within a dimension)
- `evidence` (typed union: HttpExchange, DomExcerpt, RuntimeProbe, ArtifactRef)
- `fix` (structured `Fix(action_type, target, payload, summary, references)`,
  required when status ∈ {FAIL, NOT_DETECTED})
- `references` (RFC numbers, vendor docs)
- `check_dependencies` (only for LLM-dependent checks)
- `elapsed_ms`

Severity is orthogonal to weight. Severity drives prioritization; weight drives
scoring within the dimension.

### 2.2 Shared Artifact Store

The capture phase produces a single canonical `ArtifactStore` (`CA003`). One
robots.txt, one OpenAPI document, one DOM-per-URL, one JSON-LD-per-URL. All
dimensions read from it; nobody copies. `CheckResult.evidence` references
artifacts by id and excerpt, not by full payload.

When an artifact failed to capture:

- The Artifact has `capture_status != ok` and `capture_error` populated.
- Every dependent check returns `status=NOT_DETECTED`,
  `reason="artifact_unavailable:<artifact_id>:<why>"` (`CA004`).
- No cascade of FAILs; no inconsistent NOT_DETECTED-vs-FAIL across dimensions
  for one root cause.

Shared parsers (`CA017`): one robots.txt parser, one OpenAPI loader, one JSON-LD
extractor, one meta-tag/OG/Twitter Card extractor. Dimensions consume the
parsed forms.

### 2.3 Mode Enum

Each check declares its mode (`CA006`):

| Mode | Meaning | Behavior in `--mechanical-only` |
|---|---|---|
| `mechanical` | Pure deterministic check | Runs |
| `llm` | LLM judgment, no deterministic precondition | SKIPPED |
| `hybrid` | Deterministic precondition + LLM judgment | Runs precondition; if it passes, the LLM half is SKIPPED |
| `runtime` | Requires Playwright (e.g. WebMCP detection) | Runs |

`CA007`: pipeline must produce a useful scorecard with no LLM API key. LLM-only
dimensions become mostly SKIPPED but the mechanical sub-passes still run.

### 2.4 DAG Scheduler

Mechanical and runtime checks parallelize from the Artifact store up to a
concurrency cap. LLM checks declare `check_dependencies` for cases like:
"value-prop extraction → CTA alignment evaluation." The scheduler resolves
topologically and forbids cycles (`CA013`). Most LLM checks have no
dependencies.

### 2.5 Hybrid Failure Semantics

When a hybrid check's deterministic precondition fails, the check returns
`NOT_DETECTED` with `reason="precondition_failed:<which>"` (`CA014`). Never
silent fall-back to a different analysis.

### 2.6 Fix Recommendations: Emit Only

`CA009`: webprobe never applies fixes. Fix recommendations are structured for
downstream consumers (a remediation agent the operator runs separately). Fix
conflicts between dimensions ("allow AI bots" vs "rate-limit crawlers for
perf") are not webprobe's problem; the consuming agent or human reconciles.

### 2.7 Scorecard

`CA010`/`CA012`/`CA023`: per-dimension subscore (0-100) + per-dimension band +
overall band. No single rolled-up overall numeric score. Default v1 band
mapping:

| Band | Rule |
|------|------|
| L5 | All dimensions ≥ 80 |
| L4 | No dimension < 60 AND majority ≥ 80 |
| L3 | No dimension < 40 |
| L2 | No critical dimension < 20 |
| L1 | Baseline (any check ran) |

Mapping is operator-overridable in config.

### 2.8 LLM Stability

`CA024`: LLM-judgment checks use `temperature=0` and consensus-of-N (default
N=3, majority) when their results gate PR builds. Prevents flapping CI failures
on borderline narrative-quality calls.

### 2.9 Local-First Storage

`CA015`: a run writes to `runs/<timestamp>/{artifacts/, captures/, checks/,
report.html, report.json, scorecard.json}`. No server, no DB, no transmission.
Deletion is `rm -rf runs/<id>`. Hosted/multi-tenant operation is explicitly out
of scope for v1.

## 3. The 9 Dimensions

Module layout: `src/src_webprobe_analyzer/<dimension>/{__init__.py, checks.py,
parsers.py?, contract.py?}` with the uniform interface
`run(artifact_store, config) -> list[CheckResult]`. Each dimension has a paired
contract under `contracts/<dimension>/` (`CA022`).

### Dimension 1 — Discoverability

Goal: can search engines and AI agents find your stuff at all?

**v1 checks** (mode in parens):

- `discoverability.robots_txt_present` (mechanical) — 200 + valid format
- `discoverability.robots_txt_user_agent_directive` (mechanical) — has at least one User-agent rule
- `discoverability.sitemap_referenced` (mechanical) — Sitemap directive in robots.txt
- `discoverability.sitemap_valid` (mechanical) — fetch + valid XML
- `discoverability.link_headers_present` (mechanical) — RFC 8288 Link headers on homepage
- `discoverability.llms_txt_present` (mechanical) — `/llms.txt` reachable
- `discoverability.llms_txt_structured` (mechanical) — markdown headings + sections
- `discoverability.content_signals_directives` (mechanical) — `Content-Signal:` in robots.txt
- `discoverability.markdown_negotiation` (runtime) — `Accept: text/markdown` returns `text/markdown`

**v2 backlog**: RSS/Atom, JSON Feed, well-known/security.txt, manifest.json
links, hreflang sitemap variants.

**Required artifacts**: `robots_txt`, `sitemap`, homepage HTTP exchange,
`/llms.txt` HTTP exchange.

**References**: RFC 9309 (robots), sitemaps.org, RFC 8288 (Link), llms.txt
spec, contentsignals.org.

### Dimension 2 — Bot Access & Identity

Goal: explicit policy for AI bots, and is this site a bot itself?

**v1 checks**:

- `bot_access.ai_bot_matrix` (mechanical) — evaluate the configurable
  AI/search user-agent matrix (`CA016`). Each bot in the matrix → one
  sub-result (allowed/disallowed/no-rule). Aggregated into one CheckResult
  per matrix evaluation.
- `bot_access.web_bot_auth_directory` (mechanical) — fetch
  `/.well-known/http-message-signatures-directory`; valid JWKS structure

**v2 backlog**: per-path bot rule analysis, robots Crawl-delay, bot challenge
detection (Cloudflare/recaptcha gates that block agents).

**Required artifacts**: `robots_txt`, well-known JWKS HTTP exchange.

**References**: RFC 9309, IETF Web Bot Auth working group, Cloudflare docs.

### Dimension 3 — Agent Surface (well-known)

Goal: agent-facing discovery metadata at standard `/.well-known/` paths +
runtime browser tool exposure.

**v1 checks**:

- `agent_surface.api_catalog` (mechanical) — `/.well-known/api-catalog`
  returns `application/linkset+json` with `linkset` array + `service-desc`,
  `service-doc`, `status` link relations
- `agent_surface.openid_configuration` (mechanical) —
  `/.well-known/openid-configuration` valid + required fields
- `agent_surface.oauth_authorization_server` (mechanical) —
  `/.well-known/oauth-authorization-server` valid + required fields
- `agent_surface.oauth_protected_resource` (mechanical) —
  `/.well-known/oauth-protected-resource` (RFC 9728) valid
- `agent_surface.mcp_server_card` (mechanical) — try
  `/.well-known/mcp/server-card.json`, `mcp/server-cards.json`, `mcp.json`;
  validate `serverInfo`, transport, capabilities
- `agent_surface.agent_skills_index` (mechanical) —
  `/.well-known/agent-skills/index.json` valid; each skill has name, type,
  description, url, sha256
- `agent_surface.webmcp_runtime` (runtime) — Playwright loads page; checks
  for `navigator.modelContext.provideContext()` registrations

**v2 backlog**: `/.well-known/ai-plugin.json`, `/.well-known/anthropic`,
custom MCP capability fingerprinting.

**Required artifacts**: HTTP exchanges for each well-known path; for WebMCP a
RuntimeProbe(action="check navigator.modelContext").

**References**: RFC 9727, OpenID Connect Discovery, RFC 8414, RFC 9728,
SEP-2127, agentskills.io, webmachinelearning.github.io WebMCP.

### Dimension 4 — API Surface

Goal: is there an API; if so is it well-documented, well-designed, and secure?

This is the API mega-dimension that consolidates "API docs presence + quality,"
"Stripe-style design quality," and "OWASP API Top 10." All key off the same
artifact (OpenAPI document or sampled response set), so they share extraction.

**v1 mechanical checks (presence + Stripe patterns)**:

- `api_surface.openapi_present` — try `/openapi.json`, `/openapi.yaml`,
  `/v1/openapi.json`, `/swagger.json`
- `api_surface.docs_present` — try `/docs`, `/redoc`, `/swagger`, `/api-docs`
- `api_surface.openapi_valid` — schema validates
- `api_surface.openapi_examples_present` — operations/parameters have examples
- `api_surface.openapi_descriptions_present` — coverage of operation/parameter
  descriptions ≥ a configurable threshold
- `api_surface.error_schemas_defined` — error responses have schemas
- `api_surface.auth_schemes_documented` — at least one securityScheme defined
- `api_surface.identifier_prefixes` (`CA020`) — `*_id` fields use typed prefix
  pattern
- `api_surface.approved_status_codes` (`CA018`) — only approved set is used
- `api_surface.list_endpoint_empty_shape` (`CA019`) — list endpoints don't
  return 204 on empty
- `api_surface.pagination_has_more` — list responses include `has_more`
- `api_surface.resource_type_field` — responses include `object`/`type`/`kind`
- `api_surface.timestamp_format_unix_int` — datetime fields are integer seconds
- `api_surface.snake_case_naming` — fields are snake_case
- `api_surface.timestamp_naming_convention` — `<verb>ed_at` for past,
  `<verb>s_at` for future
- `api_surface.no_id_id_suffix` — no `*_id_id` patterns
- `api_surface.http_verb_conventions` — POST for create/update/upsert; PUT
  only for full-replace
- `api_surface.api_key_prefix` — auth examples use prefixed keys
- `api_surface.rate_limit_shape` — 429 with Retry-After + typed error code

**v1 hybrid checks (mechanical precondition + LLM judgment)**:

- `api_surface.resource_hierarchy_coherence` (hybrid) — precondition: OpenAPI
  reachable; LLM judges whether operations on the same logical resource share
  a path prefix
- `api_surface.boolean_vs_enum_extensibility` (hybrid) — LLM flags booleans
  that should be enums for forward extensibility
- `api_surface.docs_quality` (hybrid) — LLM judges descriptions are
  meaningful, examples are useful, error explanations are actionable

**v1 OWASP API Top 10 checks** (subset; full coverage v2):

- `api_surface.owasp_api1_bola` (mechanical, sampled) — IDOR-style probe on
  resource paths with predictable IDs (read-only; no destructive actions per
  CO002)
- `api_surface.owasp_api2_broken_auth` (mechanical) — auth-bypass on
  /me-style endpoints
- `api_surface.owasp_api4_unrestricted_consumption` (mechanical) — rate
  limiting present + reasonable
- `api_surface.owasp_api7_ssrf_surface` (mechanical) — endpoints that take
  URLs as input flagged for review
- `api_surface.owasp_api8_security_misconfiguration` (mechanical) — verbose
  error pages, debug headers, default credentials hints
- `api_surface.owasp_api9_inventory_management` (mechanical) — undocumented
  endpoints (in OpenAPI vs in sitemap/Link headers vs probed)

**v2 backlog**: full OWASP Top 10 coverage (API3, API5, API6, API10), GraphQL
introspection check, gRPC reflection check, deeper LLM analysis of auth flow
review.

**Required artifacts**: `openapi`, sampled `http_response`s for representative
endpoints.

**References**: Stripe API Reviews patterns (see
`docs/audit-prime/04-stripe-api-review.md`), OWASP API Security Top 10 (2023),
RFC 9457 (problem details).

### Dimension 5 — Structured Data

Goal: schema.org markup is present, valid, and complete enough for AI agents
to surface the page.

Generalizes the Shopify product check beyond products.

**v1 mechanical checks (per supported schema type)**:

- `structured_data.product_name_present` — `Product.name` ≤ 150 chars
- `structured_data.product_description_present` — `Product.description` ≥ 20 words
- `structured_data.product_image_present` — `Product.image`
- `structured_data.product_offer_price_present` — `Offer.price` + `priceCurrency`
- `structured_data.product_availability` — `Offer.availability` ∈ {InStock,
  OutOfStock, PreOrder}
- `structured_data.product_aggregate_rating` — `Product.aggregateRating`
- `structured_data.product_variants` — `hasVariant` / `isVariantOf` /
  `ProductGroup` with images + options (NOT_DETECTED if single-variant)
- `structured_data.organization_name` — `Organization.name`
- `structured_data.article_headline` — `Article.headline` ≤ 110 chars (where
  Article schema present)
- `structured_data.article_author` — `Article.author`
- `structured_data.article_datePublished`
- `structured_data.faqpage_questions` — `FAQPage.mainEntity` ≥ 1 question
- `structured_data.recipe_basics` — Recipe.name, recipeIngredient,
  recipeInstructions
- `structured_data.page_title_length` — HTML `<title>` 30–60 chars
- `structured_data.json_ld_validity` — JSON-LD parses; @context present

**v2 backlog**: Microdata + RDFa parsers, BreadcrumbList, Event, LocalBusiness,
Course, JobPosting, Review (standalone), Person, Place, schema.org structured
data testing-tool–style validation against full vocabularies.

**Required artifacts**: `dom` per URL, `json_ld` extracted by shared parser.

**References**: schema.org, Google Rich Results test (criteria reference only).

### Dimension 6 — Agentic Commerce

Goal: support for emerging agent-payment protocols.

**v1 mechanical checks** (informational — these protocols are early; absence
isn't penalized hard, but presence is recognized):

- `agentic_commerce.x402_payment_required` — endpoints respond 402 with
  payment requirements (probe likely API roots)
- `agentic_commerce.x402_bazaar_discovery` — `/platform/v2/x402/discovery/resources`
  or equivalent reachable
- `agentic_commerce.mpp_openapi_extensions` — `/openapi.json` includes
  `x-payment-info` extensions on payable operations
- `agentic_commerce.ucp_profile` — `/.well-known/ucp` profile present
- `agentic_commerce.acp_discovery` — `/.well-known/acp.json` valid;
  `protocol.name == "acp"`, `api_base_url`, transports, capabilities

**v2 backlog**: deeper protocol conformance per spec (lightning, tempo,
stripe-direct), payment-flow simulation in a sandbox.

**Required artifacts**: HTTP exchanges for each well-known path + sampled
API root.

**References**: x402.org, mpp.dev, ucp.dev, agenticcommerce.dev.

### Dimension 7 — Public-Facing Signals

Goal: SEO + marketing/copy quality + trust signals — same artifact, two
sub-passes (mechanical for slot presence; LLM for slot quality).

**v1 mechanical sub-pass**:

- `public_facing_signals.title_length` — 30–60 chars (overlap with structured-data
  page-title check; prefer keeping both — different dimensions, different
  audiences; reporter dedupes if both PASS)
- `public_facing_signals.meta_description_present` — present + 50–160 chars
- `public_facing_signals.canonical_url_present`
- `public_facing_signals.og_title_present`
- `public_facing_signals.og_description_present`
- `public_facing_signals.og_image_present`
- `public_facing_signals.og_image_dimensions` — recommended size
- `public_facing_signals.twitter_card_present` — `twitter:card` meta tag
- `public_facing_signals.twitter_title_present`
- `public_facing_signals.twitter_image_present`
- `public_facing_signals.heading_hierarchy` — exactly one h1; no skipped levels
- `public_facing_signals.alt_text_coverage` — % of images with non-empty
  meaningful alt
- `public_facing_signals.hreflang_consistency` — when present, hreflang
  declarations are mutually consistent
- `public_facing_signals.contact_page_reachable` — at least one of /contact,
  /about, /support reachable
- `public_facing_signals.privacy_policy_reachable`
- `public_facing_signals.terms_reachable`

**v1 LLM sub-pass** (consensus-of-N per `CA024`):

- `public_facing_signals.title_describes_page` (llm) — title is descriptive,
  not generic
- `public_facing_signals.meta_description_compels_click` (llm) — meta
  description is informative + actionable
- `public_facing_signals.hero_value_prop_legible` (llm) — homepage hero
  states what the product is in one short sentence
- `public_facing_signals.cta_specificity` (llm) — primary CTAs are specific
  ("Start free trial") rather than generic ("Learn more")
- `public_facing_signals.social_proof_present` (llm) — logos/testimonials/
  case studies/ratings present
- `public_facing_signals.pricing_transparency` (llm, hybrid) — precondition:
  pricing-related route reachable; LLM judges transparency

**v2 backlog**: page speed signals from existing capture (CLS, LCP, FID),
backlink-style external authority signals (deferred — requires external
data), readability scores, internal link density analysis.

**Required artifacts**: `dom` per URL, meta-tag-extractor output, homepage
DomExcerpt for LLM sub-pass.

**References**: ogp.me, dev.twitter.com cards, Google search-quality
guidelines (criteria reference only).

### Dimension 8 — Accessibility

Goal: WCAG compliance via axe-core (the existing-tool approach beats
re-implementing).

**v1 mechanical checks** (axe-core integration via Playwright):

- `accessibility.axe_violations_critical` — count of critical violations
- `accessibility.axe_violations_serious` — count of serious violations
- `accessibility.axe_violations_moderate`
- `accessibility.color_contrast` — uses webprobe's existing visual.py contrast
  check (CO012 sRGB linearization correctness)
- `accessibility.alt_text_present` — overlap with public_facing_signals;
  different audience (a11y vs marketing) — keep both
- `accessibility.heading_order`
- `accessibility.aria_roles_valid`
- `accessibility.form_labels_present`
- `accessibility.keyboard_focus_indicators` (runtime) — focusable elements
  show focus indicators
- `accessibility.lang_attribute_present` — `<html lang>` set

**v2 backlog**: full WCAG 2.2 ruleset, screen-reader-only content checks,
motion-reduce media-query coverage, automated keyboard-navigation simulation.

**Required artifacts**: `dom` per URL, browser instance, axe-core script
injection.

**References**: WCAG 2.1, axe-core rules.

### Dimension 9 — General Security

Goal: existing webprobe security checks brought under the unified CheckResult
schema. Distinct from API security in dim 4 (API surface). This dimension
covers HTTP-layer + cookie/CSP/HSTS + content-mixing + outbound-secret leakage.

**v1 mechanical checks** (mostly migration of existing security.py):

- `general_security.hsts_header` — Strict-Transport-Security present + reasonable
- `general_security.csp_header` — Content-Security-Policy present + non-trivial
- `general_security.x_content_type_options` — nosniff
- `general_security.x_frame_options` or CSP frame-ancestors
- `general_security.referrer_policy`
- `general_security.permissions_policy`
- `general_security.cookie_secure_attr`
- `general_security.cookie_httponly_attr`
- `general_security.cookie_samesite_attr`
- `general_security.mixed_content` — http subresources on https pages
- `general_security.tls_only` — non-HTTPS endpoints flagged
- `general_security.secrets_in_responses` — known secret-shape patterns in
  response bodies (uses mask module's redaction database)
- `general_security.cors_misconfiguration` — `Access-Control-Allow-Origin: *`
  with credentials, or reflected origins

**v2 backlog**: subresource integrity (SRI) coverage, well-known
`/.well-known/security.txt`, dependency-confusion surface analysis.

**Required artifacts**: per-URL HTTP exchange (request + response), cookies,
DOM (for mixed-content scan).

**References**: OWASP Secure Headers Project, MDN HTTP, RFC 6797 (HSTS).

## 4. Module Structure

webprobe uses the **Pact decomposition pattern**: real code under `src/webprobe/`,
single-file public-API mirrors under `src/src_webprobe_<module>/`, contract
artifacts under `contracts/src_webprobe_<module>/`, contract tests under
`tests/src_webprobe_<module>/`. New audit dimensions follow the same pattern as
existing modules like `webprobe.security`.

### 4.1 Real package — `src/webprobe/`

```
src/webprobe/
  models.py                 # extended: CheckResult, Evidence variants, Fix, Artifact, Scorecard, DimensionScore
  capturer.py               # extended: writes to artifact_store as it captures
  artifact_store.py         # NEW: canonical shared store (CA003)
  parsers/                  # NEW: shared artifact parsers (CA017)
    __init__.py
    robots_txt.py
    sitemap.py
    openapi.py
    json_ld.py
    meta_tags.py
  scheduler/                # NEW (block 2): DAG, mode-aware, mechanical-only honoring
  scorecard/                # NEW (block 2): per-dim subscore + band mapping (CA023)
  security/                 # EXTENDED: dual-emits SecurityFinding + CheckResult under general_security
  discoverability/          # NEW (block 3): dim 1
  bot_access/               # NEW (block 3): dim 2
  agent_surface/            # NEW (block 4): dim 3
  api_surface/              # NEW (block 7): dim 4 (largest — likely two engineer runs)
  structured_data/          # NEW (block 5): dim 5
  agentic_commerce/         # NEW (block 6): dim 6
  public_facing_signals/    # NEW (block 8): dim 7
  accessibility/            # NEW (block 9): dim 8
  reporter.py               # EXTENDED: renders CheckResult + Scorecard; renders Fix recommendations
  cli.py                    # EXTENDED: --mechanical-only, --dimension <name>, --emit-fixes-json
```

`general_security` (dimension 9) is the existing `webprobe.security` package
extended to dual-emit, not a new package.

### 4.2 Decomposition mirrors — `src/src_webprobe_<module>/`

For each new module, create a single-file mirror at
`src/src_webprobe_<dimension>/<dimension>.py` that re-exports the public API
the contract describes. Existing modules (`models`, `capturer`, etc.) already
have these; they need to be updated when public API changes.

> Watch item: `src/src_webprobe_security/security.py` is the OLD monolith and
> has not been kept in sync with `webprobe.security/` (which was decomposed
> into 15 submodules). The dual-emission migration in this block updates the
> mirror to track the current decomposed surface.

### 4.3 Contracts — `contracts/src_webprobe_<module>/`

Each module/dimension has `{interface.json, interface.py, history/}` per
existing convention. `interface.py` is a stub-only Python file with type
signatures, docstrings, and module invariants. `interface.json` is the same
content in machine-readable form. `history/` retains versioned snapshots
(timestamp filenames).

### 4.4 Contract tests — `tests/src_webprobe_<module>/`

Each module has `contract_test.py` validating the real implementation against
the contract. Tests import from `webprobe.<module>` (the real package), not
the mirror.

## 5. Implementation Sequence

`/engineer` runs in this order. Each block is a single `/engineer` invocation
with the deliverable scoped to that block. Earlier blocks unblock later ones;
merge after each.

1. **Foundation**: extend `models.py` with CheckResult, Artifact, Fix,
   Scorecard, Evidence variants. Build `artifact_store.py` and the shared
   parsers (robots_txt, sitemap, openapi, json_ld, meta_tags). Wire capturer
   to write into the store. Migrate `security.py` to emit CheckResult under
   `general_security`.
2. **Scheduler + Scorecard**: build `scheduler.py` (DAG, mode-aware) and
   `scorecard.py` (subscore + band mapping per CA023). Update reporter to
   render CheckResult + Scorecard.
3. **Dimensions 1 + 2** (Discoverability + Bot Access): port `probe.sh` logic
   to Python; both dimensions key off the shared robots.txt parser. v1 checks
   only.
4. **Dimension 3** (Agent Surface): well-known probes + WebMCP runtime check.
5. **Dimension 5** (Structured Data): JSON-LD extractor consumed by
   per-schema-type checks; Shopify product check generalized.
6. **Dimension 6** (Agentic Commerce): well-known probes for
   x402/MPP/UCP/ACP.
7. **Dimension 4** (API Surface): OpenAPI loader + Stripe-pattern mechanical
   checks first; OWASP subset; hybrid LLM checks (resource hierarchy,
   boolean-vs-enum, docs quality) last. This is the largest dimension —
   probably split into two `/engineer` runs.
8. **Dimension 7** (Public-Facing Signals): mechanical sub-pass first; LLM
   sub-pass second.
9. **Dimension 8** (Accessibility): axe-core integration.
10. **Polish**: CLI flags, HTML report sections per dimension, scorecard.json
    schema validation, end-to-end test against reeve.tools and one
    intentionally-broken fixture.

## 6. Out of Scope (v1)

- Hosted/multi-tenant operation. Local-only (`CA015`).
- Auto-applying fixes (`CA009`).
- Cross-run trending UI for the new dimensions (existing differ handles raw
  diffs; trend visualization is v2).
- Microdata + RDFa extraction; JSON-LD only in v1.
- Full OWASP API Top 10 (subset in v1; full coverage v2).
- LLM-judgment sub-pass of Public-Facing Signals (mechanical first; LLM
  second — but second still inside v1 if time permits).
- WCAG 2.2 beyond axe-core's default ruleset.
- RSS/Atom and JSON Feed checks within Discoverability.
