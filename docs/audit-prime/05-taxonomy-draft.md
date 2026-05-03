# Audit Taxonomy — Working Draft (8 dimensions)

Drafted across the conversation. Constrain should challenge, refine,
add missing dimensions, and produce the final spec.

## 1. Discoverability
robots.txt, sitemap presence + valid structure, sitemap referenced
from robots, Link response headers (RFC 8288), Content Signals
directives in robots.txt.

## 2. Content negotiation
Markdown negotiation (Accept: text/markdown). llms.txt presence and
shape. Future: RSS/Atom feeds, JSON Feed.

## 3. Bot access & identity
Per-AI-bot allow/deny matrix in robots.txt across the major crawlers.
Web Bot Auth (`/.well-known/http-message-signatures-directory`).

## 4. API / Auth / MCP / Skill discovery
API Catalog (RFC 9727), OAuth/OIDC discovery, OAuth Protected Resource
metadata (RFC 9728), MCP Server Card (SEP-1649/2127), Agent Skills
index, WebMCP runtime detection.

## 5. Commerce
x402 (HTTP 402 payment), MPP (`x-payment-info` in OpenAPI), UCP
profile, ACP discovery, Shopify product structured data (11 product
fields), `<title>` length 30–60.

## 6. API docs presence + quality
- Presence: `/openapi.json`, `/openapi.yaml`, `/docs`, `/redoc`,
  `/swagger`, `/api-docs`.
- Quality: spec validates, examples present, descriptions on
  operations/parameters, error response schemas defined, auth
  schemes documented.

## 7. OWASP / API security
OWASP API Security Top 10 (2023):
- API1: Broken Object Level Authorization
- API2: Broken Authentication
- API3: Broken Object Property Level Authorization
- API4: Unrestricted Resource Consumption
- API5: Broken Function Level Authorization
- API6: Unrestricted Access to Sensitive Business Flows
- API7: Server Side Request Forgery
- API8: Security Misconfiguration
- API9: Improper Inventory Management
- API10: Unsafe Consumption of APIs

Also: existing security.py checks (cookies, CSP, HSTS, etc.) extended
with API-surface-specific checks.

## 8. API design quality (Stripe-style)
Mechanical: ID prefixes, status code set, pagination shape, resource
type field, timestamp format, naming conventions, HTTP verbs, list
endpoint 204-vs-empty, API key prefixes, rate limit shape.
LLM-judgment: resource hierarchy coherence, boolean-vs-enum review,
doc/spec contradictions, auth pattern review.

## Pending dimensions (no reference scan yet)

### 9. SEO
Meta tags (title, description), OpenGraph, Twitter Cards, canonical
URLs, hreflang, heading hierarchy, structured data validity (beyond
Product), internal link density, alt text coverage, page speed
signals (CLS, LCP from existing capture data).

### 10. Marketing & copy quality
Hero clarity (one-sentence value prop detectable?), CTA presence
and specificity, social proof (logos, testimonials, case studies,
ratings), pricing transparency, contact/about page, trust signals
(security badges, terms, privacy). Mostly LLM-judgment with
mechanical signal-presence checks.

### 11. Accessibility (WCAG)
Color contrast, alt text, heading order, ARIA roles, keyboard nav,
form labels, focus indicators. Mature standard with axe-core as a
likely backing tool.

## Cross-cutting concerns

- **Trinary status**: PASS / FAIL / NOT_DETECTED (informational/optional).
- **Per-check evidence**: full HTTP exchange or DOM excerpt.
- **Per-check fix prompt**: machine-readable so an agent can act on it.
- **Scorecard**: per-dimension subscore + overall + level classification.
- **Mechanical vs LLM split**: every check tagged so non-LLM runs are
  meaningful.
- **Module structure**: each dimension is its own analyzer under
  `src_webprobe_analyzer/<dimension>/` with a uniform interface
  (`run(capture, config) -> List[CheckResult]`).
- **Reuse**: probe.sh logic ported to Python; existing security.py
  extended for OWASP; existing LLM exploration phase used for
  judgment-driven checks.
