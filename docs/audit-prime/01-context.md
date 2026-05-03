# Webprobe Audit Expansion — Context

## Goal
Extend webprobe to perform comprehensive site audits across multiple dimensions:
security, SEO, agent-friendliness, API design, marketing quality, copy, accessibility.

Webprobe today is a Playwright-based site state-graph auditor with phases:
1. **Map** — BFS crawl via robots.txt, sitemap, link following
2. **Capture** — Playwright captures DOM, headers, console, screenshots, forms
3. **Analyze** — graph metrics, broken links, auth boundaries, timing
4. **Report** — JSON + HTML reports
5. **Explore** — optional LLM-driven agents for visual/behavioral defects

Existing modules under `src/`:
- `src_webprobe_analyzer/analyzer.py` (258 lines)
- `src_webprobe_capturer/capturer.py` (325 lines)
- `src_webprobe_security/security.py` (414 lines) + `security/` package
- mapper, explorer, reporter, llm_provider, mask, visual, frameworks, auth

## Existing assets to reuse
- `~/.claude/skills/agentreadiness/probe.sh` (233 lines) — bash+curl
  implementation of the Cloudflare isitagentready.com checks. Spec-of-record
  for paths and pass/fail logic when porting to Python.
- Webprobe already crawls robots.txt, captures headers, runs Playwright,
  and has an LLM exploration phase. Most raw materials are present.

## Reference scans collected (see sibling files)
1. `02-shopify-product-scan.md` — Shopify's "agent discoverability" check
   for product pages (JSON-LD/schema.org structured data).
2. `03-cloudflare-agentready-scan.md` — Cloudflare isitagentready.com scan
   (5 categories: Discoverability, Content, Bot Access, Protocol Discovery,
   Commerce).
3. `04-stripe-api-review.md` — Stripe API Reviews scan of Herald's SPEC.md
   (API design quality patterns).

## Constraints to respect
- `webprobe/constraints.yaml` and `webprobe/trust_policy.yaml` exist; new
  modules must comply.
- Webprobe is contract-first (Pact pipeline). New modules need contracts
  in `contracts/`.
- LLM use is optional — mechanical checks must work without API keys.

## Out-of-scope clarifications needed
- Marketing quality / SEO / copy: no reference scan provided yet. Should
  we design from first principles using LLM judgment + standard signals
  (Lighthouse-style: meta tags, OpenGraph, Twitter Cards, heading
  hierarchy, alt text, readability scores)?
- OWASP API Top 10: existing security.py is general; do we extend it or
  create a new analyzer specifically for API surfaces?
- Should each new dimension be a separate analyzer module under
  `src_webprobe_analyzer/`, or co-located with related existing modules?
