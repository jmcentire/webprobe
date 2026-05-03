# Reference Scan #1 — Shopify Agent Discoverability (Product Pages)

Source: Shopify's "Is your product page optimized for AI selling?" tool.
Target: a Reeve.tools product page. Score: 33/100, 9 weighted-equal factors.

## What it checks (11 factors, equal weight)

| # | Factor | Pass criterion |
|---|--------|----------------|
| 1 | Product name | schema.org `Product.name`, under 150 chars |
| 2 | Page title | HTML `<title>`, 30–60 chars |
| 3 | Description | schema.org `Product.description`, ≥20 words |
| 4 | Images | schema.org `Product.image` present |
| 5 | Per-variant images | `Product.hasVariant` / `isVariantOf` / `ProductGroup` with distinct image per variant |
| 6 | Variant options | `Product.hasVariant` with option names + values |
| 7 | Pricing | schema.org `Offer.price` + `Offer.priceCurrency` |
| 8 | Availability | `Offer.availability` ∈ {InStock, OutOfStock, PreOrder} |
| 9 | Shop name | schema.org `Organization.name` |
| 10 | Rating & reviews | `Product.aggregateRating` with rating value + review count |
| 11 | Crawler access | robots.txt allows the 10 search/AI user-agents checked |

## Per-check output shape
- Status: AI READY / FAIL / NOT DETECTED
- Goal: one-sentence intent
- Result: what was actually found
- What we checked for: detection criterion
- Resources: links to standards / docs

## Notes for webprobe
- All checks are derivable from JSON-LD extracted from the rendered DOM
  (Playwright already captures this) plus robots.txt parsing (existing).
- "NOT DETECTED" is distinct from "FAIL" — used when the feature is
  optional but not present (e.g. variant markup on a single-variant
  product). Webprobe should preserve this trinary.
- The robots.txt check uses a fixed set of ~10 user-agents. Need to
  enumerate: GPTBot, ChatGPT-User, ClaudeBot, anthropic-ai, PerplexityBot,
  Google-Extended, Googlebot, Bingbot, Applebot-Extended, Meta-ExternalAgent.
