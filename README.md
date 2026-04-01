# webprobe

Generic site state-graph auditor. Maps any website as a directed graph, captures detailed per-node metrics, scans for security vulnerabilities, and uses LLM-driven agents to discover visual defects and behavioral issues.

## Quick Start

```bash
pip install webprobe
playwright install chromium

# Full mechanical scan (no LLM, no API keys needed)
webprobe run https://your-site.com

# With LLM exploration (requires ANTHROPIC_API_KEY)
webprobe run https://your-site.com --explore --agents 5
```

## What It Does

Five phases, each runnable independently or as a pipeline:

### Phase 1: Map
BFS crawl via `robots.txt`, sitemap chain, and link following. Two passes: anonymous and authenticated. Optional framework route detection (Astro, Next.js, SvelteKit).

### Phase 2: Capture
Playwright headless browser visits every node. Captures per page:
- HTTP status, TTFB, DOMContentLoaded, load timing
- Every subresource (scripts, CSS, images, fonts) with status codes, sizes, MIME types
- Response headers, cookies (with security attribute analysis)
- Console messages (errors, warnings)
- Form inventory (CSRF tokens, password fields, autocomplete)
- Full-page screenshots

### Phase 3: Analyze
Graph metrics (cyclomatic complexity, edge coverage, orphans, dead ends), broken link detection, auth boundary violations, timing outliers (z-score), prime path enumeration.

### Phase 4: Report
JSON (stable schema for aggregation) + HTML (dark theme, summary cards, sortable tables, per-node detail with expandable resources/console/security/screenshots).

### Phase 5: Explore (optional, requires LLM)
Concurrent AI agents with headless browsers:
- **Computational**: WCAG AA/AAA contrast checking, hidden element detection
- **Vision**: LLM analyzes screenshots for layout defects, broken rendering, accessibility issues
- **Interactive**: Agents click, fill forms, scroll, and report what they find
- **Cost tracked**: Every LLM call logged with tokens and estimated USD

## Security Scanning

Passive checks (no attack payloads):

| Category | Checks |
|---|---|
| Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| XSS | Missing/weak CSP, unsafe-inline/eval, reflected URL parameters |
| Cookies | Secure, HttpOnly, SameSite flags (session cookies weighted higher) |
| Mixed Content | HTTP resources on HTTPS, forms posting to HTTP |
| CORS | Wildcard origin, wildcard + credentials |
| Info Disclosure | Server version, X-Powered-By, exposed source maps, stack traces |
| Forms | POST without CSRF, password autocomplete, HTTP form actions |
| Accessibility | WCAG AA/AAA contrast ratios via computed styles |
| Visual | Hidden elements, layout anomalies via LLM vision |

## CLI

```
webprobe run <url>                     # All phases
webprobe run <url> --explore           # Include LLM exploration
webprobe map <url>                     # Phase 1 only
webprobe capture <run-dir>             # Phase 2 only
webprobe analyze <run-dir>             # Phase 3 only
webprobe report <run-dir>              # Phase 4 only
webprobe explore <run-dir>             # Phase 5 only
webprobe diff <run-a> <run-b>          # Compare two runs
webprobe status <run-dir>              # Run summary
```

### Options

```
--config PATH          Path to webprobe.yaml
--project-root PATH    Project root for framework route detection
--output-dir PATH      Output directory for runs
--concurrency N        Override capture concurrency (default: 10)
--explore              Enable LLM exploration (Phase 5)
--llm-provider NAME    anthropic (default), openai, gemini, apprentice
--llm-model NAME       Override model (default: claude-sonnet-4)
--agents N             Concurrent exploration agents (default: 5)
--mask PATH            YAML mask file for suppressing known findings
--js                   Use Playwright for JS rendering during mapping
```

## Configuration

```yaml
# webprobe.yaml
auth:
  method: cookie          # cookie, bearer, header, none
  cookie_name: session
  cookie_value: "your-session-token"
  login_url: /login
  auth_indicator: "[data-user]"

crawl:
  max_depth: 10
  max_nodes: 500
  respect_robots: true
  follow_external: false
  request_delay_ms: 100

capture:
  concurrency: 10
  timeout_ms: 30000
  screenshot: true
  viewport_width: 1280
  viewport_height: 720

output_dir: ./webprobe-runs
```

## Mask File

Suppress known/expected findings:

```yaml
# webprobe-mask.yaml
rules:
  - url_pattern: "/legacy-page"
    title_pattern: "Visual:.*"
    reason: "Legacy page scheduled for redesign"

  - title_pattern: "Missing Permissions-Policy"
    category: "headers"
    reason: "Handled at CDN level"
```

## Run Output

```
webprobe-runs/
  20260327T143022-a1b2c3d4/
    run.json              # Complete run (stable schema v1.1)
    graph.json            # Site graph
    analysis.json         # Analysis results
    report.html           # Human-readable report
    screenshots/
      anonymous/*.png
      authenticated/*.png
    webprobe.yaml         # Config snapshot
```

## Cross-Run Diffing

```bash
webprobe diff run-a/ run-b/
```

Compares: nodes added/removed, HTTP status changes, timing deltas (>20%), new/resolved broken links, new/resolved auth violations, new/resolved security findings.

## LLM Providers

| Provider | Model Default | Vision | Install |
|---|---|---|---|
| Anthropic | claude-sonnet-4 | Yes | `pip install webprobe[explore]` |
| OpenAI | gpt-4o | Yes | `pip install webprobe[openai]` |
| Gemini | gemini-2.5-flash | Yes | `pip install webprobe[gemini]` |
| Apprentice | auto (local routing) | Yes | `pip install webprobe[apprentice]` |

## Framework Detection

When given `--project-root`, webprobe extracts routes from:
- **Astro**: `src/pages/**/*.{astro,md,mdx}`
- **Next.js**: `app/**/page.{tsx,jsx}` or `pages/**/*.{tsx,jsx}`
- **SvelteKit**: `src/routes/**/+page.svelte`

These supplement the crawl with routes that may not be linked from the homepage.

## Dependencies

All permissive licenses (MIT/Apache 2.0/BSD):

| Package | License | Purpose |
|---|---|---|
| playwright | Apache 2.0 | Browser automation |
| networkx | BSD 3-Clause | Graph algorithms |
| aiohttp | Apache 2.0 | HTTP crawling |
| pydantic | MIT | Data models |
| click | BSD 3-Clause | CLI |
| jinja2 | BSD 3-Clause | HTML reports |
| anthropic | MIT | Claude API (optional) |
| transmogrifier | MIT | Prompt optimization (optional) |

## License

MIT
