# Reference Scan #2 — Cloudflare isitagentready.com

Target: https://reeve.tools. Score: 25/100 (Level 1: Basic Web Presence).

## Categories (5) and per-check criteria

### Discoverability (3 checks, scored 2/3 = 67)
1. **robots.txt** — exists with valid format. Validate User-agent directives.
2. **Sitemap** — referenced from robots.txt via `Sitemap:` directive AND
   the sitemap URL returns valid XML.
3. **Link headers** (RFC 8288) — homepage response includes `Link:` headers
   advertising agent resources, e.g. `</.well-known/api-catalog>; rel="api-catalog"`,
   `</docs/api>; rel="service-doc"`.

### Content Accessibility (1 check, scored 0/1 = 0)
4. **Markdown negotiation** — `GET /` with `Accept: text/markdown` returns
   `Content-Type: text/markdown` (with optional `x-markdown-tokens` header).

### Bot Access Control (2 checks, scored 1/2 = 50)
5. **AI bot rules in robots.txt** — explicit User-agent entries for AI
   crawlers. Reeve was credited for: gptbot, chatgpt-user, google-extended,
   ccbot, anthropic-ai, claude-web, bytespider, perplexitybot, cohere-ai.
6. **Web Bot Auth request signing** — `/.well-known/http-message-signatures-directory`
   returns a valid JWKS for the site's outbound bot identity.
7. **Content Signals in robots.txt** — `Content-Signal:` directives declaring
   `ai-train`, `search`, `ai-input` preferences.

### API, Auth, MCP & Skill Discovery (6 checks, scored 0/6 = 0)
8. **API Catalog** (RFC 9727) — `/.well-known/api-catalog` returns
   `application/linkset+json` with a `linkset` array. Each entry includes
   `anchor` URL plus link relations: `service-desc` (OpenAPI), `service-doc`
   (documentation), `status` (health endpoint).
9. **OAuth/OIDC discovery** — either `/.well-known/openid-configuration`
   or `/.well-known/oauth-authorization-server` exposes issuer,
   authorization_endpoint, token_endpoint, jwks_uri, grant_types_supported.
10. **OAuth Protected Resource** (RFC 9728) — `/.well-known/oauth-protected-resource`
    publishes resource identifier, authorization_servers, scopes_supported.
11. **MCP Server Card** (SEP-1649/2127) — `/.well-known/mcp/server-card.json`
    (or fallback paths) with `serverInfo` (name, version), transport endpoint,
    capabilities.
12. **Agent Skills index** — `/.well-known/agent-skills/index.json` with
    `$schema` and a `skills` array of {name, type, description, url, sha256}.
13. **WebMCP** — runtime check: page calls `navigator.modelContext.provideContext()`
    with tool definitions (name, description, inputSchema, execute). Requires
    a real browser (Playwright) to detect.

### Commerce (4 checks, optional/informational)
14. **x402 Protocol** — endpoints return HTTP 402 with payment requirements.
    Also: querying `/platform/v2/x402/discovery/resources` style discovery.
15. **MPP (Machine Payment Protocol)** — `/openapi.json` includes
    `x-payment-info` extensions on payable operations.
16. **UCP (Universal Commerce Protocol)** — `/.well-known/ucp` profile.
17. **ACP (Agentic Commerce Protocol)** — `/.well-known/acp.json` with
    `protocol.name = "acp"`, `api_base_url`, transports, capabilities.

## Per-check output shape
- Goal, Result/Issue, How to implement, Resources, Skill (copy-paste prompt)
- Audit details: full HTTP exchange (method, path, status, request/response
  headers, body excerpt, conclusion, time taken)

## Notes for webprobe
- 14 mandatory checks + 4 informational commerce checks.
- All but #13 (WebMCP) are HTTP probes. Webprobe's mapper already does HTTP.
- WebMCP needs the existing Playwright browser pass.
- Output should preserve the full HTTP exchange as evidence.
