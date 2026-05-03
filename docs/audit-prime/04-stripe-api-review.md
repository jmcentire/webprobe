# Reference Scan #3 — Stripe API Reviews

Target: Herald SPEC.md. 1 critical, 8 warnings, 4 suggestions, 6 positives.

## Pattern categories surfaced (by severity, deduplicated)

### CRITICAL
- **Identifiers — prefixed format**: raw SHA-256 hex IDs flagged. Pattern:
  IDs should use short prefix + opaque body (Stripe `cus_`, `pm_`, `pi_`).
  Recommendation: separate delivery ID (`msg_…`) from content hash (`fp_…`).

### WARNINGS
- **Resource path hierarchy**: operations on the same logical resource
  fragmented across unrelated top-level prefixes (`/queue/`, `/ack/`,
  `/nack/`, `/heartbeat/`, `/dlq/`). Should nest under the primary
  resource path.
- **HTTP methods**: PUT used where POST is the convention. Pattern: POST
  for all create/update/upsert operations; PUT only for true full-replace.
- **HTTP status codes**: non-approved codes flagged (here, 507 for
  queue-full). Approved set: 400, 401, 402, 403, 404, 409, 424, 429, 500,
  503. Use 429 + Retry-After + typed `code` for queue-exhaustion.
- **Resource type identifier**: every response should carry a consistent
  type field (`object`, `type`, or `kind`) for polymorphic deserialization.
- **Pagination metadata**: list responses must include `has_more`. Stripe
  shape: `{ object: "list", data: [...], has_more: bool }`.
- **Field naming — reserved timestamps**: `created` and `updated` are
  reserved for Unix timestamp fields. Don't reuse as boolean flags. Use
  `is_new` or HTTP status (201 vs 200) instead.
- **Timestamp serialization**: Unix integer seconds. Ambiguous formats
  ("UTC timestamp, ns precision" with no concrete shape) flagged. For
  sub-second precision, expose as separate `<field>_ns` decimal string.
- **Booleans vs enums**: any boolean that could plausibly grow values
  (e.g. `permanent: true/false` for retry disposition) should be an
  enum (`disposition: "requeue" | "dlq" | "delay_requeue" | …`).

### SUGGESTIONS
- **Documentation/spec consistency**: doc fields that contradict the
  actual derivation logic (template var described as "content-addressable
  hash" when it includes timestamp + endpoint).
- **Field naming — `_id` suffix**: redundant suffixing (`new_message_id`)
  inconsistent with object-reference pattern; prefer renaming to match
  the resource's canonical ID field.
- **Status codes — 204 vs empty array**: empty list endpoints should
  return 200 + `{ data: [], has_more: false }`, not 204. Forces
  two-branch client handling otherwise.
- **Unauthenticated endpoint hygiene**: document rate limits, input
  validation rules (length, charset, reserved names), and key activation
  policy for endpoints like `/register`.

### POSITIVES (patterns to detect favorably)
- **API key prefixes** identify credentials for secret scanners.
- **WebSocket auth via first message** (not query params) avoids
  credential leakage to logs/CDNs/Referer.
- **Consistent snake_case** + correct `<verb>ed_at`/`<verb>s_at` for
  past/future timestamps.
- **Two-hash design**: separate delivery ID from content hash.
- **Rate limiting**: 429 + Retry-After + tier separation via subdomains.
- **Batch operations**: batch ACK with partial-success response shape
  (`acknowledged: [...], failed: [...]`).

## Mechanical vs LLM-judgment split

**Mechanical (regex/AST over OpenAPI + sample responses):**
- ID format: prefix detection on `*_id` fields
- Status code set: enumerate codes used, flag non-approved
- `has_more` presence on list responses
- `object`/`type`/`kind` field presence
- Timestamp serialization (integer vs string, presence of `_ns` companion)
- Field naming: snake_case throughout, `created`/`updated` type check,
  `<verb>ed_at`/`<verb>s_at` patterns, no `_id_id`
- HTTP verb conventions across the route table
- 204 vs 200+empty on list endpoints
- API key prefix presence in auth examples
- 429 + Retry-After shape

**LLM-judgment:**
- Resource hierarchy coherence (paths fragmented vs nested)
- Boolean-vs-enum extensibility flags (which booleans "feel" like enums)
- Doc/spec contradictions
- Auth pattern review (WebSocket, registration abuse surface)
- Resource type field naming consistency across the surface
