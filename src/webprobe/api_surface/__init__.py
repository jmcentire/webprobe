"""API Surface dimension analyzer (Dimension 4).

Mega-dimension consolidating: API docs presence + Stripe-style design quality
(mechanical patterns + 3 LLM hybrids) + OWASP API Top 10 subset.

v1 checks (26 total):

  Presence (7, mechanical):
    api_surface.openapi_present
    api_surface.docs_present
    api_surface.openapi_valid
    api_surface.openapi_examples_present
    api_surface.openapi_descriptions_present
    api_surface.error_schemas_defined
    api_surface.auth_schemes_documented

  Stripe-style mechanical (10):
    api_surface.identifier_prefixes (CA020)
    api_surface.approved_status_codes (CA018)
    api_surface.list_endpoint_empty_shape (CA019)
    api_surface.pagination_has_more
    api_surface.resource_type_field
    api_surface.timestamp_format_unix_int
    api_surface.snake_case_naming
    api_surface.timestamp_naming_convention
    api_surface.no_id_id_suffix
    api_surface.http_verb_conventions
    api_surface.api_key_prefix
    api_surface.rate_limit_shape

  Hybrid LLM (3 — SKIPPED in mechanical_only; implementation pending in full):
    api_surface.resource_hierarchy_coherence
    api_surface.boolean_vs_enum_extensibility
    api_surface.docs_quality

  OWASP API Top 10 subset (6):
    api_surface.owasp_api1_bola
    api_surface.owasp_api2_broken_auth
    api_surface.owasp_api4_unrestricted_consumption
    api_surface.owasp_api7_ssrf_surface
    api_surface.owasp_api8_security_misconfiguration
    api_surface.owasp_api9_inventory_management

Reads `openapi` artifacts (parsed via webprobe.parsers.openapi). Most checks
operate on the parsed OpenAPI summary; some reach into raw bytes for
fine-grained heuristics.
"""

from __future__ import annotations

import json
import re
import time
from urllib.parse import urljoin, urlparse

from webprobe.artifact_store import ArtifactStore
from webprobe.models import (
    Artifact,
    ArtifactRef,
    ArtifactType,
    CaptureStatus,
    CheckMode,
    CheckResult,
    CheckSeverity,
    CheckStatus,
    DimensionId,
    Fix,
    FixActionType,
    HttpExchange,
    Reference,
)


DIMENSION = DimensionId.api_surface
_NUM_CHECKS = 28  # 7 presence + 12 Stripe mechanical + 3 hybrid LLM + 6 OWASP
_W = 1.0 / _NUM_CHECKS


_APPROVED_CODES = {
    "200", "201", "202", "204", "301", "302", "304", "307", "308",
    "400", "401", "402", "403", "404", "409", "410", "422", "424", "429",
    "500", "502", "503", "504",
}


_RFC_REF = Reference(label="OpenAPI 3.x", url="https://spec.openapis.org/oas/v3.0.3")


def _origin(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return url.rstrip("/")
    return f"{p.scheme}://{p.netloc}"


def _find_openapi(store: ArtifactStore, base_url: str) -> Artifact | None:
    """Find an openapi artifact under the base URL's origin."""
    arts = store.find_by_type(ArtifactType.openapi)
    origin = _origin(base_url)
    for a in arts:
        if a.source_url.startswith(origin):
            return a
    return arts[0] if arts else None


def _ref(art: Artifact, excerpt: str = "") -> ArtifactRef:
    return ArtifactRef(artifact_id=art.artifact_id, excerpt=excerpt)


def _pass(check_id: str, title: str, goal: str, art: Artifact, excerpt: str = "", severity: CheckSeverity = CheckSeverity.info) -> CheckResult:
    return CheckResult(
        dimension=DIMENSION, check_id=check_id, title=title, goal=goal,
        status=CheckStatus.pass_, severity=severity, mode=CheckMode.mechanical,
        weight=_W, evidence=_ref(art, excerpt),
    )


def _fail(check_id: str, title: str, goal: str, art: Artifact, excerpt: str, fix: Fix, severity: CheckSeverity = CheckSeverity.warning) -> CheckResult:
    return CheckResult(
        dimension=DIMENSION, check_id=check_id, title=title, goal=goal,
        status=CheckStatus.fail, severity=severity, mode=CheckMode.mechanical,
        weight=_W, evidence=_ref(art, excerpt), fix=fix,
    )


def _not_detected_no_openapi(check_id: str, title: str, goal: str, severity: CheckSeverity = CheckSeverity.warning) -> CheckResult:
    return CheckResult(
        dimension=DIMENSION, check_id=check_id, title=title, goal=goal,
        status=CheckStatus.not_detected, severity=severity, mode=CheckMode.mechanical,
        weight=_W, evidence=HttpExchange(method="GET", url="", status=None),
        reason="artifact_unavailable:openapi:not_captured",
    )


def _hybrid_skipped(check_id: str, title: str, goal: str, mode: str) -> CheckResult:
    """Hybrid LLM check: SKIPPED with mode-specific reason."""
    if mode == "mechanical_only":
        reason = "mechanical_only_mode_skips_hybrid_llm_portion"
    else:
        reason = "llm_judgment_implementation_pending_in_v1"
    return CheckResult(
        dimension=DIMENSION, check_id=check_id, title=title, goal=goal,
        status=CheckStatus.skipped, severity=CheckSeverity.suggestion,
        mode=CheckMode.hybrid, weight=_W,
        evidence=HttpExchange(method="GET", url="", status=None),
        reason=reason,
    )


# ============================================================================
# Presence checks (7)
# ============================================================================


def check_openapi_present(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None:
        return CheckResult(
            dimension=DIMENSION, check_id="api_surface.openapi_present",
            title="OpenAPI document present",
            goal="/openapi.json or equivalent reachable",
            status=CheckStatus.fail,
            severity=CheckSeverity.warning, mode=CheckMode.mechanical, weight=_W,
            evidence=HttpExchange(method="GET", url=urljoin(_origin(base_url) + "/", "openapi.json"), status=None),
            fix=Fix(
                action_type=FixActionType.add_well_known_resource,
                target=urljoin(_origin(base_url) + "/", "openapi.json"),
                payload={"format": "OpenAPI 3.x JSON"},
                summary="Publish /openapi.json describing your HTTP API",
                references=[_RFC_REF],
            ),
        )
    if art.capture_status != CaptureStatus.ok:
        return _fail("api_surface.openapi_present", "OpenAPI document present", "OpenAPI is reachable + parses",
                     art, art.capture_error or "fetch failed",
                     Fix(action_type=FixActionType.add_well_known_resource, target=art.source_url,
                         payload={"reason": art.capture_error}, summary="Make /openapi.json reachable and valid", references=[_RFC_REF]))
    return _pass("api_surface.openapi_present", "OpenAPI document present", "OpenAPI is reachable + parses", art, art.source_url)


def check_docs_present(store: ArtifactStore, base_url: str) -> CheckResult:
    """Look for any captured http_response or well_known artifact at /docs, /redoc, /swagger, /api-docs."""
    candidates = ("docs", "redoc", "swagger", "api-docs", "api/docs")
    origin = _origin(base_url)
    for path in candidates:
        target = urljoin(origin + "/", path)
        for atype in (ArtifactType.http_response, ArtifactType.well_known, ArtifactType.dom):
            art = store.find(atype, target)
            if art is not None and art.capture_status == CaptureStatus.ok:
                return _pass("api_surface.docs_present", "Human API docs present", "/docs|/redoc|/swagger reachable", art, target)
    # Not found — informational suggestion
    return CheckResult(
        dimension=DIMENSION, check_id="api_surface.docs_present",
        title="Human API docs present",
        goal="/docs|/redoc|/swagger|/api-docs reachable",
        status=CheckStatus.not_detected, severity=CheckSeverity.suggestion,
        mode=CheckMode.mechanical, weight=_W,
        evidence=HttpExchange(method="GET", url=urljoin(origin + "/", "docs"), status=None),
        reason="artifact_unavailable:docs:none_of_candidates_reachable",
    )


def check_openapi_valid(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None:
        return _not_detected_no_openapi("api_surface.openapi_valid", "OpenAPI parses cleanly", "openapi parser ok=true")
    if art.capture_status == CaptureStatus.ok and (art.payload or {}).get("operations") is not None:
        return _pass("api_surface.openapi_valid", "OpenAPI parses cleanly", "openapi parser ok=true", art, "parsed cleanly")
    return _fail("api_surface.openapi_valid", "OpenAPI parses cleanly", "openapi parser ok=true",
                 art, art.capture_error or "parser produced no operations",
                 Fix(action_type=FixActionType.other, target=art.source_url,
                     payload={"action": "fix OpenAPI document validation errors"},
                     summary="Validate /openapi.json against the OpenAPI 3.x schema", references=[_RFC_REF]))


def check_openapi_examples_present(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.openapi_examples_present", "OpenAPI examples present",
                                         "≥30% of operations have examples", severity=CheckSeverity.suggestion)
    p = art.payload or {}
    total = p.get("operation_count", 0)
    with_ex = p.get("operations_with_examples", 0)
    if total == 0:
        return _hybrid_skipped("api_surface.openapi_examples_present", "OpenAPI examples present", "≥30% of operations have examples", "full")
    coverage = with_ex / total
    if coverage >= 0.3:
        return _pass("api_surface.openapi_examples_present", "OpenAPI examples present",
                     f"{with_ex}/{total} operations have examples ({coverage:.0%})", art, f"coverage={coverage:.0%}")
    return _fail("api_surface.openapi_examples_present", "OpenAPI examples present",
                 "≥30% of operations have examples", art, f"only {coverage:.0%} ({with_ex}/{total})",
                 Fix(action_type=FixActionType.other, target=art.source_url,
                     payload={"current_coverage": coverage, "target": 0.3},
                     summary="Add request/response examples to operations in OpenAPI", references=[_RFC_REF]),
                 severity=CheckSeverity.suggestion)


def check_openapi_descriptions_present(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.openapi_descriptions_present", "OpenAPI descriptions present",
                                         "≥80% of operations have descriptions", severity=CheckSeverity.suggestion)
    p = art.payload or {}
    total = p.get("operation_count", 0)
    with_d = p.get("operations_with_descriptions", 0)
    if total == 0:
        return _hybrid_skipped("api_surface.openapi_descriptions_present", "OpenAPI descriptions present", "≥80% of operations have descriptions", "full")
    coverage = with_d / total
    if coverage >= 0.8:
        return _pass("api_surface.openapi_descriptions_present", "OpenAPI descriptions present",
                     "≥80% of operations have descriptions", art, f"coverage={coverage:.0%}")
    return _fail("api_surface.openapi_descriptions_present", "OpenAPI descriptions present",
                 "≥80% of operations have descriptions", art, f"only {coverage:.0%} ({with_d}/{total})",
                 Fix(action_type=FixActionType.other, target=art.source_url,
                     payload={"current_coverage": coverage, "target": 0.8},
                     summary="Add summary/description to every OpenAPI operation", references=[_RFC_REF]),
                 severity=CheckSeverity.suggestion)


def check_error_schemas_defined(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.error_schemas_defined", "Error response schemas defined",
                                         "4xx/5xx responses include schemas", severity=CheckSeverity.suggestion)
    p = art.payload or {}
    total = p.get("error_responses_total", 0)
    with_s = p.get("error_responses_with_schemas", 0)
    if total == 0:
        return _hybrid_skipped("api_surface.error_schemas_defined", "Error response schemas defined", "4xx/5xx responses include schemas", "full")
    coverage = with_s / total
    if coverage >= 0.8:
        return _pass("api_surface.error_schemas_defined", "Error response schemas defined",
                     "≥80% of error responses define schemas", art, f"coverage={coverage:.0%}")
    return _fail("api_surface.error_schemas_defined", "Error response schemas defined",
                 "≥80% of error responses define schemas", art, f"only {coverage:.0%} ({with_s}/{total})",
                 Fix(action_type=FixActionType.other, target=art.source_url,
                     payload={"current_coverage": coverage, "target": 0.8},
                     summary="Add response schemas to all 4xx/5xx error responses", references=[_RFC_REF]),
                 severity=CheckSeverity.suggestion)


def check_auth_schemes_documented(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.auth_schemes_documented", "Auth schemes documented",
                                         "components.securitySchemes is non-empty", severity=CheckSeverity.suggestion)
    schemes = (art.payload or {}).get("security_schemes", []) or []
    if schemes:
        return _pass("api_surface.auth_schemes_documented", "Auth schemes documented",
                     "components.securitySchemes is non-empty", art, f"schemes={schemes}")
    return _fail("api_surface.auth_schemes_documented", "Auth schemes documented",
                 "components.securitySchemes is non-empty", art, "no securitySchemes",
                 Fix(action_type=FixActionType.other, target=art.source_url,
                     payload={"action": "declare components.securitySchemes"},
                     summary="Declare auth schemes (e.g. bearer, apiKey, oauth2) under components.securitySchemes",
                     references=[_RFC_REF]),
                 severity=CheckSeverity.suggestion)


# ============================================================================
# Stripe-style mechanical patterns (12)
# ============================================================================


def _raw(art: Artifact) -> str:
    if art.raw_bytes is None:
        return json.dumps(art.payload or {})
    try:
        return art.raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        return ""


def check_identifier_prefixes(store: ArtifactStore, base_url: str) -> CheckResult:
    """CA020: *_id fields should use a typed prefix (e.g. msg_, cus_)."""
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.identifier_prefixes", "Prefixed identifiers (CA020)", "*_id values use typed prefixes")
    text = _raw(art)
    # Heuristic: look for example or pattern values for *_id fields. Pass if
    # any *_id schema/field has an example with letters_ underscore prefix
    # (e.g. "msg_a3f9..."). Fail if examples exist but are raw hex/numeric.
    examples = re.findall(r'"([a-z_]*_id)"\s*:\s*"([^"]+)"', text)
    if not examples:
        return CheckResult(
            dimension=DIMENSION, check_id="api_surface.identifier_prefixes",
            title="Prefixed identifiers (CA020)", goal="*_id values use typed prefixes",
            status=CheckStatus.not_detected, severity=CheckSeverity.suggestion,
            mode=CheckMode.mechanical, weight=_W, evidence=_ref(art, "no *_id examples found"),
            reason="artifact_unavailable:id_examples:none_in_openapi",
        )
    prefixed = [v for k, v in examples if re.match(r"^[a-z]{2,5}_[a-zA-Z0-9]+", v)]
    if len(prefixed) >= len(examples) * 0.5:
        return _pass("api_surface.identifier_prefixes", "Prefixed identifiers (CA020)",
                     "*_id values use typed prefixes", art, f"{len(prefixed)}/{len(examples)} prefixed",
                     severity=CheckSeverity.info)
    return _fail("api_surface.identifier_prefixes", "Prefixed identifiers (CA020)",
                 "*_id values use typed prefixes", art, f"only {len(prefixed)}/{len(examples)} prefixed",
                 Fix(action_type=FixActionType.add_id_prefix, target=art.source_url,
                     payload={"pattern": "<short_prefix>_<opaque>", "examples": ["msg_abc", "cus_def"]},
                     summary="Adopt prefixed identifier format (e.g. msg_, cus_) for *_id fields",
                     references=[Reference(label="Stripe API conventions", url="https://stripe.com/docs/api")]),
                 severity=CheckSeverity.suggestion)


def check_approved_status_codes(store: ArtifactStore, base_url: str) -> CheckResult:
    """CA018: only the approved status code set."""
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.approved_status_codes", "Approved HTTP status codes (CA018)", "all responses use the approved set")
    used = set((art.payload or {}).get("response_codes_used", []))
    bad = sorted(c for c in used if c.isdigit() and c not in _APPROVED_CODES)
    if not bad:
        return _pass("api_surface.approved_status_codes", "Approved HTTP status codes (CA018)",
                     "all responses use the approved set", art, f"used={sorted(used)}")
    return _fail("api_surface.approved_status_codes", "Approved HTTP status codes (CA018)",
                 "all responses use the approved set", art, f"non-approved={bad}",
                 Fix(action_type=FixActionType.fix_status_code, target=art.source_url,
                     payload={"non_approved_codes": bad, "approved_set": sorted(_APPROVED_CODES)},
                     summary=f"Replace non-standard codes {bad} with approved equivalents (e.g. 507 → 429)",
                     references=[Reference(label="Stripe API conventions", url="https://stripe.com/docs/api")]),
                 severity=CheckSeverity.warning)


def check_list_endpoint_empty_shape(store: ArtifactStore, base_url: str) -> CheckResult:
    """CA019: list endpoints shouldn't return 204 on empty."""
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.list_endpoint_empty_shape", "List endpoints don't 204 on empty (CA019)",
                                         "GET list endpoints return 200 with empty data", severity=CheckSeverity.suggestion)
    operations = (art.payload or {}).get("operations", [])
    list_ops = [o for o in operations if o.get("method") == "get" and any(r.get("code") == "204" for r in o.get("responses", []))]
    if not list_ops:
        return _pass("api_surface.list_endpoint_empty_shape", "List endpoints don't 204 on empty (CA019)",
                     "no GET endpoints return 204", art, "ok")
    return _fail("api_surface.list_endpoint_empty_shape", "List endpoints don't 204 on empty (CA019)",
                 "no GET endpoints return 204", art, f"{len(list_ops)} GET ops with 204",
                 Fix(action_type=FixActionType.fix_status_code, target=art.source_url,
                     payload={"affected": [o.get("path") for o in list_ops]},
                     summary="Return 200 + {data: [], has_more: false} instead of 204 on empty list",
                     references=[Reference(label="Stripe API conventions", url="https://stripe.com/docs/api")]),
                 severity=CheckSeverity.suggestion)


def check_pagination_has_more(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.pagination_has_more", "Pagination has_more field",
                                         "list responses include has_more", severity=CheckSeverity.suggestion)
    text = _raw(art)
    if '"has_more"' in text:
        return _pass("api_surface.pagination_has_more", "Pagination has_more field",
                     "list responses include has_more", art, "has_more found")
    return _fail("api_surface.pagination_has_more", "Pagination has_more field",
                 "list responses include has_more", art, "no has_more in OpenAPI",
                 Fix(action_type=FixActionType.add_pagination_field, target=art.source_url,
                     payload={"field": "has_more", "type": "boolean"},
                     summary="Add `has_more: boolean` to list response schemas",
                     references=[Reference(label="Stripe API conventions", url="https://stripe.com/docs/api")]),
                 severity=CheckSeverity.suggestion)


def check_resource_type_field(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.resource_type_field", "Resource type field",
                                         "responses include object/type/kind", severity=CheckSeverity.suggestion)
    text = _raw(art)
    has_type_field = re.search(r'"(object|type|kind)"\s*:\s*\{', text) is not None
    if has_type_field:
        return _pass("api_surface.resource_type_field", "Resource type field",
                     "responses include object/type/kind", art, "type field found")
    return _fail("api_surface.resource_type_field", "Resource type field",
                 "responses include object/type/kind", art, "no type field in schemas",
                 Fix(action_type=FixActionType.add_jsonld_block, target=art.source_url,
                     payload={"field": "object", "purpose": "resource type discriminator"},
                     summary="Add an object/type/kind field to all resource response schemas",
                     references=[Reference(label="Stripe API conventions", url="https://stripe.com/docs/api")]),
                 severity=CheckSeverity.suggestion)


def check_timestamp_format_unix_int(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.timestamp_format_unix_int", "Unix integer timestamps",
                                         "*_at fields are integer (epoch seconds)", severity=CheckSeverity.suggestion)
    text = _raw(art)
    # Find timestamp-ish fields and check their type. Heuristic: look for
    # patterns like '"created_at": {"type": "<X>"}' for X.
    matches = re.findall(r'"([a-z_]+(_at|_ts))"\s*:\s*\{[^{}]*"type"\s*:\s*"([^"]+)"', text)
    if not matches:
        return CheckResult(
            dimension=DIMENSION, check_id="api_surface.timestamp_format_unix_int",
            title="Unix integer timestamps", goal="*_at fields are integer (epoch seconds)",
            status=CheckStatus.not_detected, severity=CheckSeverity.suggestion,
            mode=CheckMode.mechanical, weight=_W, evidence=_ref(art, "no *_at type info"),
            reason="artifact_unavailable:timestamp_fields:none_in_openapi",
        )
    bad = [(name, t) for name, _, t in matches if t != "integer"]
    if not bad:
        return _pass("api_surface.timestamp_format_unix_int", "Unix integer timestamps",
                     "*_at fields are integer (epoch seconds)", art, f"{len(matches)} timestamps, all integer")
    return _fail("api_surface.timestamp_format_unix_int", "Unix integer timestamps",
                 "*_at fields are integer (epoch seconds)", art, f"non-integer: {bad[:5]}",
                 Fix(action_type=FixActionType.other, target=art.source_url,
                     payload={"fields": [n for n, _ in bad], "expected": "integer (Unix seconds)"},
                     summary="Encode timestamp fields as Unix-seconds integers, not strings",
                     references=[Reference(label="Stripe API conventions", url="https://stripe.com/docs/api")]),
                 severity=CheckSeverity.suggestion)


def check_snake_case_naming(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.snake_case_naming", "snake_case naming",
                                         "field names are snake_case", severity=CheckSeverity.suggestion)
    text = _raw(art)
    # Heuristic: find quoted identifiers used as keys in `properties` and check.
    properties_blocks = re.findall(r'"properties"\s*:\s*\{([^{}]*)\}', text)
    field_names: list[str] = []
    for block in properties_blocks:
        field_names.extend(re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:', block))
    if not field_names:
        return CheckResult(
            dimension=DIMENSION, check_id="api_surface.snake_case_naming",
            title="snake_case naming", goal="field names are snake_case",
            status=CheckStatus.not_detected, severity=CheckSeverity.suggestion,
            mode=CheckMode.mechanical, weight=_W, evidence=_ref(art, "no field names found"),
            reason="artifact_unavailable:field_names:none_in_openapi",
        )
    camel = [n for n in field_names if re.search(r"[a-z][A-Z]", n)]
    if not camel:
        return _pass("api_surface.snake_case_naming", "snake_case naming",
                     "field names are snake_case", art, f"{len(field_names)} fields, none camelCase")
    return _fail("api_surface.snake_case_naming", "snake_case naming",
                 "field names are snake_case", art, f"camelCase: {sorted(set(camel))[:5]}",
                 Fix(action_type=FixActionType.rename_field, target=art.source_url,
                     payload={"camelCase_examples": sorted(set(camel))[:10]},
                     summary="Rename camelCase fields to snake_case",
                     references=[Reference(label="Stripe API conventions", url="https://stripe.com/docs/api")]),
                 severity=CheckSeverity.suggestion)


def check_timestamp_naming_convention(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.timestamp_naming_convention", "Timestamp field naming",
                                         "past=<verb>ed_at, future=<verb>s_at", severity=CheckSeverity.suggestion)
    text = _raw(art)
    # Find time-ish field names; flag those that don't match _at suffix.
    suspects = re.findall(r'"(timestamp|date|time|when|moment)"', text)
    if not suspects:
        return _pass("api_surface.timestamp_naming_convention", "Timestamp field naming",
                     "no generically-named time fields", art, "no offenders")
    return _fail("api_surface.timestamp_naming_convention", "Timestamp field naming",
                 "past=<verb>ed_at, future=<verb>s_at", art, f"generic names: {set(suspects)}",
                 Fix(action_type=FixActionType.rename_field, target=art.source_url,
                     payload={"recommended": "<verb>ed_at for past, <verb>s_at for future"},
                     summary="Rename generic timestamp fields (e.g. 'timestamp', 'date') to <verb>ed_at/<verb>s_at",
                     references=[Reference(label="Stripe API conventions", url="https://stripe.com/docs/api")]),
                 severity=CheckSeverity.suggestion)


def check_no_id_id_suffix(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.no_id_id_suffix", "No `_id_id` patterns",
                                         "redundant _id suffix avoided", severity=CheckSeverity.suggestion)
    text = _raw(art)
    bad = re.findall(r'"([a-z_]+_id_id)"', text)
    if not bad:
        return _pass("api_surface.no_id_id_suffix", "No `_id_id` patterns",
                     "no `*_id_id` field names", art, "ok")
    return _fail("api_surface.no_id_id_suffix", "No `_id_id` patterns",
                 "no `*_id_id` field names", art, f"offenders: {sorted(set(bad))[:5]}",
                 Fix(action_type=FixActionType.rename_field, target=art.source_url,
                     payload={"offenders": sorted(set(bad))},
                     summary="Drop redundant `_id` suffix on already-id-named fields",
                     references=[Reference(label="Stripe API conventions", url="https://stripe.com/docs/api")]),
                 severity=CheckSeverity.suggestion)


def check_http_verb_conventions(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.http_verb_conventions", "HTTP verb conventions",
                                         "POST for create/update; PUT only for full-replace", severity=CheckSeverity.suggestion)
    operations = (art.payload or {}).get("operations", []) or []
    puts = [o for o in operations if o.get("method") == "put"]
    # Heuristic: PUT is suspicious unless the path looks like a singleton (no /:id).
    suspect_puts = [o for o in puts if not re.search(r"\{[^/]+\}", o.get("path", ""))]
    if not suspect_puts:
        return _pass("api_surface.http_verb_conventions", "HTTP verb conventions",
                     "no suspicious PUT usages", art, f"{len(puts)} PUT op(s), none flagged")
    return _fail("api_surface.http_verb_conventions", "HTTP verb conventions",
                 "no suspicious PUT usages", art, f"{len(suspect_puts)} non-replacement PUT op(s)",
                 Fix(action_type=FixActionType.other, target=art.source_url,
                     payload={"suspicious_puts": [o.get("path") for o in suspect_puts]},
                     summary="Use POST for create/update; reserve PUT for full-replacement of an addressable resource",
                     references=[Reference(label="Stripe API conventions", url="https://stripe.com/docs/api")]),
                 severity=CheckSeverity.suggestion)


def check_api_key_prefix(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.api_key_prefix", "API key prefix",
                                         "API key examples use a structured prefix", severity=CheckSeverity.suggestion)
    text = _raw(art)
    if re.search(r"[a-z]{2,5}_(?:sk|pk|live|test)_[a-zA-Z0-9_]+", text):
        return _pass("api_surface.api_key_prefix", "API key prefix",
                     "API key examples use a structured prefix", art, "prefix detected")
    return CheckResult(
        dimension=DIMENSION, check_id="api_surface.api_key_prefix", title="API key prefix",
        goal="API key examples use a structured prefix",
        status=CheckStatus.not_detected, severity=CheckSeverity.suggestion,
        mode=CheckMode.mechanical, weight=_W, evidence=_ref(art, "no prefixed key examples"),
        reason="artifact_unavailable:api_key_examples:none_in_openapi",
    )


def check_rate_limit_shape(store: ArtifactStore, base_url: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected_no_openapi("api_surface.rate_limit_shape", "Rate-limit response shape",
                                         "429 documented with Retry-After", severity=CheckSeverity.suggestion)
    used = set((art.payload or {}).get("response_codes_used", []))
    text = _raw(art)
    has_429 = "429" in used
    has_retry_after = "Retry-After" in text or "retry-after" in text.lower()
    if has_429 and has_retry_after:
        return _pass("api_surface.rate_limit_shape", "Rate-limit response shape",
                     "429 + Retry-After present", art, "429 + Retry-After")
    return _fail("api_surface.rate_limit_shape", "Rate-limit response shape",
                 "429 + Retry-After present", art,
                 f"has_429={has_429}, has_retry_after={has_retry_after}",
                 Fix(action_type=FixActionType.add_response_header, target=art.source_url,
                     payload={"status": 429, "header": "Retry-After"},
                     summary="Document 429 responses with a Retry-After header",
                     references=[Reference(label="RFC 6585", rfc="6585")]),
                 severity=CheckSeverity.suggestion)


# ============================================================================
# Hybrid LLM checks (3) — SKIPPED in v1
# ============================================================================


def check_resource_hierarchy_coherence(store: ArtifactStore, base_url: str, mode: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION, check_id="api_surface.resource_hierarchy_coherence",
            title="Resource hierarchy coherence (LLM)",
            goal="Operations on the same logical resource share a path prefix",
            status=CheckStatus.not_detected, severity=CheckSeverity.suggestion,
            mode=CheckMode.hybrid, weight=_W,
            evidence=HttpExchange(method="GET", url="", status=None),
            reason="precondition_failed:openapi_unreachable",
        )
    return _hybrid_skipped("api_surface.resource_hierarchy_coherence",
                           "Resource hierarchy coherence (LLM)",
                           "Operations on the same logical resource share a path prefix", mode)


def check_boolean_vs_enum_extensibility(store: ArtifactStore, base_url: str, mode: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION, check_id="api_surface.boolean_vs_enum_extensibility",
            title="Boolean-vs-enum extensibility (LLM)",
            goal="Booleans that should grow values are flagged as enum candidates",
            status=CheckStatus.not_detected, severity=CheckSeverity.suggestion,
            mode=CheckMode.hybrid, weight=_W,
            evidence=HttpExchange(method="GET", url="", status=None),
            reason="precondition_failed:openapi_unreachable",
        )
    return _hybrid_skipped("api_surface.boolean_vs_enum_extensibility",
                           "Boolean-vs-enum extensibility (LLM)",
                           "Booleans that should grow values are flagged as enum candidates", mode)


def check_docs_quality(store: ArtifactStore, base_url: str, mode: str) -> CheckResult:
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION, check_id="api_surface.docs_quality",
            title="Docs quality (LLM)",
            goal="Operation/parameter descriptions are meaningful; examples are useful",
            status=CheckStatus.not_detected, severity=CheckSeverity.suggestion,
            mode=CheckMode.hybrid, weight=_W,
            evidence=HttpExchange(method="GET", url="", status=None),
            reason="precondition_failed:openapi_unreachable",
        )
    return _hybrid_skipped("api_surface.docs_quality", "Docs quality (LLM)",
                           "Operation/parameter descriptions are meaningful; examples are useful", mode)


# ============================================================================
# OWASP API Top 10 subset (6)
# ============================================================================


_OWASP_REF = Reference(label="OWASP API Security Top 10 (2023)", url="https://owasp.org/API-Security/editions/2023/en/0x11-t10/")


def _owasp_skip_no_openapi(check_id: str, title: str, goal: str) -> CheckResult:
    return CheckResult(
        dimension=DIMENSION, check_id=check_id, title=title, goal=goal,
        status=CheckStatus.not_detected, severity=CheckSeverity.suggestion,
        mode=CheckMode.mechanical, weight=_W,
        evidence=HttpExchange(method="GET", url="", status=None),
        reason="artifact_unavailable:openapi:not_captured",
    )


def check_owasp_api1_bola(store: ArtifactStore, base_url: str) -> CheckResult:
    """API1: Broken Object Level Authorization. Heuristic: paths with {:id} that
    have no security applied to operations."""
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _owasp_skip_no_openapi("api_surface.owasp_api1_bola", "API1: BOLA — :id paths require auth",
                                       "Paths with {param} require security on every operation")
    operations = (art.payload or {}).get("operations", []) or []
    suspicious = [
        o for o in operations
        if re.search(r"\{[^/]+\}", o.get("path", "")) and not o.get("security")
    ]
    if not suspicious:
        return _pass("api_surface.owasp_api1_bola", "API1: BOLA — :id paths require auth",
                     "all parameterized paths require security", art, f"{len(operations)} ops checked")
    return _fail("api_surface.owasp_api1_bola", "API1: BOLA — :id paths require auth",
                 "all parameterized paths require security", art,
                 f"{len(suspicious)} ops with {{id}}-style path lack security",
                 Fix(action_type=FixActionType.other, target=art.source_url,
                     payload={"affected": [(o.get("method"), o.get("path")) for o in suspicious[:10]]},
                     summary="Add `security` to parameterized-path operations to prevent BOLA",
                     references=[_OWASP_REF]),
                 severity=CheckSeverity.warning)


def check_owasp_api2_broken_auth(store: ArtifactStore, base_url: str) -> CheckResult:
    """API2: Broken Authentication. Heuristic: any auth-related endpoint without security AND
    securitySchemes is empty/missing."""
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _owasp_skip_no_openapi("api_surface.owasp_api2_broken_auth", "API2: Broken Authentication",
                                       "Auth surface declares securitySchemes")
    schemes = (art.payload or {}).get("security_schemes", []) or []
    if schemes:
        return _pass("api_surface.owasp_api2_broken_auth", "API2: Broken Authentication",
                     "components.securitySchemes is non-empty", art, f"schemes={schemes}")
    return _fail("api_surface.owasp_api2_broken_auth", "API2: Broken Authentication",
                 "components.securitySchemes is non-empty", art, "no securitySchemes declared",
                 Fix(action_type=FixActionType.other, target=art.source_url,
                     payload={"action": "declare components.securitySchemes"},
                     summary="Declare auth schemes (e.g. bearer, oauth2) under components.securitySchemes",
                     references=[_OWASP_REF]),
                 severity=CheckSeverity.warning)


def check_owasp_api4_unrestricted_consumption(store: ArtifactStore, base_url: str) -> CheckResult:
    """API4: Unrestricted Resource Consumption. Heuristic: 429 documented + pagination present."""
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _owasp_skip_no_openapi("api_surface.owasp_api4_unrestricted_consumption",
                                       "API4: Unrestricted Resource Consumption",
                                       "Rate limit (429) and pagination present")
    used = set((art.payload or {}).get("response_codes_used", []))
    has_429 = "429" in used
    text = _raw(art)
    has_pagination = '"has_more"' in text or '"limit"' in text or '"per_page"' in text
    if has_429 and has_pagination:
        return _pass("api_surface.owasp_api4_unrestricted_consumption",
                     "API4: Unrestricted Resource Consumption",
                     "429 documented + pagination present", art, "ok")
    return _fail("api_surface.owasp_api4_unrestricted_consumption",
                 "API4: Unrestricted Resource Consumption",
                 "429 documented + pagination present", art,
                 f"has_429={has_429}, has_pagination={has_pagination}",
                 Fix(action_type=FixActionType.add_response_header, target=art.source_url,
                     payload={"missing": ["429" if not has_429 else None, "pagination" if not has_pagination else None]},
                     summary="Document 429 rate-limit responses and add pagination (limit/has_more) to list endpoints",
                     references=[_OWASP_REF]),
                 severity=CheckSeverity.warning)


def check_owasp_api7_ssrf_surface(store: ArtifactStore, base_url: str) -> CheckResult:
    """API7: SSRF. Heuristic: parameters whose name suggests URL input."""
    art = _find_openapi(store, base_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _owasp_skip_no_openapi("api_surface.owasp_api7_ssrf_surface", "API7: SSRF surface",
                                       "Parameters taking URLs as input are flagged for review")
    text = _raw(art)
    suspects = re.findall(r'"name"\s*:\s*"((?:url|uri|link|callback|redirect|fetch|webhook|target)[a-z_]*)"', text, re.IGNORECASE)
    if not suspects:
        return _pass("api_surface.owasp_api7_ssrf_surface", "API7: SSRF surface",
                     "no obvious URL-input parameters", art, "ok")
    return CheckResult(
        dimension=DIMENSION, check_id="api_surface.owasp_api7_ssrf_surface",
        title="API7: SSRF surface",
        goal="URL-input parameters are intentional + validated",
        status=CheckStatus.fail, severity=CheckSeverity.warning, mode=CheckMode.mechanical,
        weight=_W, evidence=_ref(art, f"params: {sorted(set(suspects))[:5]}"),
        fix=Fix(action_type=FixActionType.other, target=art.source_url,
                payload={"params": sorted(set(suspects))},
                summary="Review URL-input parameters for SSRF: validate against allowlist, restrict private IPs",
                references=[_OWASP_REF]),
    )


def check_owasp_api8_security_misconfiguration(store: ArtifactStore, base_url: str) -> CheckResult:
    """API8: Security Misconfiguration. Heuristic: HTTP responses with verbose error/debug headers."""
    candidates = store.find_by_type(ArtifactType.http_response)
    origin = _origin(base_url)
    relevant = [a for a in candidates if a.source_url.startswith(origin) and a.capture_status == CaptureStatus.ok]
    if not relevant:
        return CheckResult(
            dimension=DIMENSION, check_id="api_surface.owasp_api8_security_misconfiguration",
            title="API8: Security Misconfiguration",
            goal="No verbose debug/server-version headers exposed",
            status=CheckStatus.not_detected, severity=CheckSeverity.suggestion,
            mode=CheckMode.mechanical, weight=_W,
            evidence=HttpExchange(method="GET", url=base_url, status=None),
            reason="artifact_unavailable:http_response:no_samples_captured",
        )
    bad: list[tuple[str, str]] = []
    for a in relevant:
        h = (a.payload or {}).get("headers", {}) or {}
        for name in ("x-powered-by", "x-debug", "x-runtime", "x-aspnet-version"):
            if any(k.lower() == name for k in h.keys()):
                bad.append((a.source_url, name))
        # Server header with version
        server = next((v for k, v in h.items() if k.lower() == "server"), "")
        if server and re.search(r"\d+\.\d+", server):
            bad.append((a.source_url, f"server={server}"))
    if not bad:
        return _pass("api_surface.owasp_api8_security_misconfiguration", "API8: Security Misconfiguration",
                     "No verbose debug/server-version headers", relevant[0], f"{len(relevant)} responses checked")
    art = relevant[0]
    return _fail("api_surface.owasp_api8_security_misconfiguration", "API8: Security Misconfiguration",
                 "No verbose debug/server-version headers", art, f"{len(bad)} verbose-header instance(s)",
                 Fix(action_type=FixActionType.modify_response_header, target=art.source_url,
                     payload={"strip": ["X-Powered-By", "X-Debug", "X-Runtime", "Server"][:],
                              "examples": bad[:5]},
                     summary="Strip X-Powered-By, X-Debug, and version-revealing Server headers",
                     references=[_OWASP_REF]),
                 severity=CheckSeverity.warning)


def check_owasp_api9_inventory_management(store: ArtifactStore, base_url: str) -> CheckResult:
    """API9: Improper Inventory. Heuristic: paths in OpenAPI vs paths reachable on the site.
    For v1: just check that an OpenAPI document exists at all (presence is the inventory)."""
    art = _find_openapi(store, base_url)
    if art is None:
        return _fail(
            check_id="api_surface.owasp_api9_inventory_management",
            title="API9: Improper Inventory Management",
            goal="An OpenAPI inventory of endpoints is published",
            art=Artifact(artifact_type=ArtifactType.openapi, source_url=base_url, capture_status=CaptureStatus.not_found, capture_error="no_openapi_inventory"),
            excerpt="no OpenAPI inventory",
            fix=Fix(action_type=FixActionType.add_well_known_resource, target=urljoin(_origin(base_url) + "/", "openapi.json"),
                    payload={"format": "OpenAPI 3.x"},
                    summary="Publish /openapi.json as the canonical API inventory",
                    references=[_OWASP_REF]),
            severity=CheckSeverity.suggestion,
        )
    if art.capture_status != CaptureStatus.ok:
        return _fail("api_surface.owasp_api9_inventory_management", "API9: Improper Inventory Management",
                     "An OpenAPI inventory of endpoints is published", art, art.capture_error or "openapi unparsed",
                     Fix(action_type=FixActionType.other, target=art.source_url,
                         payload={"action": "publish a parseable OpenAPI document"},
                         summary="Make /openapi.json reachable and valid", references=[_OWASP_REF]),
                     severity=CheckSeverity.suggestion)
    return _pass("api_surface.owasp_api9_inventory_management", "API9: Improper Inventory Management",
                 "An OpenAPI inventory of endpoints is published", art, "OpenAPI present")


# ============================================================================
# Analyzer
# ============================================================================


class APISurfaceAnalyzer:
    name: str = DIMENSION.value
    mode_class: CheckMode = CheckMode.hybrid  # has both mechanical + hybrid LLM portions
    depends_on_analyzers: tuple[str, ...] = ()

    async def run(
        self,
        store: ArtifactStore,
        *,
        mode: str = "full",
        prior_results: list[CheckResult] | None = None,
        config: dict | None = None,
    ) -> list[CheckResult]:
        config = config or {}
        url = config.get("base_url") or ""
        t0 = time.perf_counter()
        results = [
            # presence
            check_openapi_present(store, url),
            check_docs_present(store, url),
            check_openapi_valid(store, url),
            check_openapi_examples_present(store, url),
            check_openapi_descriptions_present(store, url),
            check_error_schemas_defined(store, url),
            check_auth_schemes_documented(store, url),
            # stripe-style mechanical
            check_identifier_prefixes(store, url),
            check_approved_status_codes(store, url),
            check_list_endpoint_empty_shape(store, url),
            check_pagination_has_more(store, url),
            check_resource_type_field(store, url),
            check_timestamp_format_unix_int(store, url),
            check_snake_case_naming(store, url),
            check_timestamp_naming_convention(store, url),
            check_no_id_id_suffix(store, url),
            check_http_verb_conventions(store, url),
            check_api_key_prefix(store, url),
            check_rate_limit_shape(store, url),
            # hybrid (LLM portion deferred)
            check_resource_hierarchy_coherence(store, url, mode),
            check_boolean_vs_enum_extensibility(store, url, mode),
            check_docs_quality(store, url, mode),
            # OWASP subset
            check_owasp_api1_bola(store, url),
            check_owasp_api2_broken_auth(store, url),
            check_owasp_api4_unrestricted_consumption(store, url),
            check_owasp_api7_ssrf_surface(store, url),
            check_owasp_api8_security_misconfiguration(store, url),
            check_owasp_api9_inventory_management(store, url),
        ]
        elapsed = (time.perf_counter() - t0) * 1000.0
        for r in results:
            r.elapsed_ms = max(r.elapsed_ms, elapsed / len(results))
        return results


__all__ = ["DIMENSION", "APISurfaceAnalyzer"]
