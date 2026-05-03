"""OpenAPI document parser (JSON or YAML, OpenAPI 3.x).

Loads + validates the basic shape and exposes summary structures used by the
api_surface dimension: paths × methods, parameters, examples coverage,
description coverage, security schemes, response schemas. Deeper validation
(deep schema validity, $ref resolution) is deferred to v2.
"""

from __future__ import annotations

import json
import time

import yaml

from webprobe.parsers import ParseResult


def _load(text: str) -> tuple[dict | None, str | None]:
    """Try JSON then YAML. Returns (doc, error)."""
    text_stripped = text.lstrip()
    if text_stripped.startswith("{") or text_stripped.startswith("["):
        try:
            return json.loads(text), None
        except json.JSONDecodeError as e:
            return None, f"json_parse_error: {e}"
    try:
        loaded = yaml.safe_load(text)
        if not isinstance(loaded, dict):
            return None, f"yaml_root_not_mapping: got {type(loaded).__name__}"
        return loaded, None
    except yaml.YAMLError as e:
        return None, f"yaml_parse_error: {e}"


def parse(raw: bytes | str, *, source_url: str = "") -> ParseResult:
    """Parse an OpenAPI document. Never raises (CO005)."""
    started = time.perf_counter()
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception as e:  # pragma: no cover
            return ParseResult(ok=False, payload={}, error=f"decode_error: {e!r}")
    else:
        text = raw

    if not text.strip():
        return ParseResult(ok=False, payload={}, error="empty_payload")

    doc, err = _load(text)
    if doc is None:
        return ParseResult(
            ok=False,
            payload={"source_url": source_url},
            error=err or "unknown_load_error",
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    warnings: list[str] = []
    openapi_version = doc.get("openapi") or doc.get("swagger") or ""
    if not openapi_version:
        warnings.append("missing_openapi_version")
    if isinstance(openapi_version, str) and openapi_version.startswith("2."):
        warnings.append("swagger_2_format_partial_support")

    info = doc.get("info") or {}
    paths = doc.get("paths") or {}
    components = doc.get("components") or {}
    security_schemes = (components.get("securitySchemes") or {}) if isinstance(components, dict) else {}

    operations: list[dict] = []
    response_codes: set[str] = set()
    examples_count = 0
    operations_with_descriptions = 0
    operations_with_examples = 0
    error_responses_with_schemas = 0
    error_responses_total = 0

    for path, path_item in paths.items() if isinstance(paths, dict) else []:
        if not isinstance(path_item, dict):
            warnings.append(f"path_item_not_mapping: {path}")
            continue
        for method in ("get", "put", "post", "delete", "patch", "options", "head", "trace"):
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            op_summary: dict = {
                "path": path,
                "method": method,
                "operation_id": op.get("operationId", ""),
                "summary": op.get("summary", ""),
                "description": op.get("description", ""),
                "parameters": [],
                "responses": [],
                "security": op.get("security") or [],
            }
            if op_summary["description"] or op_summary["summary"]:
                operations_with_descriptions += 1

            for param in op.get("parameters") or []:
                if not isinstance(param, dict):
                    continue
                op_summary["parameters"].append(
                    {
                        "name": param.get("name", ""),
                        "in": param.get("in", ""),
                        "required": param.get("required", False),
                        "description": param.get("description", ""),
                        "has_example": "example" in param or "examples" in param,
                    }
                )

            request_body = op.get("requestBody")
            op_summary["request_body_examples"] = 0
            if isinstance(request_body, dict):
                content = request_body.get("content") or {}
                for media in content.values():
                    if not isinstance(media, dict):
                        continue
                    if "example" in media or "examples" in media:
                        op_summary["request_body_examples"] += 1

            for code, resp in (op.get("responses") or {}).items():
                response_codes.add(str(code))
                if not isinstance(resp, dict):
                    continue
                content = resp.get("content") or {}
                has_schema = False
                has_example = False
                for media in content.values():
                    if not isinstance(media, dict):
                        continue
                    if "schema" in media:
                        has_schema = True
                    if "example" in media or "examples" in media:
                        has_example = True
                op_summary["responses"].append(
                    {
                        "code": str(code),
                        "description": resp.get("description", ""),
                        "has_schema": has_schema,
                        "has_example": has_example,
                    }
                )
                if str(code).startswith(("4", "5")):
                    error_responses_total += 1
                    if has_schema:
                        error_responses_with_schemas += 1
                if has_example:
                    examples_count += 1
                    operations_with_examples += 1

            operations.append(op_summary)

    payload = {
        "source_url": source_url,
        "version": openapi_version,
        "info": {
            "title": info.get("title", ""),
            "version": info.get("version", ""),
            "description": info.get("description", ""),
        },
        "operations": operations,
        "operation_count": len(operations),
        "operations_with_descriptions": operations_with_descriptions,
        "operations_with_examples": operations_with_examples,
        "response_codes_used": sorted(response_codes),
        "error_responses_total": error_responses_total,
        "error_responses_with_schemas": error_responses_with_schemas,
        "examples_count": examples_count,
        "security_schemes": list(security_schemes.keys()) if isinstance(security_schemes, dict) else [],
    }

    return ParseResult(
        ok=True,
        payload=payload,
        warnings=warnings,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
    )
