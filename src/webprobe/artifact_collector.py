"""Artifact collection helpers for Phase 2 capture (CA003).

Bridges the existing NodeCapture flow into the canonical ArtifactStore by
deriving per-URL Artifacts (dom, meta_tags, json_ld, http_response) from a
single capture and writing them to the store with mask redaction applied to
any AUTH-tier headers/cookies (CO008).

robots.txt, sitemap, and OpenAPI artifacts are produced separately by the
mapper / dimension probes; this module is per-page only.
"""

from __future__ import annotations

import logging
import re
from typing import Iterable

from webprobe.artifact_store import ArtifactStore
from webprobe.models import (
    Artifact,
    ArtifactType,
    CaptureStatus,
    NodeCapture,
)
from webprobe.parsers import json_ld as json_ld_parser
from webprobe.parsers import meta_tags as meta_tags_parser

logger = logging.getLogger(__name__)


# Headers that may carry AUTH-tier values (CO008). Comparison is
# case-insensitive on the header name.
_REDACTABLE_HEADERS: tuple[str, ...] = (
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-session-token",
)

# Patterns that often appear in header values themselves (bearer tokens, etc.).
_REDACT_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(Bearer\s+)\S+", re.IGNORECASE),
    re.compile(r"(Basic\s+)\S+", re.IGNORECASE),
    re.compile(r"(api[_-]?key=)[^&\s;]+", re.IGNORECASE),
    re.compile(r"(token=)[^&\s;]+", re.IGNORECASE),
)

_REDACTED_TOKEN = "[REDACTED]"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a new dict with AUTH-tier headers replaced by [REDACTED] (CO008).

    Names are matched case-insensitively. Other header values are scanned for
    common credential patterns (Bearer, Basic, api_key=, token=) and the
    secret portion is masked while the structure is preserved.
    """
    redacted: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in _REDACTABLE_HEADERS:
            redacted[name] = _REDACTED_TOKEN
            continue
        new_value = value
        for pat in _REDACT_VALUE_PATTERNS:
            new_value = pat.sub(lambda m: m.group(1) + _REDACTED_TOKEN, new_value)
        redacted[name] = new_value
    return redacted


def collect_from_capture(
    *,
    url: str,
    capture: NodeCapture,
    raw_html: str | None,
    store: ArtifactStore,
) -> list[str]:
    """Build artifacts from a NodeCapture and persist them to the store.

    Returns the list of artifact_ids written. Existing artifacts for the same
    (type, url) are replaced (capture is the source of truth for its URL).

    - http_response: always written (status, redacted headers).
    - dom: written when raw_html is provided (truncated to 1MB to bound storage).
    - json_ld: written when raw_html contains JSON-LD; capture_status reflects parse.
    - meta_tags: written when raw_html is provided; capture_status reflects parse.
    """
    written: list[str] = []

    # http_response artifact (always)
    redacted = redact_headers(capture.response_headers.raw)
    http_payload: dict = {
        "status": capture.http_status,
        "headers": redacted,
        "auth_context": capture.auth_context.value,
    }
    if capture.timing is not None:
        http_payload["elapsed_ms"] = capture.timing.duration_ms
    http_status = (
        CaptureStatus.ok if capture.http_status is not None else CaptureStatus.network_error
    )
    http_artifact = Artifact(
        artifact_type=ArtifactType.http_response,
        source_url=url,
        capture_status=http_status,
        capture_error="" if http_status == CaptureStatus.ok else "no_http_status",
        payload=http_payload,
        elapsed_ms=capture.timing.duration_ms if capture.timing else 0.0,
    )
    written.append(store.put(http_artifact, replace=True))

    if raw_html is None:
        return written

    # dom artifact (truncated)
    dom_truncated = raw_html if len(raw_html) <= 1_000_000 else raw_html[:1_000_000]
    dom_artifact = Artifact(
        artifact_type=ArtifactType.dom,
        source_url=url,
        capture_status=CaptureStatus.ok,
        payload={"length": len(raw_html), "truncated": len(raw_html) > 1_000_000},
        raw_bytes=dom_truncated.encode("utf-8", errors="replace"),
    )
    written.append(store.put(dom_artifact, replace=True))

    # meta_tags artifact (parsed from DOM)
    link_header_values: list[str] = []
    for name, value in capture.response_headers.raw.items():
        if name.lower() == "link":
            link_header_values.append(value)
    meta_result = meta_tags_parser.parse(
        raw_html, source_url=url, link_header_values=link_header_values
    )
    meta_artifact = Artifact(
        artifact_type=ArtifactType.meta_tags,
        source_url=url,
        capture_status=CaptureStatus.ok if meta_result.ok else CaptureStatus.parse_error,
        capture_error=meta_result.error,
        payload=meta_result.payload,
        elapsed_ms=meta_result.elapsed_ms,
    )
    written.append(store.put(meta_artifact, replace=True))

    # json_ld artifact (parsed from DOM)
    jl_result = json_ld_parser.parse(raw_html, source_url=url)
    if jl_result.ok or jl_result.error == "no_jsonld_blocks_found":
        # Both 'has blocks' and 'no blocks' are useful: dimensions need to know
        # the page was scanned and either had or did not have JSON-LD.
        jl_status = CaptureStatus.ok if jl_result.ok else CaptureStatus.not_found
        jl_error = "" if jl_result.ok else jl_result.error
    else:
        jl_status = CaptureStatus.parse_error
        jl_error = jl_result.error
    jl_artifact = Artifact(
        artifact_type=ArtifactType.json_ld,
        source_url=url,
        capture_status=jl_status,
        capture_error=jl_error,
        payload=jl_result.payload,
        elapsed_ms=jl_result.elapsed_ms,
    )
    written.append(store.put(jl_artifact, replace=True))

    logger.debug(
        "artifact_collector.persisted",
        extra={"url": url, "count": len(written)},
    )
    return written


def collect_from_graph(graph_captures: Iterable[tuple[str, NodeCapture, str | None]], store: ArtifactStore) -> int:
    """Bulk-collect artifacts for a sequence of (url, capture, raw_html) triples.

    Useful when the capturer aggregates captures and post-processes after
    Phase 2. Returns the total artifact count written.
    """
    count = 0
    for url, capture, raw_html in graph_captures:
        count += len(collect_from_capture(url=url, capture=capture, raw_html=raw_html, store=store))
    return count
