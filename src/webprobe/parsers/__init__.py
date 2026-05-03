"""Shared artifact parsers (CA017).

Each parser exposes ``parse(raw, source_url=...) -> ParseResult`` taking raw
bytes/text and returning a structured ``ParseResult`` whose ``payload`` is a
JSON-serializable dict suitable for storage in an :class:`Artifact.payload`.

Parsers MUST be graceful on malformed input (CO005): they never raise; they
return a ParseResult with ``ok=False`` and ``error`` populated.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParseResult:
    """Outcome of a parse operation.

    - ``ok``: parser produced a usable structured form.
    - ``payload``: structured form (JSON-serializable). Empty dict on failure.
    - ``error``: short human-readable error string if not ok.
    - ``warnings``: non-fatal issues encountered during parsing.
    - ``elapsed_ms``: time spent parsing (CO011).
    """

    ok: bool
    payload: dict
    error: str = ""
    warnings: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0


from webprobe.parsers import robots_txt, sitemap, openapi, json_ld, meta_tags  # noqa: E402

__all__ = ["ParseResult", "robots_txt", "sitemap", "openapi", "json_ld", "meta_tags"]
