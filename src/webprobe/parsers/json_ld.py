"""JSON-LD extractor for schema.org structured data.

Pulls ``<script type="application/ld+json">`` blocks from a rendered DOM and
parses each as JSON. Supported types in v1 (CA021): Product, Offer,
Organization, AggregateRating, ProductGroup, Article, FAQPage, Recipe.
Microdata and RDFa parsers are deferred to v2.

The parser is tolerant: malformed JSON in one block does not fail the others.
"""

from __future__ import annotations

import json
import re
import time

from webprobe.parsers import ParseResult


_SCRIPT_RE = re.compile(
    r"<script\b[^>]*\btype\s*=\s*[\"']application/ld\+json[\"'][^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)


SUPPORTED_TYPES: frozenset[str] = frozenset(
    {
        "Product",
        "Offer",
        "Organization",
        "AggregateRating",
        "ProductGroup",
        "Article",
        "FAQPage",
        "Recipe",
        "BreadcrumbList",  # Common companion type; recognized but not deeply validated
        "WebSite",
        "WebPage",
    }
)


def _node_types(node: dict) -> list[str]:
    """Return @type as a list (it may be a string or list)."""
    t = node.get("@type")
    if isinstance(t, str):
        return [t]
    if isinstance(t, list):
        return [str(x) for x in t]
    return []


def _flatten(obj, out: list[dict]) -> None:
    """Recursively walk a JSON-LD payload, collecting any node with @type into out."""
    if isinstance(obj, dict):
        if "@graph" in obj and isinstance(obj["@graph"], list):
            for child in obj["@graph"]:
                _flatten(child, out)
            return
        if obj.get("@type"):
            out.append(obj)
            # Walk into known nested type fields too (offers, hasVariant, etc.)
        for v in obj.values():
            if isinstance(v, (dict, list)):
                _flatten(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _flatten(item, out)


def parse(raw: bytes | str, *, source_url: str = "") -> ParseResult:
    """Extract and parse JSON-LD blocks from rendered HTML. Never raises (CO005).

    Returns:
      payload.blocks: list of {raw, parsed: any | None, error?}
      payload.nodes: list of typed nodes (flattened from @graph etc.)
      payload.types: dict[type_name, list[node]] for quick dimension consumption
    """
    started = time.perf_counter()
    if isinstance(raw, bytes):
        try:
            html = raw.decode("utf-8", errors="replace")
        except Exception as e:  # pragma: no cover
            return ParseResult(ok=False, payload={}, error=f"decode_error: {e!r}")
    else:
        html = raw

    blocks: list[dict] = []
    nodes: list[dict] = []
    warnings: list[str] = []

    for match in _SCRIPT_RE.finditer(html):
        body = match.group(1).strip()
        if not body:
            blocks.append({"raw": "", "parsed": None, "error": "empty_block"})
            continue
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as e:
            blocks.append({"raw": body[:500], "parsed": None, "error": f"json_parse_error: {e}"})
            warnings.append(f"json_parse_error_in_block: {e}")
            continue

        blocks.append({"raw": body[:500], "parsed": parsed})
        flat: list[dict] = []
        _flatten(parsed, flat)
        nodes.extend(flat)

    types: dict[str, list[dict]] = {}
    for n in nodes:
        for t in _node_types(n):
            types.setdefault(t, []).append(n)

    payload = {
        "source_url": source_url,
        "blocks": blocks,
        "nodes": nodes,
        "types": types,
    }

    ok = bool(blocks)
    error = "" if ok else "no_jsonld_blocks_found"

    return ParseResult(
        ok=ok,
        payload=payload,
        error=error,
        warnings=warnings,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
    )


# ---- Helpers used by the structured_data dimension ----


def field_value(node: dict, field: str) -> str | None:
    """Extract a string field value, tolerant of {"@value": "..."} forms."""
    v = node.get(field)
    if v is None:
        return None
    if isinstance(v, str):
        return v
    if isinstance(v, dict) and "@value" in v:
        return str(v["@value"])
    if isinstance(v, list) and v:
        first = v[0]
        if isinstance(first, str):
            return first
        if isinstance(first, dict) and "@value" in first:
            return str(first["@value"])
    return None


def has_field(node: dict, field: str) -> bool:
    return field_value(node, field) is not None


def find_offers(product: dict) -> list[dict]:
    """Return Offer nodes attached to a Product (offers may be a single dict or a list)."""
    offers = product.get("offers")
    if offers is None:
        return []
    if isinstance(offers, dict):
        return [offers]
    if isinstance(offers, list):
        return [o for o in offers if isinstance(o, dict)]
    return []


def find_variants(product: dict) -> list[dict]:
    """Return variant nodes via hasVariant or isVariantOf/ProductGroup."""
    variants = product.get("hasVariant")
    if isinstance(variants, list):
        return [v for v in variants if isinstance(v, dict)]
    if isinstance(variants, dict):
        return [variants]
    return []
