"""Sitemap XML parser.

Supports the standard sitemap format and sitemap-index format from
sitemaps.org. Tolerant of namespace variations and minor schema deviations.

Reference: https://www.sitemaps.org/protocol.html
"""

from __future__ import annotations

import time
from xml.etree import ElementTree as ET

from webprobe.parsers import ParseResult


# Namespace map covering the canonical sitemap namespace and extensions we
# care about. Lookups use ElementTree's local-name fallback if no namespace
# matches.
_NS = {
    "sm": "http://www.sitemaps.org/schemas/sitemap/0.9",
}


def _local(tag: str) -> str:
    """Strip XML namespace from a tag for tolerant matching."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def parse(raw: bytes | str, *, source_url: str = "") -> ParseResult:
    """Parse a sitemap XML payload. Detects sitemap vs sitemap-index automatically.

    Never raises (CO005). Returns:
      - payload.kind: "urlset" | "sitemapindex" | "unknown"
      - payload.urls: list[{loc, lastmod?, changefreq?, priority?}] (urlset)
      - payload.sitemaps: list[{loc, lastmod?}] (sitemapindex)
    """
    started = time.perf_counter()
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception as e:  # pragma: no cover
            return ParseResult(ok=False, payload={}, error=f"decode_error: {e!r}")
    else:
        text = raw

    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        return ParseResult(
            ok=False,
            payload={"kind": "unknown", "urls": [], "sitemaps": [], "source_url": source_url},
            error=f"xml_parse_error: {e}",
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    root_local = _local(root.tag)
    payload: dict = {
        "kind": "unknown",
        "urls": [],
        "sitemaps": [],
        "source_url": source_url,
    }
    warnings: list[str] = []

    if root_local == "urlset":
        payload["kind"] = "urlset"
        for url_elem in root:
            if _local(url_elem.tag) != "url":
                continue
            entry: dict = {}
            for child in url_elem:
                name = _local(child.tag)
                if name in ("loc", "lastmod", "changefreq", "priority"):
                    entry[name] = (child.text or "").strip()
            if "loc" in entry:
                payload["urls"].append(entry)
            else:
                warnings.append("url_without_loc")

    elif root_local == "sitemapindex":
        payload["kind"] = "sitemapindex"
        for sm_elem in root:
            if _local(sm_elem.tag) != "sitemap":
                continue
            entry = {}
            for child in sm_elem:
                name = _local(child.tag)
                if name in ("loc", "lastmod"):
                    entry[name] = (child.text or "").strip()
            if "loc" in entry:
                payload["sitemaps"].append(entry)
            else:
                warnings.append("sitemap_without_loc")
    else:
        return ParseResult(
            ok=False,
            payload=payload,
            error=f"unknown_root_element: {root_local}",
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    return ParseResult(
        ok=True,
        payload=payload,
        warnings=warnings,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
    )
