"""Meta-tag and head-element extractor.

Pulls signals used by the public_facing_signals dimension (and others):
- HTML <title>
- <meta name="description">, viewport, robots, generator
- OpenGraph (og:*) tags
- Twitter Card (twitter:*) tags
- <link rel="canonical">, <link rel="alternate" hreflang="*">
- Heading hierarchy (h1..h6 counts and first text)
- Image alt-text coverage
- HTTP Link headers (when passed as ``link_header_values``)

Uses stdlib html.parser — graceful on malformed input (CO005).
"""

from __future__ import annotations

import re
import time
from html.parser import HTMLParser

from webprobe.parsers import ParseResult


class _MetaExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self._in_title = False
        self.meta: list[dict] = []
        self.links: list[dict] = []
        self.headings: dict[str, list[str]] = {f"h{i}": [] for i in range(1, 7)}
        self._current_heading: str | None = None
        self._heading_buf: list[str] = []
        self.images: list[dict] = []
        self.lang_attr: str = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html":
            self.lang_attr = a.get("lang", "")
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            self.meta.append(a)
        elif tag == "link":
            self.links.append(a)
        elif tag in self.headings:
            self._current_heading = tag
            self._heading_buf = []
        elif tag == "img":
            self.images.append(
                {
                    "src": a.get("src", ""),
                    "alt": a.get("alt"),  # None if missing entirely
                    "has_alt_attr": "alt" in a,
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag in self.headings and self._current_heading == tag:
            text = " ".join(self._heading_buf).strip()
            if text:
                self.headings[tag].append(text)
            self._current_heading = None
            self._heading_buf = []

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
        if self._current_heading is not None:
            self._heading_buf.append(data)


def _parse_link_header(value: str) -> list[dict]:
    """Parse a single Link header value (possibly comma-separated).

    Returns list of {url, rel, params}. Tolerant of commas inside quoted params
    (rare for Link headers, but handled by a simple state machine).
    """
    out: list[dict] = []
    # Split on commas that are NOT inside angle brackets or quotes.
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    in_quote = False
    for ch in value:
        if ch == '"' and depth == 0:
            in_quote = not in_quote
            buf.append(ch)
        elif ch == "<" and not in_quote:
            depth += 1
            buf.append(ch)
        elif ch == ">" and not in_quote:
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0 and not in_quote:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())

    for part in parts:
        if not part:
            continue
        m = re.match(r"<([^>]*)>\s*(.*)", part)
        if not m:
            continue
        url = m.group(1)
        rest = m.group(2).strip()
        params: dict[str, str] = {}
        for kv in rest.split(";"):
            kv = kv.strip()
            if not kv:
                continue
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k.strip().lower()] = v.strip().strip('"')
        out.append({"url": url, "rel": params.get("rel", ""), "params": params})
    return out


def parse(
    raw: bytes | str,
    *,
    source_url: str = "",
    link_header_values: list[str] | None = None,
) -> ParseResult:
    """Extract meta-level signals from rendered HTML. Never raises (CO005).

    ``link_header_values`` is the list of HTTP Link header values for the same
    URL. Passing it lets the dimension see both DOM and header link relations
    without re-fetching.
    """
    started = time.perf_counter()
    if isinstance(raw, bytes):
        try:
            html = raw.decode("utf-8", errors="replace")
        except Exception as e:  # pragma: no cover
            return ParseResult(ok=False, payload={}, error=f"decode_error: {e!r}")
    else:
        html = raw

    extractor = _MetaExtractor()
    try:
        extractor.feed(html)
    except Exception as e:  # html.parser is generally tolerant; this is a safety net
        return ParseResult(
            ok=False,
            payload={"source_url": source_url},
            error=f"html_parse_error: {e!r}",
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    title = "".join(extractor.title_parts).strip()

    # Categorize meta tags.
    description = ""
    robots = ""
    viewport = ""
    generator = ""
    og: dict[str, str] = {}
    twitter: dict[str, str] = {}
    other_meta: list[dict] = []
    for m in extractor.meta:
        name = (m.get("name") or "").lower()
        prop = (m.get("property") or "").lower()
        content = m.get("content", "")
        if name == "description":
            description = content
        elif name == "robots":
            robots = content
        elif name == "viewport":
            viewport = content
        elif name == "generator":
            generator = content
        elif prop.startswith("og:"):
            og[prop[3:]] = content
        elif name.startswith("twitter:") or prop.startswith("twitter:"):
            key = (name or prop).split(":", 1)[1]
            twitter[key] = content
        else:
            other_meta.append({"name": name, "property": prop, "content": content})

    # Categorize link tags.
    canonical = ""
    alternates: list[dict] = []
    icon: list[str] = []
    well_known_relations: list[dict] = []
    for link in extractor.links:
        rel = (link.get("rel") or "").lower().strip()
        href = link.get("href", "")
        if rel == "canonical":
            canonical = href
        elif rel == "alternate":
            alternates.append(
                {
                    "href": href,
                    "hreflang": link.get("hreflang", ""),
                    "type": link.get("type", ""),
                }
            )
        elif rel in ("icon", "shortcut icon", "apple-touch-icon"):
            icon.append(href)
        elif rel in (
            "service-desc",
            "service-doc",
            "api-catalog",
            "describedby",
            "help",
            "license",
            "next",
            "prev",
        ):
            well_known_relations.append({"rel": rel, "href": href})

    # HTTP Link headers (RFC 8288).
    parsed_link_headers: list[dict] = []
    for value in link_header_values or []:
        parsed_link_headers.extend(_parse_link_header(value))

    images_total = len(extractor.images)
    images_with_alt = sum(1 for i in extractor.images if i["has_alt_attr"])
    images_with_meaningful_alt = sum(
        1 for i in extractor.images if (i["alt"] or "").strip()
    )
    alt_coverage = (images_with_meaningful_alt / images_total) if images_total else None

    payload = {
        "source_url": source_url,
        "lang": extractor.lang_attr,
        "title": title,
        "title_length": len(title),
        "description": description,
        "description_length": len(description),
        "robots_meta": robots,
        "viewport": viewport,
        "generator": generator,
        "og": og,
        "twitter": twitter,
        "other_meta": other_meta,
        "canonical": canonical,
        "alternates": alternates,
        "icons": icon,
        "well_known_relations": well_known_relations,
        "link_headers": parsed_link_headers,
        "headings": {tag: list(titles) for tag, titles in extractor.headings.items()},
        "images_total": images_total,
        "images_with_alt_attr": images_with_alt,
        "images_with_meaningful_alt": images_with_meaningful_alt,
        "alt_text_coverage": alt_coverage,
    }

    return ParseResult(
        ok=True,
        payload=payload,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
    )
