# === Site Mapper (src_webprobe_mapper) v1 ===
#  Dependencies: asyncio, re, time, xml.etree.ElementTree, datetime, html.parser, typing, urllib.parse, aiohttp, webprobe.auth, webprobe.config, webprobe.models
# Phase 1 site mapping module: discovers site structure via robots.txt parsing, sitemap extraction, and BFS crawling with authentication-aware link discovery. Builds a SiteGraph with nodes and edges for subsequent analysis phases.

# Module invariants:
#   - All URLs are normalized before use in graph construction
#   - Crawl respects max_nodes and max_depth limits from config
#   - robots.txt disallowed paths honored when config.crawl.respect_robots=True
#   - External links not followed when config.crawl.follow_external=False
#   - Auth detection: status 401/403 or auth redirect indicates requires_auth=True
#   - Nodes appearing in both anonymous and authenticated passes marked as public (requires_auth=False)
#   - 30 second timeout enforced on all HTTP requests

class _LinkExtractor:
    """HTML parser that extracts href from <a> tags and action from <form> tags, accumulating link text for anchor tags."""
    links: list[tuple[str, str]]             # required, Accumulated (href, link_text) or (action, '') pairs
    _current_link: str | None                # required, Currently open anchor href, or None if not inside <a> tag
    _current_text: list[str]                 # required, Text fragments accumulated inside current <a> tag

def normalize_url(
    url: str,
    base: str | None = None,
) -> str:
    """
    Normalize a URL: resolve relative URLs against base, strip fragment, lowercase scheme/host, remove default ports, collapse double slashes, strip trailing slash (except root).

    Postconditions:
      - Returns empty string if URL lacks scheme or netloc
      - Scheme and netloc are lowercased
      - Default ports (:80 for http, :443 for https) are removed
      - Fragment identifier is removed
      - Path has double slashes collapsed to single slashes
      - Trailing slash stripped unless path is root '/'
      - Relative URLs are resolved against base if provided

    Side effects: none
    Idempotent: no
    """
    ...

def is_same_origin(
    url: str,
    base_url: str,
) -> bool:
    """
    Check if url has same scheme, host, and port as base_url.

    Postconditions:
      - Returns True if scheme and netloc (host:port) match
      - Returns False otherwise

    Side effects: none
    Idempotent: no
    """
    ...

def extract_links(
    html: str,
) -> list[tuple[str, str]]:
    """
    Extract (href, link_text) pairs from HTML by parsing <a> tags and <form> action attributes.

    Postconditions:
      - Returns list of (href, link_text) tuples
      - Form actions appear with empty string as link_text
      - Parsing exceptions are silently suppressed

    Errors:
      - parse_error (Exception): HTML parsing raises Exception
          handling: silently caught and ignored

    Side effects: none
    Idempotent: no
    """
    ...

def parse_robots_txt(
    text: str,
    base_url: str,
) -> tuple[list[str], list[str]]:
    """
    Parse robots.txt content to extract disallowed paths and sitemap URLs.

    Postconditions:
      - Returns (disallowed_paths, sitemap_urls)
      - Disallowed paths extracted from 'Disallow:' directives
      - Sitemap URLs extracted from 'Sitemap:' directives
      - Empty paths/URLs are filtered out
      - All values are stripped of whitespace

    Side effects: none
    Idempotent: no
    """
    ...

def parse_sitemap(
    xml_text: str,
) -> list[str]:
    """
    Parse sitemap XML (handles both sitemap indexes and URL sets) to extract location URLs.

    Postconditions:
      - Returns list of URLs found in <loc> elements
      - Handles namespace-prefixed XML
      - Extracts URLs from both <sitemap> and <url> elements
      - Returns empty list on XML parse errors

    Errors:
      - xml_parse_error (ET.ParseError): xml_text is malformed XML
          handling: returns empty list

    Side effects: none
    Idempotent: no
    """
    ...

async def _fetch(
    session: aiohttp.ClientSession,
    url: str,
    delay_ms: int = 0,
) -> tuple[int, str, str, float]:
    """
    Fetch a URL using aiohttp with optional delay. Returns status code, body, final URL after redirects, and duration in milliseconds.

    Postconditions:
      - Returns (status_code, body, final_url, duration_ms)
      - Follows redirects automatically
      - On exception, returns (0, '', original_url, duration_ms)
      - Body text encoding errors are replaced
      - 30 second total timeout enforced

    Errors:
      - network_error (Exception): Any exception during fetch (timeout, connection error, etc.)
          handling: returns (0, '', url, duration_ms)

    Side effects: Network I/O, Sleeps if delay_ms > 0
    Idempotent: no
    """
    ...

async def _crawl_pass(
    base_url: str,
    seed_urls: Sequence[str],
    config: WebprobeConfig,
    auth_manager: AuthManager | None = None,
    auth_context: AuthContext = AuthContext.anonymous,
    disallowed_paths: Sequence[str] = (),
) -> tuple[dict[str, Node], list[Edge]]:
    """
    BFS crawl starting from base_url and seed_urls. Respects max depth, robots.txt, exclude patterns, and auth context. Returns discovered nodes and edges.

    Postconditions:
      - Returns (nodes_dict, edges_list) where keys are normalized URLs
      - Respects config.crawl.max_nodes limit
      - Respects config.crawl.max_depth limit
      - Filters URLs by config.crawl.url_exclude_patterns
      - Respects robots.txt disallowed paths if config.crawl.respect_robots=True
      - Does not follow external links if config.crawl.follow_external=False
      - Nodes marked requires_auth=True if status is 401/403 or auth redirect detected
      - Edges created for all links found in 200 responses

    Side effects: Creates aiohttp.ClientSession, Makes HTTP requests via _fetch
    Idempotent: no
    """
    ...

async def map_site(
    config: WebprobeConfig,
    url: str,
    framework_routes: Sequence[str] | None = None,
) -> tuple[SiteGraph, PhaseStatus]:
    """
    Phase 1 site mapping orchestrator. Fetches robots.txt, parses sitemaps, performs anonymous and authenticated crawl passes, merges results into SiteGraph with auth requirements identified.

    Postconditions:
      - Returns (SiteGraph, PhaseStatus)
      - PhaseStatus tracks timing and completion
      - SiteGraph contains merged nodes from anonymous and authenticated passes
      - Nodes accessible in both passes marked requires_auth=False
      - Nodes only in authenticated pass marked requires_auth=True
      - Nodes only in anonymous pass with no auth indicators marked requires_auth=False
      - Edges deduplicated by (source, target, auth_context)
      - Fetches robots.txt and processes sitemaps (including nested)
      - Adds framework_routes to seed_urls if provided
      - Authenticated crawl only runs if auth_manager.has_auth=True

    Side effects: Creates aiohttp sessions, Makes multiple HTTP requests, Updates PhaseStatus timestamps
    Idempotent: no
    """
    ...

def __init__() -> None:
    """
    _LinkExtractor constructor. Initializes HTMLParser and link collection state.

    Postconditions:
      - self.links initialized to empty list
      - self._current_link initialized to None
      - self._current_text initialized to empty list

    Side effects: none
    Idempotent: no
    """
    ...

def handle_starttag(
    tag: str,
    attrs: list[tuple[str, str | None]],
) -> None:
    """
    HTMLParser callback for start tags. Captures href from <a> tags and action from <form> tags.

    Postconditions:
      - If tag='a' with 'href' attribute, sets _current_link and resets _current_text
      - If tag='form' with 'action' attribute, appends (action, '') to links
      - None or empty attribute values default to empty string

    Side effects: none
    Idempotent: no
    """
    ...

def handle_data(
    data: str,
) -> None:
    """
    HTMLParser callback for text data. Accumulates text content inside <a> tags.

    Postconditions:
      - If inside <a> tag (_current_link is not None), appends data to _current_text

    Side effects: none
    Idempotent: no
    """
    ...

def handle_endtag(
    tag: str,
) -> None:
    """
    HTMLParser callback for end tags. Finalizes link extraction for </a> tags.

    Postconditions:
      - If tag='a' and _current_link is set, joins accumulated text and appends (href, text) to links
      - Resets _current_link and _current_text to None and empty list

    Side effects: none
    Idempotent: no
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['_LinkExtractor', 'normalize_url', 'is_same_origin', 'extract_links', 'parse_robots_txt', 'parse_sitemap', '_fetch', '_crawl_pass', 'map_site', 'handle_starttag', 'handle_data', 'handle_endtag']
