# === Framework Route Detection (src_webprobe_frameworks) v1 ===
#  Dependencies: pathlib, re
# Auto-detects web framework types (Astro, Next.js, SvelteKit) from project root directories and extracts URL routes from their file-based routing conventions. Converts filesystem paths to URL patterns with support for dynamic segments.

# Module invariants:
#   - All routes produced start with '/'
#   - All route lists are sorted and deduplicated
#   - Dynamic segment conversions: [param] -> :param, [...rest] -> *rest
#   - Astro extensions: .astro, .md, .mdx, .html
#   - Next.js extensions: .tsx, .jsx, .ts, .js
#   - SvelteKit page file pattern: +page.svelte
#   - Framework detection is order-dependent: Astro, Next.js, SvelteKit

Path = primitive  # pathlib.Path - filesystem path object

def _path_to_route(
    filepath: Path,
    pages_dir: Path,
    strip_extensions: tuple[str, ...],
) -> str:
    """
    Convert a file path under a pages directory to a URL route. Strips file extensions, converts 'index' to root, and transforms dynamic segments ([param] -> :param, [...rest] -> *rest).

    Preconditions:
      - filepath must be relative to or under pages_dir for relative_to() to succeed

    Postconditions:
      - Returns a route string starting with '/'
      - File extensions in strip_extensions are removed from the last path component
      - Path segments named 'index' at the end are removed
      - Dynamic segments [param] are converted to :param
      - Catch-all segments [...rest] are converted to *rest

    Errors:
      - ValueError (ValueError): filepath is not relative to pages_dir
          raised_by: filepath.relative_to(pages_dir)

    Side effects: none
    Idempotent: yes
    """
    ...

def detect_astro(
    project_root: Path,
) -> list[str]:
    """
    Detect routes from an Astro project by scanning src/pages/** for .astro, .md, .mdx, .html files. Also checks web/src/pages for monorepo patterns.

    Postconditions:
      - Returns sorted list of unique route strings
      - Returns empty list if src/pages and web/src/pages directories don't exist
      - All returned routes start with '/'
      - Routes are deduplicated via set conversion

    Side effects: Reads filesystem to check directory existence (is_dir), Recursively scans directories for files matching extensions
    Idempotent: yes
    """
    ...

def detect_nextjs(
    project_root: Path,
) -> list[str]:
    """
    Detect routes from a Next.js project supporting both App Router (app/**/page.{tsx,jsx,ts,js}) and Pages Router (pages/**/*.{tsx,jsx,ts,js}). Excludes files starting with underscore in Pages Router.

    Postconditions:
      - Returns sorted list of unique route strings
      - Returns empty list if neither app/ nor pages/ directories exist
      - All returned routes start with '/'
      - Routes are deduplicated via set conversion
      - Files starting with _ in pages/ are excluded

    Side effects: Reads filesystem to check directory existence (is_dir), Recursively scans app/ for page.{tsx,jsx,ts,js} files, Recursively scans pages/ for *.{tsx,jsx,ts,js} files
    Idempotent: yes
    """
    ...

def detect_sveltekit(
    project_root: Path,
) -> list[str]:
    """
    Detect routes from a SvelteKit project by scanning src/routes/**/ for +page.svelte files.

    Postconditions:
      - Returns sorted list of unique route strings
      - Returns empty list if src/routes directory doesn't exist
      - All returned routes start with '/'
      - Routes are deduplicated via set conversion

    Side effects: Reads filesystem to check directory existence (is_dir), Recursively scans src/routes for +page.svelte files
    Idempotent: yes
    """
    ...

def detect_framework(
    project_root: Path,
) -> tuple[str | None, list[str]]:
    """
    Auto-detect web framework type from project root by checking for framework-specific config files, then extract routes. Checks in order: Astro (astro.config.*), Next.js (next.config.*), SvelteKit (svelte.config.*).

    Postconditions:
      - Returns (framework_name, routes) tuple
      - framework_name is 'astro', 'nextjs', 'sveltekit', or None
      - If framework detected, routes are extracted using corresponding detector function
      - If no framework detected, returns (None, [])
      - Detection order: Astro -> Next.js -> SvelteKit
      - Also checks web/astro.config.* for monorepo Astro projects

    Side effects: Reads filesystem to glob for config files, Delegates to framework-specific detector which performs additional filesystem reads
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['_path_to_route', 'detect_astro', 'detect_nextjs', 'detect_sveltekit', 'detect_framework']
