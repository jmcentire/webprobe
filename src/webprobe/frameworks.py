"""Optional framework route detection from a project root directory."""

from __future__ import annotations

import re
from pathlib import Path


def _path_to_route(filepath: Path, pages_dir: Path, strip_extensions: tuple[str, ...]) -> str:
    """Convert a file path under a pages directory to a URL route."""
    rel = filepath.relative_to(pages_dir)
    parts = list(rel.parts)
    # Strip extension from last part
    if parts:
        name = parts[-1]
        for ext in strip_extensions:
            if name.endswith(ext):
                name = name[: -len(ext)]
                break
        parts[-1] = name

    # index -> /
    if parts and parts[-1] == "index":
        parts = parts[:-1]

    # Convert dynamic segments: [param] -> :param, [...rest] -> *rest
    converted = []
    for p in parts:
        if p.startswith("[...") and p.endswith("]"):
            converted.append(f"*{p[4:-1]}")
        elif p.startswith("[") and p.endswith("]"):
            converted.append(f":{p[1:-1]}")
        else:
            converted.append(p)

    route = "/" + "/".join(converted)
    return route


def detect_astro(project_root: Path) -> list[str]:
    """Detect routes from an Astro project (src/pages/**)."""
    pages_dir = project_root / "src" / "pages"
    if not pages_dir.is_dir():
        # Check for web/ subdirectory (monorepo pattern)
        pages_dir = project_root / "web" / "src" / "pages"
        if not pages_dir.is_dir():
            return []

    routes = []
    extensions = (".astro", ".md", ".mdx", ".html")
    for ext in extensions:
        for f in pages_dir.rglob(f"*{ext}"):
            if f.is_file():
                route = _path_to_route(f, pages_dir, extensions)
                routes.append(route)
    return sorted(set(routes))


def detect_nextjs(project_root: Path) -> list[str]:
    """Detect routes from a Next.js project (app/ or pages/)."""
    routes = []

    # App Router: app/**/page.{tsx,jsx,ts,js}
    app_dir = project_root / "app"
    if app_dir.is_dir():
        for ext in (".tsx", ".jsx", ".ts", ".js"):
            for f in app_dir.rglob(f"page{ext}"):
                if f.is_file():
                    route = _path_to_route(f.parent / "index", app_dir, ("index",))
                    routes.append(route)

    # Pages Router: pages/**/*.{tsx,jsx,ts,js}
    pages_dir = project_root / "pages"
    if pages_dir.is_dir():
        extensions = (".tsx", ".jsx", ".ts", ".js")
        for ext in extensions:
            for f in pages_dir.rglob(f"*{ext}"):
                if f.is_file() and not f.name.startswith("_"):
                    route = _path_to_route(f, pages_dir, extensions)
                    routes.append(route)

    return sorted(set(routes))


def detect_sveltekit(project_root: Path) -> list[str]:
    """Detect routes from a SvelteKit project (src/routes/**/+page.svelte)."""
    routes_dir = project_root / "src" / "routes"
    if not routes_dir.is_dir():
        return []

    routes = []
    for f in routes_dir.rglob("+page.svelte"):
        if f.is_file():
            route = _path_to_route(f.parent / "index", routes_dir, ("index",))
            routes.append(route)
    return sorted(set(routes))


def detect_framework(project_root: Path) -> tuple[str | None, list[str]]:
    """Auto-detect framework and extract routes.

    Returns (framework_name, routes). framework_name is None if not detected.
    """
    root = Path(project_root)

    # Check for Astro
    astro_configs = list(root.glob("astro.config.*")) + list(root.glob("web/astro.config.*"))
    if astro_configs:
        return "astro", detect_astro(root)

    # Check for Next.js
    next_configs = list(root.glob("next.config.*"))
    if next_configs:
        return "nextjs", detect_nextjs(root)

    # Check for SvelteKit
    svelte_configs = list(root.glob("svelte.config.*"))
    if svelte_configs:
        return "sveltekit", detect_sveltekit(root)

    return None, []
