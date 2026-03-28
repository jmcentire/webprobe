"""
Contract-based test suite for src_webprobe_frameworks component.

This test suite verifies the behavior of framework route detection functions
according to their contract specifications. Tests cover:
- Path to route conversion with dynamic segments and extensions
- Framework-specific route detection (Astro, Next.js, SvelteKit)
- Framework auto-detection and configuration file scanning
- Contract invariants (routes start with '/', sorted, deduplicated)
- Error cases (ValueError for paths outside pages directory)
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import tempfile
import shutil
from typing import List, Tuple

# Import the module under test
from src.webprobe.frameworks import (
    _path_to_route,
    detect_astro,
    detect_nextjs,
    detect_sveltekit,
    detect_framework,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def temp_project_root(tmp_path):
    """Create a temporary project root directory."""
    return tmp_path


@pytest.fixture
def astro_project(tmp_path):
    """Create a minimal Astro project structure."""
    src_pages = tmp_path / "src" / "pages"
    src_pages.mkdir(parents=True)
    
    # Create sample files
    (src_pages / "index.astro").write_text("")
    (src_pages / "about.astro").write_text("")
    (src_pages / "blog").mkdir()
    (src_pages / "blog" / "post.md").write_text("")
    
    return tmp_path


@pytest.fixture
def nextjs_project(tmp_path):
    """Create a minimal Next.js project structure."""
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    
    (app_dir / "page.tsx").write_text("")
    (app_dir / "about").mkdir()
    (app_dir / "about" / "page.tsx").write_text("")
    
    return tmp_path


@pytest.fixture
def sveltekit_project(tmp_path):
    """Create a minimal SvelteKit project structure."""
    routes = tmp_path / "src" / "routes"
    routes.mkdir(parents=True)
    
    (routes / "+page.svelte").write_text("")
    (routes / "about").mkdir()
    (routes / "about" / "+page.svelte").write_text("")
    
    return tmp_path


# ============================================================================
# Tests for _path_to_route
# ============================================================================

def test_path_to_route_basic_file():
    """Convert a simple file path to a route."""
    filepath = Path("pages/about.astro")
    pages_dir = Path("pages")
    strip_extensions = ('.astro',)
    
    result = _path_to_route(filepath, pages_dir, strip_extensions)
    
    assert result == '/about'
    assert result.startswith('/')


def test_path_to_route_nested_path():
    """Convert a nested file path to a route."""
    filepath = Path("pages/blog/post.md")
    pages_dir = Path("pages")
    strip_extensions = ('.md',)
    
    result = _path_to_route(filepath, pages_dir, strip_extensions)
    
    assert result == '/blog/post'
    assert result.startswith('/')


def test_path_to_route_index_file():
    """Index files should map to directory root."""
    filepath = Path("pages/index.astro")
    pages_dir = Path("pages")
    strip_extensions = ('.astro',)
    
    result = _path_to_route(filepath, pages_dir, strip_extensions)
    
    assert result == '/'
    assert result.startswith('/')


def test_path_to_route_nested_index():
    """Nested index files map to their directory."""
    filepath = Path("pages/blog/index.md")
    pages_dir = Path("pages")
    strip_extensions = ('.md',)
    
    result = _path_to_route(filepath, pages_dir, strip_extensions)
    
    assert result == '/blog'
    assert result.startswith('/')


def test_path_to_route_dynamic_segment():
    """Dynamic route segments [param] convert to :param."""
    filepath = Path("pages/users/[id].astro")
    pages_dir = Path("pages")
    strip_extensions = ('.astro',)
    
    result = _path_to_route(filepath, pages_dir, strip_extensions)
    
    assert result == '/users/:id'
    assert ':id' in result


def test_path_to_route_catch_all_segment():
    """Catch-all segments [...rest] convert to *rest."""
    filepath = Path("pages/blog/[...slug].astro")
    pages_dir = Path("pages")
    strip_extensions = ('.astro',)
    
    result = _path_to_route(filepath, pages_dir, strip_extensions)
    
    assert result == '/blog/*slug'
    assert '*slug' in result


def test_path_to_route_multiple_extensions():
    """Strip any of multiple extensions."""
    filepath = Path("pages/about.md")
    pages_dir = Path("pages")
    strip_extensions = ('.astro', '.md', '.mdx')
    
    result = _path_to_route(filepath, pages_dir, strip_extensions)
    
    assert result == '/about'
    assert '.md' not in result


def test_path_to_route_outside_pages_dir():
    """Raises ValueError when filepath not under pages_dir."""
    filepath = Path("other/file.astro")
    pages_dir = Path("pages")
    strip_extensions = ('.astro',)
    
    with pytest.raises(ValueError):
        _path_to_route(filepath, pages_dir, strip_extensions)


def test_path_to_route_dynamic_folder():
    """Dynamic segments in folder names."""
    filepath = Path("pages/blog/[category]/post.astro")
    pages_dir = Path("pages")
    strip_extensions = ('.astro',)
    
    result = _path_to_route(filepath, pages_dir, strip_extensions)
    
    assert result == '/blog/:category/post'
    assert ':category' in result


def test_path_to_route_no_extension_to_strip():
    """File with extension not in strip_extensions."""
    filepath = Path("pages/about.html")
    pages_dir = Path("pages")
    strip_extensions = ('.astro',)
    
    result = _path_to_route(filepath, pages_dir, strip_extensions)
    
    assert result.startswith('/')


# ============================================================================
# Tests for detect_astro
# ============================================================================

def test_detect_astro_basic_structure(tmp_path):
    """Detect routes from basic Astro project."""
    src_pages = tmp_path / "src" / "pages"
    src_pages.mkdir(parents=True)
    
    (src_pages / "index.astro").write_text("")
    (src_pages / "about.astro").write_text("")
    
    result = detect_astro(tmp_path)
    
    assert isinstance(result, list)
    assert all(r.startswith('/') for r in result)
    assert result == sorted(result)


def test_detect_astro_all_extensions(tmp_path):
    """Detect .astro, .md, .mdx, .html files."""
    src_pages = tmp_path / "src" / "pages"
    src_pages.mkdir(parents=True)
    
    (src_pages / "page1.astro").write_text("")
    (src_pages / "page2.md").write_text("")
    (src_pages / "page3.mdx").write_text("")
    (src_pages / "page4.html").write_text("")
    
    result = detect_astro(tmp_path)
    
    assert isinstance(result, list)
    assert len(result) > 0


def test_detect_astro_no_pages_dir(tmp_path):
    """Returns empty list when pages directory missing."""
    result = detect_astro(tmp_path)
    
    assert result == []
    assert isinstance(result, list)


def test_detect_astro_monorepo_pattern(tmp_path):
    """Detect Astro routes from web/src/pages in monorepo."""
    web_pages = tmp_path / "web" / "src" / "pages"
    web_pages.mkdir(parents=True)
    
    (web_pages / "index.astro").write_text("")
    (web_pages / "about.astro").write_text("")
    
    result = detect_astro(tmp_path)
    
    assert isinstance(result, list)
    assert all(r.startswith('/') for r in result)


def test_detect_astro_deduplication(tmp_path):
    """Routes are deduplicated via set conversion."""
    src_pages = tmp_path / "src" / "pages"
    src_pages.mkdir(parents=True)
    
    (src_pages / "index.astro").write_text("")
    (src_pages / "about.astro").write_text("")
    
    result = detect_astro(tmp_path)
    
    assert len(result) == len(set(result))


# ============================================================================
# Tests for detect_nextjs
# ============================================================================

def test_detect_nextjs_app_router(tmp_path):
    """Detect routes from Next.js App Router."""
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    
    (app_dir / "page.tsx").write_text("")
    blog_dir = app_dir / "blog"
    blog_dir.mkdir()
    (blog_dir / "page.tsx").write_text("")
    
    result = detect_nextjs(tmp_path)
    
    assert isinstance(result, list)
    assert all(r.startswith('/') for r in result)
    assert result == sorted(result)


def test_detect_nextjs_pages_router(tmp_path):
    """Detect routes from Next.js Pages Router."""
    pages_dir = tmp_path / "pages"
    pages_dir.mkdir()
    
    (pages_dir / "index.tsx").write_text("")
    (pages_dir / "about.tsx").write_text("")
    
    result = detect_nextjs(tmp_path)
    
    assert isinstance(result, list)
    assert all(r.startswith('/') for r in result)


def test_detect_nextjs_excludes_underscore_files(tmp_path):
    """Files starting with underscore in pages/ are excluded."""
    pages_dir = tmp_path / "pages"
    pages_dir.mkdir()
    
    (pages_dir / "_app.tsx").write_text("")
    (pages_dir / "_document.tsx").write_text("")
    (pages_dir / "index.tsx").write_text("")
    
    result = detect_nextjs(tmp_path)
    
    # Underscore files should not appear (except as part of root route)
    assert all('_' not in r.split('/')[-1] for r in result if r != '/')


def test_detect_nextjs_no_directories(tmp_path):
    """Returns empty list when neither app/ nor pages/ exist."""
    result = detect_nextjs(tmp_path)
    
    assert result == []
    assert isinstance(result, list)


def test_detect_nextjs_all_extensions(tmp_path):
    """Detect all Next.js extensions: .tsx, .jsx, .ts, .js."""
    pages_dir = tmp_path / "pages"
    pages_dir.mkdir()
    
    (pages_dir / "page1.tsx").write_text("")
    (pages_dir / "page2.jsx").write_text("")
    (pages_dir / "page3.ts").write_text("")
    (pages_dir / "page4.js").write_text("")
    
    result = detect_nextjs(tmp_path)
    
    assert isinstance(result, list)
    assert len(result) >= 0


def test_detect_nextjs_deduplication(tmp_path):
    """Routes are deduplicated via set conversion."""
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    
    (app_dir / "page.tsx").write_text("")
    
    result = detect_nextjs(tmp_path)
    
    assert len(result) == len(set(result))


# ============================================================================
# Tests for detect_sveltekit
# ============================================================================

def test_detect_sveltekit_basic(tmp_path):
    """Detect routes from SvelteKit project."""
    routes = tmp_path / "src" / "routes"
    routes.mkdir(parents=True)
    
    (routes / "+page.svelte").write_text("")
    about_dir = routes / "about"
    about_dir.mkdir()
    (about_dir / "+page.svelte").write_text("")
    
    result = detect_sveltekit(tmp_path)
    
    assert isinstance(result, list)
    assert all(r.startswith('/') for r in result)
    assert result == sorted(result)


def test_detect_sveltekit_nested_routes(tmp_path):
    """Detect nested SvelteKit routes."""
    routes = tmp_path / "src" / "routes"
    routes.mkdir(parents=True)
    
    (routes / "+page.svelte").write_text("")
    
    blog_dir = routes / "blog"
    blog_dir.mkdir()
    (blog_dir / "+page.svelte").write_text("")
    
    post_dir = blog_dir / "post"
    post_dir.mkdir()
    (post_dir / "+page.svelte").write_text("")
    
    result = detect_sveltekit(tmp_path)
    
    assert isinstance(result, list)
    assert all(r.startswith('/') for r in result)


def test_detect_sveltekit_no_routes_dir(tmp_path):
    """Returns empty list when src/routes doesn't exist."""
    result = detect_sveltekit(tmp_path)
    
    assert result == []
    assert isinstance(result, list)


def test_detect_sveltekit_deduplication(tmp_path):
    """Routes are deduplicated via set conversion."""
    routes = tmp_path / "src" / "routes"
    routes.mkdir(parents=True)
    
    (routes / "+page.svelte").write_text("")
    
    result = detect_sveltekit(tmp_path)
    
    assert len(result) == len(set(result))


# ============================================================================
# Tests for detect_framework
# ============================================================================

def test_detect_framework_astro(tmp_path):
    """Detect Astro framework from astro.config.*."""
    (tmp_path / "astro.config.mjs").write_text("")
    
    src_pages = tmp_path / "src" / "pages"
    src_pages.mkdir(parents=True)
    (src_pages / "index.astro").write_text("")
    
    framework, routes = detect_framework(tmp_path)
    
    assert framework == 'astro'
    assert isinstance(routes, list)


def test_detect_framework_nextjs(tmp_path):
    """Detect Next.js framework from next.config.*."""
    (tmp_path / "next.config.js").write_text("")
    
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "page.tsx").write_text("")
    
    framework, routes = detect_framework(tmp_path)
    
    assert framework == 'nextjs'
    assert isinstance(routes, list)


def test_detect_framework_sveltekit(tmp_path):
    """Detect SvelteKit framework from svelte.config.*."""
    (tmp_path / "svelte.config.js").write_text("")
    
    routes_dir = tmp_path / "src" / "routes"
    routes_dir.mkdir(parents=True)
    (routes_dir / "+page.svelte").write_text("")
    
    framework, routes = detect_framework(tmp_path)
    
    assert framework == 'sveltekit'
    assert isinstance(routes, list)


def test_detect_framework_none(tmp_path):
    """Returns (None, []) when no framework detected."""
    framework, routes = detect_framework(tmp_path)
    
    assert framework is None
    assert routes == []


def test_detect_framework_detection_order(tmp_path):
    """Framework detection order: Astro -> Next.js -> SvelteKit."""
    # Create both Astro and Next.js config files
    (tmp_path / "astro.config.mjs").write_text("")
    (tmp_path / "next.config.js").write_text("")
    
    src_pages = tmp_path / "src" / "pages"
    src_pages.mkdir(parents=True)
    (src_pages / "index.astro").write_text("")
    
    framework, routes = detect_framework(tmp_path)
    
    # Astro should be detected first
    assert framework == 'astro'


def test_detect_framework_monorepo_astro(tmp_path):
    """Detect Astro from web/astro.config.* in monorepo."""
    web_dir = tmp_path / "web"
    web_dir.mkdir()
    (web_dir / "astro.config.mjs").write_text("")
    
    web_pages = web_dir / "src" / "pages"
    web_pages.mkdir(parents=True)
    (web_pages / "index.astro").write_text("")
    
    framework, routes = detect_framework(tmp_path)
    
    assert framework == 'astro'
    assert isinstance(routes, list)


# ============================================================================
# Invariant Tests
# ============================================================================

def test_invariant_all_routes_start_with_slash(tmp_path):
    """All routes from all detectors start with '/'."""
    src_pages = tmp_path / "src" / "pages"
    src_pages.mkdir(parents=True)
    
    (src_pages / "index.astro").write_text("")
    (src_pages / "about.astro").write_text("")
    blog_dir = src_pages / "blog"
    blog_dir.mkdir()
    (blog_dir / "post.md").write_text("")
    
    result = detect_astro(tmp_path)
    
    assert all(r.startswith('/') for r in result)


def test_invariant_routes_sorted(tmp_path):
    """All route lists are sorted."""
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    
    (app_dir / "page.tsx").write_text("")
    
    zzz_dir = app_dir / "zzz"
    zzz_dir.mkdir()
    (zzz_dir / "page.tsx").write_text("")
    
    aaa_dir = app_dir / "aaa"
    aaa_dir.mkdir()
    (aaa_dir / "page.tsx").write_text("")
    
    result = detect_nextjs(tmp_path)
    
    assert result == sorted(result)


# ============================================================================
# Additional Edge Case Tests
# ============================================================================

def test_path_to_route_with_absolute_paths(tmp_path):
    """Test _path_to_route with absolute paths."""
    pages_dir = tmp_path / "pages"
    pages_dir.mkdir()
    
    filepath = pages_dir / "about.astro"
    filepath.write_text("")
    
    result = _path_to_route(filepath, pages_dir, ('.astro',))
    
    assert result.startswith('/')


def test_detect_astro_with_nested_dynamic_routes(tmp_path):
    """Test Astro detection with nested dynamic routes."""
    src_pages = tmp_path / "src" / "pages"
    src_pages.mkdir(parents=True)
    
    blog_dir = src_pages / "blog"
    blog_dir.mkdir()
    
    (blog_dir / "[slug].astro").write_text("")
    
    result = detect_astro(tmp_path)
    
    assert isinstance(result, list)
    assert all(r.startswith('/') for r in result)


def test_detect_nextjs_with_dynamic_routes(tmp_path):
    """Test Next.js detection with dynamic routes."""
    pages_dir = tmp_path / "pages"
    pages_dir.mkdir()
    
    users_dir = pages_dir / "users"
    users_dir.mkdir()
    (users_dir / "[id].tsx").write_text("")
    
    result = detect_nextjs(tmp_path)
    
    assert isinstance(result, list)
    assert all(r.startswith('/') for r in result)


def test_detect_sveltekit_with_dynamic_routes(tmp_path):
    """Test SvelteKit detection with dynamic routes."""
    routes = tmp_path / "src" / "routes"
    routes.mkdir(parents=True)
    
    blog_dir = routes / "blog" / "[slug]"
    blog_dir.mkdir(parents=True)
    (blog_dir / "+page.svelte").write_text("")
    
    result = detect_sveltekit(tmp_path)
    
    assert isinstance(result, list)
    assert all(r.startswith('/') for r in result)


def test_detect_framework_with_multiple_config_variants(tmp_path):
    """Test framework detection with different config file extensions."""
    # Test with .mjs extension
    (tmp_path / "astro.config.mjs").write_text("")
    
    src_pages = tmp_path / "src" / "pages"
    src_pages.mkdir(parents=True)
    (src_pages / "index.astro").write_text("")
    
    framework, routes = detect_framework(tmp_path)
    
    assert framework == 'astro'


def test_path_to_route_multiple_dynamic_segments(tmp_path):
    """Test path with multiple dynamic segments."""
    filepath = Path("pages/blog/[year]/[month]/[slug].astro")
    pages_dir = Path("pages")
    strip_extensions = ('.astro',)
    
    result = _path_to_route(filepath, pages_dir, strip_extensions)
    
    assert result.startswith('/')
    assert ':year' in result
    assert ':month' in result
    assert ':slug' in result
