"""Orchestration module -- scan_capture and scan_graph entry points."""

from __future__ import annotations

import logging
from typing import Any

from webprobe.models import (
    AuthContext,
    NodeCapture,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
    SiteGraph,
)

from webprobe.security.headers import (
    check_cache_control,
    check_cross_origin_headers,
    check_csp_detailed,
    check_security_headers,
)
from webprobe.security.cookies import (
    check_cookie_prefixes,
    check_cookie_scope,
    check_cookies,
)
from webprobe.security.mixed_content import check_mixed_content
from webprobe.security.cors import check_cors
from webprobe.security.info_disclosure import (
    check_information_disclosure,
    check_injection_signals,
    check_secrets_in_content,
)
from webprobe.security.forms import check_forms
from webprobe.security.xss import check_xss_signals
from webprobe.security.auth_session import check_open_redirect, check_session_in_url
from webprobe.security.privacy import (
    check_cookie_consent,
    check_pii_in_forms,
    check_privacy_policy,
    check_sensitive_url_params,
    check_third_party_trackers,
)
from webprobe.security.supply_chain import (
    check_js_library_versions,
    check_sri,
    check_third_party_script_inventory,
)
from webprobe.security.tls import check_tls

logger = logging.getLogger(__name__)


def _safe_extend(findings: list[SecurityFinding], check_fn, *args) -> None:
    """Call a check function and extend findings, logging errors gracefully."""
    try:
        result = check_fn(*args)
        if isinstance(result, list):
            findings.extend(result)
        else:
            logger.warning("Check %s returned %s instead of list", check_fn.__name__, type(result).__name__)
    except Exception:
        logger.warning("Check %s failed for %s", check_fn.__name__, args[0] if args else "unknown", exc_info=True)


def scan_capture(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Run all passive security checks on a single capture."""
    findings: list[SecurityFinding] = []

    # --- Original checks ---
    _safe_extend(findings, check_security_headers, url, capture.response_headers, capture.auth_context)
    _safe_extend(findings, check_cookies, url, capture.cookies, capture.auth_context)
    _safe_extend(findings, check_mixed_content, url, capture)
    _safe_extend(findings, check_cors, url, capture.response_headers, capture.auth_context)
    _safe_extend(findings, check_information_disclosure, url, capture.response_headers, capture)
    _safe_extend(findings, check_forms, url, capture.forms, capture.auth_context)
    _safe_extend(findings, check_xss_signals, url, capture)

    # --- New header checks ---
    _safe_extend(findings, check_csp_detailed, url, capture.response_headers, capture.auth_context)
    _safe_extend(findings, check_cache_control, url, capture.response_headers, capture.auth_context, capture)
    _safe_extend(findings, check_cross_origin_headers, url, capture.response_headers, capture.auth_context)

    # --- New cookie checks ---
    _safe_extend(findings, check_cookie_prefixes, url, capture.cookies, capture.auth_context)
    _safe_extend(findings, check_cookie_scope, url, capture.cookies, capture.auth_context)

    # --- New info disclosure checks ---
    _safe_extend(findings, check_injection_signals, url, capture)
    _safe_extend(findings, check_secrets_in_content, url, capture)

    # --- Auth/session checks ---
    _safe_extend(findings, check_session_in_url, url, capture)
    _safe_extend(findings, check_open_redirect, url, capture)

    # --- Privacy checks ---
    _safe_extend(findings, check_privacy_policy, url, capture)
    _safe_extend(findings, check_cookie_consent, url, capture)
    _safe_extend(findings, check_third_party_trackers, url, capture)
    _safe_extend(findings, check_pii_in_forms, url, capture)
    _safe_extend(findings, check_sensitive_url_params, url, capture)

    # --- Supply chain checks ---
    _safe_extend(findings, check_js_library_versions, url, capture)
    _safe_extend(findings, check_sri, url, capture)
    _safe_extend(findings, check_third_party_script_inventory, url, capture)

    return findings


def scan_graph(graph: SiteGraph, config: Any = None) -> list[SecurityFinding]:
    """Run security scans across all captured nodes. Returns consolidated findings.

    Site-wide findings (headers, missing policies) are consolidated into a single
    finding with affected_urls listing all pages. Per-page findings (cookies, forms,
    reflected params) remain per-URL.

    Args:
        graph: The site graph with all captured nodes.
        config: Optional configuration (reserved for future use).

    Returns:
        Consolidated list of SecurityFinding.
    """
    # Categories where findings are typically identical across all pages
    SITE_WIDE_CATEGORIES = {SecurityCategory.headers, SecurityCategory.xss}
    SITE_WIDE_TITLES = {
        "Missing Strict-Transport-Security header",
        "Missing Content-Security-Policy header",
        "Missing clickjacking protection",
        "Missing X-Content-Type-Options header",
        "Missing Referrer-Policy header",
        "Missing Permissions-Policy header",
        "HSTS max-age too short",
        "CSP allows unsafe-inline",
        "CSP allows unsafe-eval",
        "Weak X-Frame-Options value",
        # New site-wide titles from header checks
        "CSP missing reporting directive",
        "CSP missing frame-ancestors directive",
        "CSP missing base-uri restriction",
        "CSP missing form-action restriction",
        "CSP missing upgrade-insecure-requests",
        "CSP default-src includes wildcard",
        "Missing Cross-Origin-Opener-Policy header",
        "Missing Cross-Origin-Resource-Policy header",
        "Missing Cross-Origin-Embedder-Policy header",
    }

    consolidated: dict[tuple[str, str], SecurityFinding] = {}  # (category, title) -> finding
    per_url: list[SecurityFinding] = []
    per_url_seen: set[tuple[str, str, str]] = set()  # (url, category, title)

    for node in graph.nodes.values():
        for capture in node.captures:
            findings = scan_capture(node.id, capture)
            for f in findings:
                # Attach to capture for per-node reporting
                capture.security_findings.append(f)

                if f.category in SITE_WIDE_CATEGORIES and f.title in SITE_WIDE_TITLES:
                    key = (f.category.value, f.title)
                    if key in consolidated:
                        existing = consolidated[key]
                        if f.url not in existing.affected_urls:
                            existing.affected_urls.append(f.url)
                            existing.affected_count = len(existing.affected_urls)
                    else:
                        f.affected_urls = [f.url]
                        f.affected_count = 1
                        consolidated[key] = f
                else:
                    url_key = (f.url, f.category.value, f.title)
                    if url_key not in per_url_seen:
                        per_url_seen.add(url_key)
                        per_url.append(f)

    # --- TLS checks ---
    if graph.tls_info is not None:
        root_url = graph.root_url or (graph.seed_urls[0] if graph.seed_urls else "")
        tls_findings = check_tls(root_url, graph.tls_info)
        per_url.extend(tls_findings)

    # --- Site-wide auth checks ---
    # Check if ANY page has a logout link across all captures
    has_logout = False
    for node in graph.nodes.values():
        for capture in node.captures:
            for link in capture.outgoing_links:
                link_lower = link.lower()
                if any(kw in link_lower for kw in ("logout", "sign-out", "signout", "log-out")):
                    has_logout = True
                    break
            if has_logout:
                break
        if has_logout:
            break

    if has_logout:
        # Check if there's any session cookie across the site
        has_session_cookie = False
        for node in graph.nodes.values():
            for capture in node.captures:
                for cookie in capture.cookies:
                    if any(kw in cookie.name.lower() for kw in ("session", "token", "auth", "sid", "jwt")):
                        has_session_cookie = True
                        break
                if has_session_cookie:
                    break
            if has_session_cookie:
                break

        if not has_session_cookie:
            root_url = graph.root_url or (graph.seed_urls[0] if graph.seed_urls else "")
            per_url.append(SecurityFinding(
                category=SecurityCategory.auth_session,
                severity=SecuritySeverity.info,
                title="Logout link found but no session cookie detected",
                detail="Site appears to have authentication (logout link found) but no session cookie was observed. Session may use a non-cookie mechanism.",
                url=root_url,
                auth_context=AuthContext.anonymous,
            ))

    return list(consolidated.values()) + per_url
