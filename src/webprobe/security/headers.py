"""Security header checks -- missing, misconfigured, and advanced analysis."""

from __future__ import annotations

import logging
import re

from webprobe.models import (
    AuthContext,
    NodeCapture,
    ResponseHeaders,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
)

logger = logging.getLogger(__name__)


def check_security_headers(url: str, headers: ResponseHeaders, auth_ctx: AuthContext) -> list[SecurityFinding]:
    """Check for missing or misconfigured security headers."""
    findings: list[SecurityFinding] = []
    h = {k.lower(): v for k, v in headers.raw.items()}

    # Strict-Transport-Security
    if "strict-transport-security" not in h:
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.high,
            title="Missing Strict-Transport-Security header",
            detail="HSTS header not set. Browsers may allow HTTP downgrade attacks.",
            url=url,
            auth_context=auth_ctx,
        ))
    elif "max-age" in h.get("strict-transport-security", ""):
        val = h["strict-transport-security"]
        match = re.search(r"max-age=(\d+)", val)
        if match and int(match.group(1)) < 31536000:
            findings.append(SecurityFinding(
                category=SecurityCategory.headers,
                severity=SecuritySeverity.low,
                title="HSTS max-age too short",
                detail=f"HSTS max-age is {match.group(1)}s, recommended >= 31536000 (1 year).",
                evidence=val,
                url=url,
                auth_context=auth_ctx,
            ))

    # Content-Security-Policy
    if "content-security-policy" not in h:
        findings.append(SecurityFinding(
            category=SecurityCategory.xss,
            severity=SecuritySeverity.medium,
            title="Missing Content-Security-Policy header",
            detail="No CSP set. Site is more vulnerable to XSS and data injection attacks.",
            url=url,
            auth_context=auth_ctx,
        ))
    else:
        csp = h["content-security-policy"]
        if "'unsafe-inline'" in csp:
            findings.append(SecurityFinding(
                category=SecurityCategory.xss,
                severity=SecuritySeverity.medium,
                title="CSP allows unsafe-inline",
                detail="'unsafe-inline' in CSP weakens XSS protection significantly.",
                evidence=csp[:200],
                url=url,
                auth_context=auth_ctx,
            ))
        if "'unsafe-eval'" in csp:
            findings.append(SecurityFinding(
                category=SecurityCategory.xss,
                severity=SecuritySeverity.medium,
                title="CSP allows unsafe-eval",
                detail="'unsafe-eval' in CSP allows eval(), reducing XSS protection.",
                evidence=csp[:200],
                url=url,
                auth_context=auth_ctx,
            ))

    # X-Frame-Options
    if "x-frame-options" not in h and "content-security-policy" not in h:
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.medium,
            title="Missing clickjacking protection",
            detail="Neither X-Frame-Options nor CSP frame-ancestors is set. Site may be frameable.",
            url=url,
            auth_context=auth_ctx,
        ))
    elif "x-frame-options" in h:
        val = h["x-frame-options"].upper()
        if val not in ("DENY", "SAMEORIGIN"):
            findings.append(SecurityFinding(
                category=SecurityCategory.headers,
                severity=SecuritySeverity.medium,
                title="Weak X-Frame-Options value",
                detail=f"X-Frame-Options is '{val}', should be DENY or SAMEORIGIN.",
                evidence=val,
                url=url,
                auth_context=auth_ctx,
            ))

    # X-Content-Type-Options
    if "x-content-type-options" not in h:
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.low,
            title="Missing X-Content-Type-Options header",
            detail="Without nosniff, browsers may MIME-sniff responses into executable types.",
            url=url,
            auth_context=auth_ctx,
        ))

    # Referrer-Policy
    if "referrer-policy" not in h:
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.low,
            title="Missing Referrer-Policy header",
            detail="No Referrer-Policy set. Full URLs (including query params) may leak to third parties.",
            url=url,
            auth_context=auth_ctx,
        ))

    # Permissions-Policy
    if "permissions-policy" not in h:
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.info,
            title="Missing Permissions-Policy header",
            detail="No Permissions-Policy set. Browser features (camera, mic, geolocation) not explicitly restricted.",
            url=url,
            auth_context=auth_ctx,
        ))

    return findings


def check_csp_detailed(url: str, headers: ResponseHeaders, auth_ctx: AuthContext) -> list[SecurityFinding]:
    """Deep CSP analysis beyond basic missing/unsafe-inline/unsafe-eval checks."""
    findings: list[SecurityFinding] = []
    h = {k.lower(): v for k, v in headers.raw.items()}

    csp = h.get("content-security-policy", "")
    if not csp:
        return findings

    csp_lower = csp.lower()

    # Parse directives into a dict
    directives: dict[str, str] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split(None, 1)
        directive_name = tokens[0].lower()
        directive_value = tokens[1] if len(tokens) > 1 else ""
        directives[directive_name] = directive_value

    # Missing report-uri or report-to
    if "report-uri" not in directives and "report-to" not in directives:
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.info,
            title="CSP missing reporting directive",
            detail="No report-uri or report-to directive. CSP violations will not be reported.",
            evidence=csp[:200],
            url=url,
            auth_context=auth_ctx,
        ))

    # Missing frame-ancestors when X-Frame-Options also missing
    xfo = h.get("x-frame-options", "")
    if "frame-ancestors" not in directives and not xfo:
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.medium,
            title="CSP missing frame-ancestors directive",
            detail="No frame-ancestors in CSP and no X-Frame-Options header. Site may be frameable.",
            evidence=csp[:200],
            url=url,
            auth_context=auth_ctx,
        ))

    # Missing base-uri restriction
    if "base-uri" not in directives:
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.low,
            title="CSP missing base-uri restriction",
            detail="No base-uri directive. Attackers may inject <base> tags to hijack relative URLs.",
            evidence=csp[:200],
            url=url,
            auth_context=auth_ctx,
        ))

    # Missing form-action restriction
    if "form-action" not in directives:
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.low,
            title="CSP missing form-action restriction",
            detail="No form-action directive. Forms may submit to any origin.",
            evidence=csp[:200],
            url=url,
            auth_context=auth_ctx,
        ))

    # Missing upgrade-insecure-requests on HTTPS
    if url.startswith("https://") and "upgrade-insecure-requests" not in directives:
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.info,
            title="CSP missing upgrade-insecure-requests",
            detail="HTTPS page without upgrade-insecure-requests. Mixed content may not be auto-upgraded.",
            evidence=csp[:200],
            url=url,
            auth_context=auth_ctx,
        ))

    # default-src includes '*'
    default_src = directives.get("default-src", "")
    if "*" in default_src.split():
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.medium,
            title="CSP default-src includes wildcard",
            detail="default-src allows '*', effectively disabling CSP protection for unlisted directives.",
            evidence=f"default-src {default_src}",
            url=url,
            auth_context=auth_ctx,
        ))

    # script-src includes 'data:' or 'blob:'
    script_src = directives.get("script-src", "")
    for dangerous in ("data:", "blob:"):
        if dangerous in script_src.lower():
            findings.append(SecurityFinding(
                category=SecurityCategory.headers,
                severity=SecuritySeverity.medium,
                title=f"CSP script-src allows {dangerous} URIs",
                detail=f"script-src includes '{dangerous}', allowing scripts from {dangerous} URIs which can bypass CSP.",
                evidence=f"script-src {script_src[:200]}",
                url=url,
                auth_context=auth_ctx,
            ))

    return findings


def check_cache_control(
    url: str,
    headers: ResponseHeaders,
    auth_ctx: AuthContext,
    capture: NodeCapture,
) -> list[SecurityFinding]:
    """Check Cache-Control for sensitive pages (auth pages, pages with password forms)."""
    findings: list[SecurityFinding] = []
    h = {k.lower(): v for k, v in headers.raw.items()}

    # Determine if this is a sensitive page
    is_auth_page = any(
        kw in url.lower()
        for kw in ("login", "signin", "sign-in", "auth", "account", "password", "reset")
    )
    has_password_form = any(form.has_password_field for form in capture.forms)

    if not is_auth_page and not has_password_form:
        return findings

    cache_control = h.get("cache-control", "")
    if "no-store" not in cache_control.lower():
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.medium,
            title="Sensitive page missing Cache-Control: no-store",
            detail="Auth or password page does not set Cache-Control: no-store. Sensitive data may be cached by browsers or proxies.",
            evidence=f"Cache-Control: {cache_control}" if cache_control else "Cache-Control header not set",
            url=url,
            auth_context=auth_ctx,
        ))

    return findings


def check_cross_origin_headers(url: str, headers: ResponseHeaders, auth_ctx: AuthContext) -> list[SecurityFinding]:
    """Check for Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, and Cross-Origin-Embedder-Policy."""
    findings: list[SecurityFinding] = []
    h = {k.lower(): v for k, v in headers.raw.items()}

    if "cross-origin-opener-policy" not in h:
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.info,
            title="Missing Cross-Origin-Opener-Policy header",
            detail="No COOP header. Page may be subject to cross-origin window attacks.",
            url=url,
            auth_context=auth_ctx,
        ))

    if "cross-origin-resource-policy" not in h:
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.info,
            title="Missing Cross-Origin-Resource-Policy header",
            detail="No CORP header. Resources may be loaded by cross-origin pages.",
            url=url,
            auth_context=auth_ctx,
        ))

    if "cross-origin-embedder-policy" not in h:
        findings.append(SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.info,
            title="Missing Cross-Origin-Embedder-Policy header",
            detail="No COEP header. Page cannot enable cross-origin isolation.",
            url=url,
            auth_context=auth_ctx,
        ))

    return findings
