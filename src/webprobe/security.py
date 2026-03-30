"""Passive security scanning -- analyzes captured data for common web vulnerabilities."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from webprobe.models import (
    AuthContext,
    CookieInfo,
    FormInfo,
    NodeCapture,
    ResponseHeaders,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
    SiteGraph,
)


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


def check_cookies(url: str, cookies: list[CookieInfo], auth_ctx: AuthContext) -> list[SecurityFinding]:
    """Check cookie security attributes."""
    findings: list[SecurityFinding] = []
    is_https = urlparse(url).scheme == "https"

    for cookie in cookies:
        # Session-like cookies (heuristic: name contains session, token, auth, sid)
        is_session_like = any(
            kw in cookie.name.lower()
            for kw in ("session", "token", "auth", "sid", "jwt", "access")
        )

        if is_https and not cookie.secure:
            sev = SecuritySeverity.high if is_session_like else SecuritySeverity.medium
            findings.append(SecurityFinding(
                category=SecurityCategory.cookies,
                severity=sev,
                title=f"Cookie '{cookie.name}' missing Secure flag",
                detail="Cookie can be sent over unencrypted HTTP, exposing it to interception.",
                evidence=f"name={cookie.name}, domain={cookie.domain}",
                url=url,
                auth_context=auth_ctx,
            ))

        if not cookie.http_only and is_session_like:
            findings.append(SecurityFinding(
                category=SecurityCategory.cookies,
                severity=SecuritySeverity.high,
                title=f"Session cookie '{cookie.name}' missing HttpOnly flag",
                detail="Cookie accessible to JavaScript. XSS could steal this session cookie.",
                evidence=f"name={cookie.name}",
                url=url,
                auth_context=auth_ctx,
            ))

        if not cookie.same_site or cookie.same_site.lower() == "none":
            sev = SecuritySeverity.medium if is_session_like else SecuritySeverity.low
            findings.append(SecurityFinding(
                category=SecurityCategory.cookies,
                severity=sev,
                title=f"Cookie '{cookie.name}' has weak SameSite policy",
                detail=f"SameSite={cookie.same_site or 'not set'}. Cross-site requests will include this cookie.",
                evidence=f"name={cookie.name}, SameSite={cookie.same_site}",
                url=url,
                auth_context=auth_ctx,
            ))

    return findings


def check_mixed_content(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Check for HTTP resources loaded on an HTTPS page."""
    findings: list[SecurityFinding] = []
    if not url.startswith("https://"):
        return findings

    for resource in capture.resources:
        if resource.url.startswith("http://"):
            sev = SecuritySeverity.high if resource.resource_type.value in ("script", "stylesheet") else SecuritySeverity.medium
            findings.append(SecurityFinding(
                category=SecurityCategory.mixed_content,
                severity=sev,
                title=f"Mixed content: {resource.resource_type.value} loaded over HTTP",
                detail=f"HTTPS page loads {resource.resource_type.value} over insecure HTTP.",
                evidence=resource.url[:200],
                url=url,
                auth_context=capture.auth_context,
            ))

    return findings


def check_cors(url: str, headers: ResponseHeaders, auth_ctx: AuthContext) -> list[SecurityFinding]:
    """Check for CORS misconfigurations."""
    findings: list[SecurityFinding] = []
    h = {k.lower(): v for k, v in headers.raw.items()}

    acao = h.get("access-control-allow-origin", "")
    if acao == "*":
        acac = h.get("access-control-allow-credentials", "")
        if acac.lower() == "true":
            findings.append(SecurityFinding(
                category=SecurityCategory.cors,
                severity=SecuritySeverity.critical,
                title="CORS allows any origin with credentials",
                detail="Access-Control-Allow-Origin: * with Allow-Credentials: true. Any site can make authenticated requests.",
                evidence=f"ACAO={acao}, ACAC={acac}",
                url=url,
                auth_context=auth_ctx,
            ))
        else:
            findings.append(SecurityFinding(
                category=SecurityCategory.cors,
                severity=SecuritySeverity.low,
                title="CORS allows any origin",
                detail="Access-Control-Allow-Origin: * -- any site can read responses (without credentials).",
                evidence=f"ACAO={acao}",
                url=url,
                auth_context=auth_ctx,
            ))

    return findings


def check_information_disclosure(url: str, headers: ResponseHeaders, capture: NodeCapture) -> list[SecurityFinding]:
    """Check for information leakage in headers and page content."""
    findings: list[SecurityFinding] = []
    h = {k.lower(): v for k, v in headers.raw.items()}

    # Server version disclosure
    server = h.get("server", "")
    if server and re.search(r"\d+\.\d+", server):
        findings.append(SecurityFinding(
            category=SecurityCategory.information_disclosure,
            severity=SecuritySeverity.low,
            title="Server version disclosed in headers",
            detail="Server header reveals version info, aiding targeted attacks.",
            evidence=f"Server: {server}",
            url=url,
            auth_context=capture.auth_context,
        ))

    # X-Powered-By
    powered_by = h.get("x-powered-by", "")
    if powered_by:
        findings.append(SecurityFinding(
            category=SecurityCategory.information_disclosure,
            severity=SecuritySeverity.low,
            title="X-Powered-By header reveals technology stack",
            detail="Technology stack disclosed via X-Powered-By header.",
            evidence=f"X-Powered-By: {powered_by}",
            url=url,
            auth_context=capture.auth_context,
        ))

    # Source maps exposed
    for resource in capture.resources:
        if resource.url.endswith(".map") and resource.status_code == 200:
            findings.append(SecurityFinding(
                category=SecurityCategory.information_disclosure,
                severity=SecuritySeverity.medium,
                title="JavaScript source map exposed",
                detail="Source maps reveal original source code, aiding reverse engineering.",
                evidence=resource.url[:200],
                url=url,
                auth_context=capture.auth_context,
            ))

    # Stack traces in page content
    text = capture.page_text.lower()
    stack_patterns = [
        r"traceback \(most recent call last\)",
        r"at .+\(.+:\d+:\d+\)",
        r"exception in thread",
        r"fatal error:.*on line \d+",
        r"stack trace:",
        r"unhandled exception",
    ]
    for pattern in stack_patterns:
        if re.search(pattern, text):
            findings.append(SecurityFinding(
                category=SecurityCategory.information_disclosure,
                severity=SecuritySeverity.high,
                title="Stack trace or error details exposed",
                detail="Page content contains what appears to be a stack trace or detailed error message.",
                evidence=f"Pattern matched: {pattern}",
                url=url,
                auth_context=capture.auth_context,
            ))
            break  # One finding per page is enough

    return findings


def check_forms(url: str, forms: list[FormInfo], auth_ctx: AuthContext) -> list[SecurityFinding]:
    """Check form security: CSRF tokens, password fields, autocomplete."""
    findings: list[SecurityFinding] = []

    for form in forms:
        # POST forms without CSRF token
        if form.method.upper() == "POST" and not form.has_csrf_token:
            findings.append(SecurityFinding(
                category=SecurityCategory.forms,
                severity=SecuritySeverity.medium,
                title="POST form without CSRF token",
                detail="Form submits via POST without an apparent CSRF token. May be vulnerable to CSRF.",
                evidence=f"action={form.action}, method={form.method}",
                url=url,
                auth_context=auth_ctx,
            ))

        # Password fields with autocomplete enabled
        if form.has_password_field and not form.autocomplete_off:
            findings.append(SecurityFinding(
                category=SecurityCategory.forms,
                severity=SecuritySeverity.low,
                title="Password field allows autocomplete",
                detail="Password input without autocomplete='off'. Browsers may cache credentials.",
                evidence=f"action={form.action}",
                url=url,
                auth_context=auth_ctx,
            ))

        # Form action over HTTP on HTTPS page
        if url.startswith("https://") and form.action.startswith("http://"):
            findings.append(SecurityFinding(
                category=SecurityCategory.mixed_content,
                severity=SecuritySeverity.high,
                title="Form submits to HTTP endpoint",
                detail="HTTPS page has a form that submits to an insecure HTTP URL.",
                evidence=f"action={form.action}",
                url=url,
                auth_context=auth_ctx,
            ))

    return findings


def check_xss_signals(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Check for XSS-related signals: reflected params, inline event handlers, dangerous patterns."""
    findings: list[SecurityFinding] = []

    # Check for URL parameters reflected in page text (basic reflected XSS indicator)
    parsed = urlparse(url)
    if parsed.query:
        params = parsed.query.split("&")
        for param in params:
            if "=" in param:
                _, value = param.split("=", 1)
                if len(value) > 3 and value in capture.page_text:
                    findings.append(SecurityFinding(
                        category=SecurityCategory.xss,
                        severity=SecuritySeverity.medium,
                        title="URL parameter reflected in page content",
                        detail="A query parameter value appears in the page body. If not properly escaped, this may be a reflected XSS vector.",
                        evidence=f"param value '{value[:50]}' found in page text",
                        url=url,
                        auth_context=capture.auth_context,
                    ))

    return findings


def scan_capture(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Run all passive security checks on a single capture."""
    findings: list[SecurityFinding] = []
    findings.extend(check_security_headers(url, capture.response_headers, capture.auth_context))
    findings.extend(check_cookies(url, capture.cookies, capture.auth_context))
    findings.extend(check_mixed_content(url, capture))
    findings.extend(check_cors(url, capture.response_headers, capture.auth_context))
    findings.extend(check_information_disclosure(url, capture.response_headers, capture))
    findings.extend(check_forms(url, capture.forms, capture.auth_context))
    findings.extend(check_xss_signals(url, capture))
    return findings


def scan_graph(graph: SiteGraph) -> list[SecurityFinding]:
    """Run security scans across all captured nodes. Returns consolidated findings.

    Site-wide findings (headers, missing policies) are consolidated into a single
    finding with affected_urls listing all pages. Per-page findings (cookies, forms,
    reflected params) remain per-URL.
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

    return list(consolidated.values()) + per_url
