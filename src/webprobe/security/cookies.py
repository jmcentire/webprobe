"""Cookie security checks -- flags, prefixes, scope analysis."""

from __future__ import annotations

import logging
import time
from urllib.parse import urlparse

from webprobe.models import (
    AuthContext,
    CookieInfo,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
)

logger = logging.getLogger(__name__)


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


def check_cookie_prefixes(url: str, cookies: list[CookieInfo], auth_ctx: AuthContext) -> list[SecurityFinding]:
    """Check that __Host- and __Secure- cookie prefixes are used correctly."""
    findings: list[SecurityFinding] = []

    for cookie in cookies:
        name = cookie.name

        if name.startswith("__Host-"):
            issues = []
            if not cookie.secure:
                issues.append("Secure=false")
            if cookie.path != "/":
                issues.append(f"Path={cookie.path}")
            if cookie.domain:
                issues.append(f"Domain={cookie.domain}")
            if issues:
                findings.append(SecurityFinding(
                    category=SecurityCategory.cookies,
                    severity=SecuritySeverity.medium,
                    title=f"Invalid __Host- cookie prefix: '{name}'",
                    detail=f"__Host- cookies must have Secure=true, Path=/, and no Domain attribute. Issues: {', '.join(issues)}.",
                    evidence=f"name={name}, {', '.join(issues)}",
                    url=url,
                    auth_context=auth_ctx,
                ))

        elif name.startswith("__Secure-"):
            if not cookie.secure:
                findings.append(SecurityFinding(
                    category=SecurityCategory.cookies,
                    severity=SecuritySeverity.medium,
                    title=f"Invalid __Secure- cookie prefix: '{name}'",
                    detail="__Secure- cookies must have Secure=true.",
                    evidence=f"name={name}, Secure=false",
                    url=url,
                    auth_context=auth_ctx,
                ))

    return findings


def check_cookie_scope(url: str, cookies: list[CookieInfo], auth_ctx: AuthContext) -> list[SecurityFinding]:
    """Check cookie scope: long expiry on session cookies and third-party cookie domains."""
    findings: list[SecurityFinding] = []
    page_domain = urlparse(url).hostname or ""

    one_year_seconds = 365 * 24 * 60 * 60

    for cookie in cookies:
        is_session_like = any(
            kw in cookie.name.lower()
            for kw in ("session", "token", "auth", "sid", "jwt", "access")
        )

        # Session cookies with very long expiry (>1 year)
        if is_session_like and cookie.expires > 0:
            remaining = cookie.expires - time.time()
            if remaining > one_year_seconds:
                findings.append(SecurityFinding(
                    category=SecurityCategory.cookies,
                    severity=SecuritySeverity.low,
                    title=f"Session cookie '{cookie.name}' has very long expiry",
                    detail="Session cookie expires more than 1 year from now. Long-lived session cookies increase the window for session hijacking.",
                    evidence=f"name={cookie.name}, expires={cookie.expires}",
                    url=url,
                    auth_context=auth_ctx,
                ))

        # Third-party cookies (domain != page domain)
        cookie_domain = cookie.domain.lstrip(".")
        if cookie_domain and cookie_domain != page_domain and not page_domain.endswith("." + cookie_domain):
            findings.append(SecurityFinding(
                category=SecurityCategory.privacy,
                severity=SecuritySeverity.info,
                title=f"Third-party cookie: '{cookie.name}' from '{cookie.domain}'",
                detail=f"Cookie domain '{cookie.domain}' does not match page domain '{page_domain}'.",
                evidence=f"name={cookie.name}, domain={cookie.domain}, page={page_domain}",
                url=url,
                auth_context=auth_ctx,
            ))

    return findings
