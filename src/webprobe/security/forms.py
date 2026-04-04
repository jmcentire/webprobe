"""Form security checks -- CSRF tokens, password fields, autocomplete."""

from __future__ import annotations

from webprobe.models import (
    AuthContext,
    FormInfo,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
)


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
