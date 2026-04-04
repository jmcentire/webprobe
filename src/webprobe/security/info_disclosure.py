"""Information disclosure checks -- headers, stack traces, injection signals, secrets."""

from __future__ import annotations

import logging
import re

from webprobe.models import (
    NodeCapture,
    ResponseHeaders,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
)

logger = logging.getLogger(__name__)


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


def check_injection_signals(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Check page content for injection-related error messages."""
    findings: list[SecurityFinding] = []
    text = capture.page_text

    if not text:
        return findings

    text_lower = text.lower()

    # SQL error patterns
    sql_patterns = [
        (r"you have an error in your sql syntax", "MySQL SQL syntax error"),
        (r"ORA-\d{5}", "Oracle database error"),
        (r"mysql_fetch", "MySQL function exposed"),
        (r"pg_query", "PostgreSQL function exposed"),
        (r"sqlite3.*error", "SQLite error"),
        (r"SQLSTATE\[", "SQL state error"),
        (r"unclosed quotation mark", "SQL unclosed quotation"),
    ]
    for pattern, desc in sql_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(SecurityFinding(
                category=SecurityCategory.injection,
                severity=SecuritySeverity.high,
                title="SQL error pattern detected in page content",
                detail=f"Page contains SQL error message ({desc}), suggesting possible SQL injection vulnerability.",
                evidence=f"Pattern matched: {pattern}",
                url=url,
                auth_context=capture.auth_context,
            ))
            break  # One SQL finding per page

    # Template injection patterns
    template_patterns = [
        (r"TemplateSyntaxError", "Template syntax error"),
        (r"jinja2.*\{\{", "Jinja2 template error"),
    ]
    for pattern, desc in template_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(SecurityFinding(
                category=SecurityCategory.injection,
                severity=SecuritySeverity.medium,
                title="Template injection signal detected",
                detail=f"Page contains template error ({desc}), suggesting possible server-side template injection.",
                evidence=f"Pattern matched: {pattern}",
                url=url,
                auth_context=capture.auth_context,
            ))
            break

    # Command injection patterns
    cmd_patterns = [
        (r"sh: ", "Shell error"),
        (r"bash: ", "Bash error"),
        (r"command not found", "Command not found error"),
    ]
    for pattern, desc in cmd_patterns:
        if re.search(pattern, text_lower):
            findings.append(SecurityFinding(
                category=SecurityCategory.injection,
                severity=SecuritySeverity.high,
                title="Command injection signal detected",
                detail=f"Page contains shell error ({desc}), suggesting possible command injection vulnerability.",
                evidence=f"Pattern matched: {pattern}",
                url=url,
                auth_context=capture.auth_context,
            ))
            break

    # Path traversal patterns
    if "../" in text:
        findings.append(SecurityFinding(
            category=SecurityCategory.injection,
            severity=SecuritySeverity.medium,
            title="Path traversal pattern detected in page content",
            detail="Page contains '../' in error text, suggesting possible path traversal vulnerability.",
            evidence="'../' found in page content",
            url=url,
            auth_context=capture.auth_context,
        ))

    return findings


def check_secrets_in_content(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Check page content for exposed secrets and API keys."""
    findings: list[SecurityFinding] = []
    text = capture.page_text

    if not text:
        return findings

    secret_patterns = [
        (r"AKIA[0-9A-Z]{16}", SecuritySeverity.critical, "AWS access key exposed in page content"),
        (r"AIza[0-9A-Za-z\-_]{35}", SecuritySeverity.high, "Google API key exposed in page content"),
        (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", SecuritySeverity.critical, "Private key exposed in page content"),
        (r"api[_\-]?key\s*[:=]\s*['\"][a-zA-Z0-9]{20,}", SecuritySeverity.medium, "API key pattern found in page content"),
        (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}", SecuritySeverity.medium, "JWT token found in page content"),
    ]

    for pattern, severity, title in secret_patterns:
        match = re.search(pattern, text)
        if match:
            # Redact most of the matched value for evidence
            matched_text = match.group(0)
            redacted = matched_text[:8] + "..." + matched_text[-4:] if len(matched_text) > 12 else matched_text[:4] + "..."
            findings.append(SecurityFinding(
                category=SecurityCategory.information_disclosure,
                severity=severity,
                title=title,
                detail=f"Sensitive secret pattern detected in page content. This could lead to credential theft or unauthorized access.",
                evidence=f"Matched: {redacted}",
                url=url,
                auth_context=capture.auth_context,
            ))

    return findings
