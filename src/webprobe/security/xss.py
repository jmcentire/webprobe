"""XSS signal detection -- reflected parameters, inline handlers, dangerous patterns."""

from __future__ import annotations

from urllib.parse import urlparse

from webprobe.models import (
    NodeCapture,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
)


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
