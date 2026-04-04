"""Authentication and session management checks."""

from __future__ import annotations

import logging
import re
from urllib.parse import parse_qs, urlparse

from webprobe.models import (
    NodeCapture,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
)

logger = logging.getLogger(__name__)

# Session ID parameter names commonly seen in URLs
_SESSION_PARAMS = {"sid", "sessionid", "jsessionid", "phpsessid"}

# Redirect parameter names that may enable open redirect
_REDIRECT_PARAMS = {
    "redirect_url", "next", "return_to", "goto", "continue",
    "dest", "destination", "rurl", "target_url",
}


def check_session_in_url(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Check URL for session ID parameters passed in query string."""
    findings: list[SecurityFinding] = []

    parsed = urlparse(url)
    if not parsed.query:
        return findings

    params = parse_qs(parsed.query, keep_blank_values=True)
    for param_name in params:
        if param_name.lower() in _SESSION_PARAMS:
            findings.append(SecurityFinding(
                category=SecurityCategory.auth_session,
                severity=SecuritySeverity.high,
                title="Session ID exposed in URL",
                detail=f"URL contains session parameter '{param_name}'. Session IDs in URLs can be leaked via Referer headers, logs, and browser history.",
                evidence=f"param={param_name} in {url[:200]}",
                url=url,
                auth_context=capture.auth_context,
            ))

    return findings


def check_open_redirect(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Check URL for redirect parameters that may enable open redirect attacks."""
    findings: list[SecurityFinding] = []

    parsed = urlparse(url)
    if not parsed.query:
        return findings

    params = parse_qs(parsed.query, keep_blank_values=True)
    for param_name, values in params.items():
        if param_name.lower() in _REDIRECT_PARAMS:
            for value in values:
                # Check if the value looks like a URL (starts with http/https or //)
                if re.match(r"^(https?://|//)", value, re.IGNORECASE):
                    findings.append(SecurityFinding(
                        category=SecurityCategory.auth_session,
                        severity=SecuritySeverity.medium,
                        title="Potential open redirect",
                        detail=f"URL parameter '{param_name}' contains a URL value, suggesting a potential open redirect vulnerability.",
                        evidence=f"param={param_name}, value={value[:100]}",
                        url=url,
                        auth_context=capture.auth_context,
                    ))
                    break  # One finding per param

    return findings
