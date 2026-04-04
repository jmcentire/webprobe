"""Mixed content checks -- HTTP resources on HTTPS pages."""

from __future__ import annotations

from webprobe.models import (
    NodeCapture,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
)


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
