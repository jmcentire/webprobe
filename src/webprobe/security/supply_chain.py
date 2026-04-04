"""Supply chain checks -- JS library versions, SRI, third-party script inventory."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from webprobe.models import (
    NodeCapture,
    ResourceType,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
)

logger = logging.getLogger(__name__)


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a version string like '3.5.1' into a comparable tuple."""
    try:
        return tuple(int(x) for x in version_str.split("."))
    except (ValueError, AttributeError):
        return ()


# Maps: (library name, url regex pattern, vulnerable version ceiling, description)
VULNERABLE_LIBRARIES: list[tuple[str, str, str, str]] = [
    ("jQuery", r"jquery[.-](\d+\.\d+\.\d+)", "3.5.0", "XSS via htmlPrefilter"),
    ("Angular.js", r"angular[.-](\d+\.\d+\.\d+)", "1.8.0", "Multiple XSS vulnerabilities"),
    ("Bootstrap", r"bootstrap[.-](\d+\.\d+\.\d+)", "4.3.1", "XSS vulnerability"),
    ("lodash", r"lodash[.-](\d+\.\d+\.\d+)", "4.17.21", "Prototype pollution"),
    ("moment.js", r"moment[.-](\d+\.\d+\.\d+)", "2.29.4", "ReDoS vulnerability"),
]


def check_js_library_versions(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Check script resource URLs for known-vulnerable JS library versions."""
    findings: list[SecurityFinding] = []

    if not capture.resources:
        return findings

    for resource in capture.resources:
        if resource.resource_type != ResourceType.script:
            continue

        resource_url_lower = resource.url.lower()

        for lib_name, pattern, vuln_ceiling, vuln_desc in VULNERABLE_LIBRARIES:
            match = re.search(pattern, resource_url_lower, re.IGNORECASE)
            if not match:
                continue

            detected_version = match.group(1)
            detected_tuple = _parse_version(detected_version)
            ceiling_tuple = _parse_version(vuln_ceiling)

            if not detected_tuple or not ceiling_tuple:
                continue

            if detected_tuple < ceiling_tuple:
                findings.append(SecurityFinding(
                    category=SecurityCategory.supply_chain,
                    severity=SecuritySeverity.medium,
                    title=f"Vulnerable {lib_name} version detected: {detected_version}",
                    detail=f"{lib_name} {detected_version} is below {vuln_ceiling} and is affected by: {vuln_desc}.",
                    evidence=resource.url[:200],
                    url=url,
                    auth_context=capture.auth_context,
                ))
            elif detected_tuple == ceiling_tuple:
                # Exactly at the fix version -- not vulnerable but note it
                pass
            # Versions above the ceiling are fine

    return findings


def check_sri(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Check external scripts/stylesheets for Subresource Integrity (SRI)."""
    findings: list[SecurityFinding] = []

    if not capture.resources:
        return findings

    try:
        page_host = urlparse(url).hostname or ""
    except Exception:
        return findings

    # Known CDN domains
    cdn_patterns = (
        "cdn.", "cdnjs.", "jsdelivr.", "unpkg.", "cloudflare.",
        "googleapis.", "gstatic.", "bootstrapcdn.",
    )

    for resource in capture.resources:
        if resource.resource_type not in (ResourceType.script, ResourceType.stylesheet):
            continue

        try:
            resource_host = urlparse(resource.url).hostname or ""
        except Exception:
            continue

        # Skip same-origin resources
        if resource_host == page_host:
            continue
        if not resource_host:
            continue

        if resource.has_integrity:
            continue

        is_cdn = any(cdn in resource_host for cdn in cdn_patterns)
        sev = SecuritySeverity.medium if is_cdn else SecuritySeverity.low

        findings.append(SecurityFinding(
            category=SecurityCategory.supply_chain,
            severity=sev,
            title=f"External {resource.resource_type.value} missing SRI",
            detail=f"External {resource.resource_type.value} from '{resource_host}' loaded without Subresource Integrity hash. If the CDN is compromised, malicious code could be injected.",
            evidence=resource.url[:200],
            url=url,
            auth_context=capture.auth_context,
        ))

    return findings


def check_third_party_script_inventory(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Count external scripts by domain. Flag if more than 10 unique third-party script domains."""
    findings: list[SecurityFinding] = []

    if not capture.resources:
        return findings

    try:
        page_host = urlparse(url).hostname or ""
    except Exception:
        return findings

    third_party_domains: set[str] = set()

    for resource in capture.resources:
        if resource.resource_type != ResourceType.script:
            continue
        try:
            resource_host = urlparse(resource.url).hostname or ""
        except Exception:
            continue
        if resource_host and resource_host != page_host:
            third_party_domains.add(resource_host)

    if len(third_party_domains) > 10:
        findings.append(SecurityFinding(
            category=SecurityCategory.supply_chain,
            severity=SecuritySeverity.info,
            title=f"Large third-party script footprint: {len(third_party_domains)} domains",
            detail=f"Page loads scripts from {len(third_party_domains)} different third-party domains. This increases supply chain attack surface.",
            evidence=", ".join(sorted(third_party_domains)[:15]),
            url=url,
            auth_context=capture.auth_context,
        ))

    return findings
