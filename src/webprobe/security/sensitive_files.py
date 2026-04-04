"""Sensitive file probing -- check for exposed config files, admin panels, and secrets."""

from __future__ import annotations

import asyncio
import logging

import aiohttp

from webprobe.models import (
    AuthContext,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
)

logger = logging.getLogger(__name__)

# Severity mapping for sensitive paths
_PATH_SEVERITY: dict[str, tuple[SecuritySeverity, str]] = {
    # Critical -- direct credential/config exposure
    "/.env": (SecuritySeverity.critical, "Environment file exposed"),
    "/.git/config": (SecuritySeverity.critical, "Git config exposed"),
    "/.git/HEAD": (SecuritySeverity.critical, "Git HEAD exposed"),
    "/.htpasswd": (SecuritySeverity.critical, "htpasswd file exposed"),
    "/id_rsa": (SecuritySeverity.critical, "Private SSH key exposed"),
    "/id_ecdsa": (SecuritySeverity.critical, "Private SSH key exposed"),
    "/id_ed25519": (SecuritySeverity.critical, "Private SSH key exposed"),
    # High -- admin/debug/database
    "/phpinfo.php": (SecuritySeverity.high, "phpinfo() page exposed"),
    "/server-status": (SecuritySeverity.high, "Apache server-status exposed"),
    "/server-info": (SecuritySeverity.high, "Apache server-info exposed"),
    "/backup.sql": (SecuritySeverity.high, "SQL backup file exposed"),
    "/dump.sql": (SecuritySeverity.high, "SQL dump file exposed"),
    # Medium -- admin panels
    "/wp-admin": (SecuritySeverity.medium, "WordPress admin panel found"),
    "/wp-login.php": (SecuritySeverity.medium, "WordPress login page found"),
    "/admin": (SecuritySeverity.medium, "Admin panel found"),
    "/console": (SecuritySeverity.medium, "Console endpoint found"),
    # Info -- positive signals
    "/.well-known/security.txt": (SecuritySeverity.info, "security.txt present"),
    # Low -- API docs
    "/swagger.json": (SecuritySeverity.low, "Swagger API spec exposed"),
    "/openapi.json": (SecuritySeverity.low, "OpenAPI spec exposed"),
    "/api/docs": (SecuritySeverity.low, "API documentation exposed"),
}


async def probe_sensitive_files(
    base_url: str,
    paths: list[str] | None = None,
    request_delay_ms: int = 100,
) -> list[SecurityFinding]:
    """Send HEAD requests to known sensitive paths and report accessible ones.

    Args:
        base_url: The base URL to probe (e.g. https://example.com).
        paths: List of paths to check. Defaults to the built-in path list.
        request_delay_ms: Delay between requests in milliseconds.

    Returns:
        List of SecurityFinding for accessible paths.
    """
    findings: list[SecurityFinding] = []

    if paths is None:
        paths = list(_PATH_SEVERITY.keys())

    # Normalize base URL
    base = base_url.rstrip("/")

    delay_seconds = request_delay_ms / 1000.0

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for path in paths:
                probe_url = base + path
                try:
                    async with session.head(probe_url, allow_redirects=False) as resp:
                        if resp.status == 200:
                            severity, title = _PATH_SEVERITY.get(
                                path,
                                (SecuritySeverity.low, f"Sensitive path accessible: {path}"),
                            )

                            # security.txt is a positive finding
                            if path == "/.well-known/security.txt":
                                detail = "Site has a security.txt file, which is a positive security practice."
                            else:
                                detail = f"HEAD request to {path} returned 200. This file/endpoint should not be publicly accessible."

                            findings.append(SecurityFinding(
                                category=SecurityCategory.sensitive_files,
                                severity=severity,
                                title=title,
                                detail=detail,
                                evidence=f"HEAD {probe_url} -> 200",
                                url=base,
                                auth_context=AuthContext.anonymous,
                            ))
                except Exception:
                    logger.debug("Failed to probe %s", probe_url, exc_info=True)

                if delay_seconds > 0:
                    await asyncio.sleep(delay_seconds)

    except Exception:
        logger.warning("Sensitive file probing failed for %s", base_url, exc_info=True)

    return findings
