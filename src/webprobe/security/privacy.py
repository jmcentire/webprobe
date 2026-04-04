"""Privacy checks -- policies, consent, trackers, PII, sensitive URL params."""

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

# Known tracker domains
_TRACKER_DOMAINS = {
    "google-analytics.com",
    "googletagmanager.com",
    "facebook.net",
    "connect.facebook.net",
    "platform.twitter.com",
    "doubleclick.net",
    "googlesyndication.com",
    "amazon-adsystem.com",
    "hotjar.com",
    "mixpanel.com",
    "segment.com",
    "intercom.io",
}

# PII-related input name patterns
_PII_PATTERNS = [
    r"ssn",
    r"social.security",
    r"credit.card",
    r"card.number",
    r"phone",
    r"telephone",
    r"date.of.birth",
    r"dob",
    r"passport",
    r"national.id",
]

# Sensitive URL parameter names
_SENSITIVE_PARAMS = {
    "password", "passwd", "pwd", "token", "secret", "api_key",
    "apikey", "access_token", "auth", "session_id", "credit_card",
}


def check_privacy_policy(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Check if the page links to a privacy policy."""
    findings: list[SecurityFinding] = []

    if not capture.outgoing_links:
        return findings

    privacy_keywords = ("privacy", "privacy-policy", "data-protection")
    has_privacy_link = any(
        any(kw in link.lower() for kw in privacy_keywords)
        for link in capture.outgoing_links
    )

    if not has_privacy_link:
        findings.append(SecurityFinding(
            category=SecurityCategory.privacy,
            severity=SecuritySeverity.info,
            title="No privacy policy link found",
            detail="Page does not link to a privacy policy. This may be a regulatory concern (GDPR, CCPA).",
            url=url,
            auth_context=capture.auth_context,
        ))

    return findings


def check_cookie_consent(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Check for cookie consent indicators in page content."""
    findings: list[SecurityFinding] = []

    if not capture.page_text:
        return findings

    text_lower = capture.page_text.lower()
    consent_phrases = [
        "cookie consent",
        "cookie policy",
        "we use cookies",
        "accept cookies",
        "accept all",
    ]

    has_consent = any(phrase in text_lower for phrase in consent_phrases)

    findings.append(SecurityFinding(
        category=SecurityCategory.privacy,
        severity=SecuritySeverity.info,
        title="Cookie consent mechanism detected" if has_consent else "No cookie consent mechanism detected",
        detail=(
            "Page contains cookie consent language."
            if has_consent
            else "No cookie consent banner or language detected. May be required under GDPR/ePrivacy."
        ),
        url=url,
        auth_context=capture.auth_context,
    ))

    return findings


def check_third_party_trackers(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Check for known third-party tracker domains in page resources."""
    findings: list[SecurityFinding] = []

    if not capture.resources:
        return findings

    found_trackers: set[str] = set()

    for resource in capture.resources:
        try:
            resource_host = urlparse(resource.url).hostname or ""
        except Exception:
            continue
        for tracker in _TRACKER_DOMAINS:
            if resource_host == tracker or resource_host.endswith("." + tracker):
                found_trackers.add(tracker)

    for tracker in sorted(found_trackers):
        findings.append(SecurityFinding(
            category=SecurityCategory.privacy,
            severity=SecuritySeverity.info,
            title=f"Third-party tracker detected: {tracker}",
            detail=f"Page loads resources from known tracker domain '{tracker}'.",
            evidence=tracker,
            url=url,
            auth_context=capture.auth_context,
        ))

    return findings


def check_pii_in_forms(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Check form input names for PII-related fields (inventory/informational)."""
    findings: list[SecurityFinding] = []

    if not capture.forms:
        return findings

    for form in capture.forms:
        if not form.input_names:
            continue
        for input_name in form.input_names:
            name_lower = input_name.lower()
            for pattern in _PII_PATTERNS:
                if re.search(pattern, name_lower):
                    findings.append(SecurityFinding(
                        category=SecurityCategory.privacy,
                        severity=SecuritySeverity.info,
                        title=f"PII field detected: '{input_name}'",
                        detail=f"Form collects potentially sensitive PII (matched pattern: {pattern}). Ensure proper handling and encryption.",
                        evidence=f"input_name={input_name}, form_action={form.action}",
                        url=url,
                        auth_context=capture.auth_context,
                    ))
                    break  # One finding per input name

    return findings


def check_sensitive_url_params(url: str, capture: NodeCapture) -> list[SecurityFinding]:
    """Check URL query parameters for sensitive keys like passwords and tokens."""
    findings: list[SecurityFinding] = []

    parsed = urlparse(url)
    if not parsed.query:
        return findings

    params = parse_qs(parsed.query, keep_blank_values=True)
    for param_name in params:
        if param_name.lower() in _SENSITIVE_PARAMS:
            findings.append(SecurityFinding(
                category=SecurityCategory.privacy,
                severity=SecuritySeverity.high,
                title=f"Sensitive parameter in URL: '{param_name}'",
                detail=f"URL contains sensitive parameter '{param_name}'. Values in URLs leak via Referer headers, server logs, and browser history.",
                evidence=f"param={param_name} in {parsed.path}?...",
                url=url,
                auth_context=capture.auth_context,
            ))

    return findings
