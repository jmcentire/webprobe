"""SecurityFinding -> CheckResult migration wrapper (CA001).

Block 1 path: keeps the existing 15 security submodules untouched, runs them
as before, and produces a parallel ``list[CheckResult]`` under
``dimension=general_security`` via the adapter in ``webprobe.models``. Each
emitted CheckResult uses ``mode=mechanical`` and an :class:`HttpExchange`
evidence variant.

Block-1 weighting (CA010): every emitted CheckResult shares an equal slice of
the dimension. If N findings are emitted, each gets weight ``1/N``. This is
a coarse approximation — a follow-up block will move to per-check-family
fixed weights and emit PASS results for families that ran and found nothing.

The Block 1 model also doesn't yet emit NOT_DETECTED for affirmative-absence
checks (e.g. "no missing CSP" -> PASS); that distinction belongs in the
deeper per-submodule migration. For now: every SecurityFinding -> one FAIL
CheckResult.
"""

from __future__ import annotations

from typing import Iterable

from webprobe.models import (
    CheckResult,
    Fix,
    FixActionType,
    NodeCapture,
    Reference,
    SecurityCategory,
    SecurityFinding,
    SiteGraph,
    security_finding_to_check_result,
)
from webprobe.security.scanner import scan_capture, scan_graph


# Map a SecurityCategory + finding-title fragment to a structured Fix
# action_type. Keeps fix-prompt structure aligned with CA008 without rewriting
# the per-submodule logic. Anything not matched defaults to FixActionType.other.
_FIX_HINTS: tuple[tuple[SecurityCategory, str, FixActionType], ...] = (
    (SecurityCategory.headers, "missing strict-transport-security", FixActionType.add_response_header),
    (SecurityCategory.headers, "missing content-security-policy", FixActionType.add_response_header),
    (SecurityCategory.headers, "missing x-content-type-options", FixActionType.add_response_header),
    (SecurityCategory.headers, "missing referrer-policy", FixActionType.add_response_header),
    (SecurityCategory.headers, "missing permissions-policy", FixActionType.add_response_header),
    (SecurityCategory.headers, "missing clickjacking", FixActionType.add_response_header),
    (SecurityCategory.headers, "weak x-frame-options", FixActionType.modify_response_header),
    (SecurityCategory.headers, "hsts max-age too short", FixActionType.modify_response_header),
    (SecurityCategory.xss, "csp allows", FixActionType.update_csp_directive),
    (SecurityCategory.cookies, "missing secure", FixActionType.set_cookie_attribute),
    (SecurityCategory.cookies, "missing httponly", FixActionType.set_cookie_attribute),
    (SecurityCategory.cookies, "weak samesite", FixActionType.set_cookie_attribute),
)


def _build_fix(finding: SecurityFinding) -> Fix:
    title_lower = finding.title.lower()
    action = FixActionType.other
    for category, fragment, mapped in _FIX_HINTS:
        if finding.category == category and fragment in title_lower:
            action = mapped
            break

    references: list[Reference] = []
    if finding.compliance_violations:
        for cv in finding.compliance_violations:
            references.append(
                Reference(
                    label=f"{cv.standard_name} {cv.control_id}",
                    url="",
                )
            )

    return Fix(
        action_type=action,
        target=finding.url,
        payload={
            "category": finding.category.value,
            "severity": finding.severity.value,
            "detail": finding.detail,
            "evidence": finding.evidence,
        },
        summary=f"Address: {finding.title}",
        references=references,
    )


def _normalize(findings: list[SecurityFinding]) -> list[CheckResult]:
    """Convert findings to CheckResults with weights summing to ~1.0 per CA010."""
    if not findings:
        return []
    weight = 1.0 / len(findings)
    results: list[CheckResult] = []
    for finding in findings:
        fix = _build_fix(finding)
        result = security_finding_to_check_result(
            finding,
            weight=weight,
            fix=fix,
        )
        results.append(result)
    return results


def scan_capture_with_check_results(
    url: str, capture: NodeCapture
) -> tuple[list[SecurityFinding], list[CheckResult]]:
    """Run all per-capture security checks; return findings AND CheckResults.

    Existing callers can ignore the second tuple element. New audit pipeline
    callers pass the CheckResults to the scorecard.
    """
    findings = scan_capture(url, capture)
    results = _normalize(findings)
    return findings, results


def scan_graph_with_check_results(
    graph: SiteGraph,
) -> tuple[list[SecurityFinding], list[CheckResult]]:
    """Run all graph-wide security checks; return findings AND CheckResults."""
    findings = scan_graph(graph)
    results = _normalize(findings)
    return findings, results


def findings_to_check_results(
    findings: Iterable[SecurityFinding],
) -> list[CheckResult]:
    """Stand-alone adapter for callers that already have a list of findings."""
    return _normalize(list(findings))
