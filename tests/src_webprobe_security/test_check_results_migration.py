"""Tests for the SecurityFinding -> CheckResult migration wrapper (Block 1)."""

from __future__ import annotations

import pytest

from webprobe.models import (
    AuthContext,
    CheckMode,
    CheckSeverity,
    CheckStatus,
    CookieInfo,
    DimensionId,
    FixActionType,
    NodeCapture,
    Resource,
    ResourceType,
    ResponseHeaders,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
    validate_dimension_weights,
)
from webprobe.security import (
    findings_to_check_results,
    scan_capture_with_check_results,
)


def _bare_capture() -> NodeCapture:
    """A capture with enough holes to trip many security checks."""
    return NodeCapture(
        auth_context=AuthContext.anonymous,
        http_status=200,
        response_headers=ResponseHeaders(raw={
            "content-type": "text/html",
            "server": "nginx/1.18.0",
            "x-powered-by": "PHP/7.4.3",
        }),
        cookies=[
            CookieInfo(name="session", secure=False, http_only=False, same_site=""),
        ],
    )


def test_scan_capture_dual_emit_lengths_match() -> None:
    findings, results = scan_capture_with_check_results("https://x.test/", _bare_capture())
    assert len(findings) > 0
    assert len(findings) == len(results)


def test_all_results_under_general_security() -> None:
    _, results = scan_capture_with_check_results("https://x.test/", _bare_capture())
    assert all(r.dimension == DimensionId.general_security for r in results)


def test_all_results_mode_mechanical() -> None:
    _, results = scan_capture_with_check_results("https://x.test/", _bare_capture())
    assert all(r.mode == CheckMode.mechanical for r in results)


def test_all_results_status_fail_block1() -> None:
    """Block 1 emits FAIL only; PASS/NOT_DETECTED comes in the per-submodule migration."""
    _, results = scan_capture_with_check_results("https://x.test/", _bare_capture())
    assert all(r.status == CheckStatus.fail for r in results)


def test_all_results_have_fix() -> None:
    """CA008: status=FAIL requires Fix."""
    _, results = scan_capture_with_check_results("https://x.test/", _bare_capture())
    assert all(r.fix is not None for r in results)


def test_weights_sum_to_one() -> None:
    """CA010: dimension-internal weights sum to 1.0 (within float epsilon)."""
    _, results = scan_capture_with_check_results("https://x.test/", _bare_capture())
    sums = validate_dimension_weights(results)
    assert sums["general_security"] == pytest.approx(1.0)


def test_check_id_format() -> None:
    _, results = scan_capture_with_check_results("https://x.test/", _bare_capture())
    for r in results:
        assert r.check_id.startswith("general_security.")
        slug = r.check_id.split(".", 1)[1]
        assert slug == slug.lower()
        assert "__" not in slug


def test_findings_to_check_results_empty() -> None:
    assert findings_to_check_results([]) == []


def test_severity_mapping() -> None:
    """critical/high -> critical, medium -> warning, low -> suggestion, info -> info."""
    finding = SecurityFinding(
        category=SecurityCategory.headers,
        severity=SecuritySeverity.high,
        title="Missing Strict-Transport-Security header",
        url="https://x",
    )
    [r] = findings_to_check_results([finding])
    assert r.severity == CheckSeverity.critical


def test_fix_action_type_for_known_titles() -> None:
    """The action_type hint table picks structured kinds for common findings."""
    finding = SecurityFinding(
        category=SecurityCategory.headers,
        severity=SecuritySeverity.high,
        title="Missing Strict-Transport-Security header",
        url="https://x",
    )
    [r] = findings_to_check_results([finding])
    assert r.fix.action_type == FixActionType.add_response_header

    cookie_finding = SecurityFinding(
        category=SecurityCategory.cookies,
        severity=SecuritySeverity.high,
        title="Cookie 'session' missing Secure flag",
        url="https://x",
    )
    [cr] = findings_to_check_results([cookie_finding])
    assert cr.fix.action_type == FixActionType.set_cookie_attribute


def test_existing_scan_capture_unchanged() -> None:
    """Backwards compat: existing scan_capture path still returns SecurityFinding only."""
    from webprobe.security import scan_capture

    findings = scan_capture("https://x.test/", _bare_capture())
    assert all(isinstance(f, SecurityFinding) for f in findings)


def test_evidence_is_http_exchange_variant() -> None:
    _, results = scan_capture_with_check_results("https://x.test/", _bare_capture())
    for r in results:
        assert r.evidence.kind == "http_exchange"  # type: ignore[union-attr]


def test_mixed_content_finding_emitted_for_https() -> None:
    """End-to-end: mixed-content scenario produces a CheckResult with a Fix."""
    cap = _bare_capture()
    cap.resources = [
        Resource(url="http://insecure.example/script.js", resource_type=ResourceType.script, status_code=200),
    ]
    findings, results = scan_capture_with_check_results("https://x.test/", cap)
    titles = {r.title for r in results}
    assert any("mixed content" in t.lower() for t in titles)
