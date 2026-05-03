"""Tests for the audit-pipeline additions to webprobe.models (Block 1).

Covers: CheckResult validation invariants (CA001, CA002, CA004, CA008),
Evidence typed union (CA005), Fix structure (CA008), Artifact capture-status
consistency (CA004), Scorecard band-floor (CA012), weight validator (CA010),
SecurityFinding -> CheckResult adapter (CA001).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from webprobe.models import (
    Artifact,
    ArtifactRef,
    ArtifactType,
    AuthContext,
    CaptureStatus,
    CheckMode,
    CheckResult,
    CheckSeverity,
    CheckStatus,
    DimensionId,
    DimensionScore,
    DomExcerpt,
    Fix,
    FixActionType,
    HttpExchange,
    Reference,
    RuntimeProbe,
    SCHEMA_VERSION,
    Scorecard,
    ScorecardBand,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
    security_finding_to_check_result,
    validate_dimension_weights,
)


def _make_evidence() -> HttpExchange:
    return HttpExchange(method="GET", url="https://x.test/", status=200)


def _pass_check(weight: float = 1.0, dim: DimensionId = DimensionId.discoverability) -> CheckResult:
    return CheckResult(
        dimension=dim,
        check_id=f"{dim.value}.example",
        title="example",
        goal="example goal",
        status=CheckStatus.pass_,
        severity=CheckSeverity.info,
        mode=CheckMode.mechanical,
        weight=weight,
        evidence=_make_evidence(),
    )


# ---- schema_version ----


def test_schema_version_bumped() -> None:
    """CO001: schema_version must change when models change. Block 1 -> 1.3+."""
    parts = [int(p) for p in SCHEMA_VERSION.split(".")]
    assert parts >= [1, 3], f"SCHEMA_VERSION={SCHEMA_VERSION} should be ≥1.3 after Block 1"


# ---- CheckResult basic shape ----


def test_check_result_basic_pass() -> None:
    r = _pass_check()
    assert r.dimension == DimensionId.discoverability
    assert r.status == CheckStatus.pass_
    assert r.evidence.kind == "http_exchange"  # type: ignore[union-attr]


def test_check_result_check_id_must_have_dot() -> None:
    """CA001: check_id must be in '<dimension>.<check_slug>' form."""
    with pytest.raises(ValidationError):
        CheckResult(
            dimension=DimensionId.discoverability,
            check_id="no_dot_here",
            title="x", goal="y",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=0.5,
            evidence=_make_evidence(),
        )


def test_check_result_weight_bounds() -> None:
    with pytest.raises(ValidationError):
        CheckResult(
            dimension=DimensionId.discoverability,
            check_id="discoverability.x",
            title="x", goal="y",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=1.1,
            evidence=_make_evidence(),
        )
    with pytest.raises(ValidationError):
        CheckResult(
            dimension=DimensionId.discoverability,
            check_id="discoverability.x",
            title="x", goal="y",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=-0.1,
            evidence=_make_evidence(),
        )


# ---- Trinary status semantics (CA002, CA004) ----


def test_not_detected_requires_reason() -> None:
    """CA004: NOT_DETECTED requires a reason."""
    with pytest.raises(ValidationError):
        CheckResult(
            dimension=DimensionId.discoverability,
            check_id="discoverability.x",
            title="x", goal="y",
            status=CheckStatus.not_detected,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=0.5,
            evidence=_make_evidence(),
        )


def test_skipped_requires_reason() -> None:
    """CA002: SKIPPED requires a reason (e.g. 'mechanical_only_mode')."""
    with pytest.raises(ValidationError):
        CheckResult(
            dimension=DimensionId.discoverability,
            check_id="discoverability.x",
            title="x", goal="y",
            status=CheckStatus.skipped,
            severity=CheckSeverity.info,
            mode=CheckMode.llm,
            weight=0.5,
            evidence=_make_evidence(),
        )


def test_not_detected_with_artifact_unavailable_no_fix_required() -> None:
    """CA004: NOT_DETECTED with upstream-root-cause reason does NOT require fix."""
    r = CheckResult(
        dimension=DimensionId.discoverability,
        check_id="discoverability.sitemap_valid",
        title="sitemap valid",
        goal="sitemap returns valid XML",
        status=CheckStatus.not_detected,
        severity=CheckSeverity.suggestion,
        mode=CheckMode.mechanical,
        weight=0.1,
        evidence=_make_evidence(),
        reason="artifact_unavailable:sitemap:http_503",
    )
    assert r.fix is None
    assert r.reason.startswith("artifact_unavailable:")


def test_not_detected_with_precondition_failed_no_fix_required() -> None:
    """CA014: hybrid precondition fail returns NOT_DETECTED without fix."""
    r = CheckResult(
        dimension=DimensionId.api_surface,
        check_id="api_surface.resource_hierarchy_coherence",
        title="resource hierarchy",
        goal="OpenAPI hierarchy is coherent",
        status=CheckStatus.not_detected,
        severity=CheckSeverity.suggestion,
        mode=CheckMode.hybrid,
        weight=0.1,
        evidence=_make_evidence(),
        reason="precondition_failed:openapi_unreachable",
    )
    assert r.fix is None


def test_not_detected_with_other_reason_requires_fix() -> None:
    """CA008: NOT_DETECTED with non-upstream reason still needs a fix."""
    with pytest.raises(ValidationError):
        CheckResult(
            dimension=DimensionId.structured_data,
            check_id="structured_data.product_image_present",
            title="product image present",
            goal="Product.image declared",
            status=CheckStatus.not_detected,
            severity=CheckSeverity.warning,
            mode=CheckMode.mechanical,
            weight=0.1,
            evidence=_make_evidence(),
            reason="absent_from_jsonld",  # not upstream
        )


def test_fail_requires_fix() -> None:
    """CA008: status=FAIL requires a Fix."""
    with pytest.raises(ValidationError):
        CheckResult(
            dimension=DimensionId.discoverability,
            check_id="discoverability.x",
            title="x", goal="y",
            status=CheckStatus.fail,
            severity=CheckSeverity.warning,
            mode=CheckMode.mechanical,
            weight=0.5,
            evidence=_make_evidence(),
        )


def test_fail_with_fix_ok() -> None:
    fix = Fix(
        action_type=FixActionType.add_meta_tag,
        target="https://x.test/",
        payload={"name": "description"},
        summary="Add meta description",
    )
    r = CheckResult(
        dimension=DimensionId.public_facing_signals,
        check_id="public_facing_signals.meta_description_present",
        title="meta description present",
        goal="Description is set",
        status=CheckStatus.fail,
        severity=CheckSeverity.warning,
        mode=CheckMode.mechanical,
        weight=0.5,
        evidence=_make_evidence(),
        fix=fix,
    )
    assert r.fix.action_type == FixActionType.add_meta_tag


# ---- Evidence union (CA005) ----


def test_evidence_variants_round_trip() -> None:
    base = dict(
        dimension=DimensionId.discoverability,
        check_id="discoverability.x",
        title="x", goal="y",
        status=CheckStatus.pass_,
        severity=CheckSeverity.info,
        mode=CheckMode.mechanical,
        weight=1.0,
    )
    for ev in [
        HttpExchange(method="GET", url="https://x"),
        DomExcerpt(url="https://x", selector="title", html_snippet="<title/>"),
        RuntimeProbe(url="https://x", action="navigator.modelContext", observation={"present": False}),
        ArtifactRef(artifact_id="abc123", excerpt="x"),
    ]:
        r = CheckResult(evidence=ev, **base)
        # Discriminated union: kind round-trips
        d = r.model_dump()
        assert d["evidence"]["kind"] == ev.kind  # type: ignore[union-attr]


# ---- Weight validator (CA010) ----


def test_validate_weights_passes_when_sum_one() -> None:
    checks = [
        _pass_check(weight=0.5),
        _pass_check(weight=0.5),
    ]
    sums = validate_dimension_weights(checks)
    assert sums["discoverability"] == pytest.approx(1.0)


def test_validate_weights_fails_when_off() -> None:
    checks = [_pass_check(weight=0.3), _pass_check(weight=0.3)]
    with pytest.raises(ValueError, match="weights sum"):
        validate_dimension_weights(checks)


def test_validate_weights_per_dimension_independent() -> None:
    checks = [
        _pass_check(weight=1.0, dim=DimensionId.discoverability),
        _pass_check(weight=0.5, dim=DimensionId.bot_access),
        _pass_check(weight=0.5, dim=DimensionId.bot_access),
    ]
    sums = validate_dimension_weights(checks)
    assert sums["discoverability"] == pytest.approx(1.0)
    assert sums["bot_access"] == pytest.approx(1.0)


# ---- Artifact (CA004) ----


def test_artifact_failure_requires_error() -> None:
    """CA004: capture_status != ok requires capture_error."""
    with pytest.raises(ValidationError):
        Artifact(
            artifact_type=ArtifactType.robots_txt,
            source_url="https://x/robots.txt",
            capture_status=CaptureStatus.http_error,
            # capture_error missing
        )


def test_artifact_ok_no_error_required() -> None:
    a = Artifact(
        artifact_type=ArtifactType.robots_txt,
        source_url="https://x/robots.txt",
        payload={"groups": []},
    )
    assert a.capture_status == CaptureStatus.ok
    assert a.capture_error == ""


# ---- Scorecard (CA012) ----


def _dim_score(band: ScorecardBand, subscore: float = 80.0) -> DimensionScore:
    return DimensionScore(
        dimension=DimensionId.discoverability,
        subscore=subscore,
        band=band,
    )


def test_scorecard_overall_band_cannot_exceed_floor() -> None:
    sc = Scorecard(
        run_id="r1",
        dimensions={
            "discoverability": DimensionScore(
                dimension=DimensionId.discoverability, subscore=20.0, band=ScorecardBand.L1
            ),
            "bot_access": DimensionScore(
                dimension=DimensionId.bot_access, subscore=90.0, band=ScorecardBand.L5
            ),
        },
        overall_band=ScorecardBand.L1,  # OK: at floor
    )
    assert sc.overall_band == ScorecardBand.L1

    with pytest.raises(ValidationError):
        Scorecard(
            run_id="r2",
            dimensions={
                "discoverability": DimensionScore(
                    dimension=DimensionId.discoverability, subscore=20.0, band=ScorecardBand.L1
                ),
            },
            overall_band=ScorecardBand.L5,  # exceeds floor
        )


# ---- SecurityFinding -> CheckResult adapter ----


def test_security_finding_adapter_basic() -> None:
    finding = SecurityFinding(
        category=SecurityCategory.headers,
        severity=SecuritySeverity.high,
        title="Missing Strict-Transport-Security header",
        url="https://x.test/",
    )
    r = security_finding_to_check_result(finding, weight=0.25)
    assert r.dimension == DimensionId.general_security
    assert r.status == CheckStatus.fail
    assert r.mode == CheckMode.mechanical
    assert r.severity == CheckSeverity.critical  # high -> critical
    assert r.fix is not None
    assert r.weight == 0.25
    assert r.check_id.startswith("general_security.")
    assert "_" in r.check_id  # slugified


def test_security_finding_adapter_severity_map() -> None:
    cases = [
        (SecuritySeverity.critical, CheckSeverity.critical),
        (SecuritySeverity.high, CheckSeverity.critical),
        (SecuritySeverity.medium, CheckSeverity.warning),
        (SecuritySeverity.low, CheckSeverity.suggestion),
        (SecuritySeverity.info, CheckSeverity.info),
    ]
    for sev_in, sev_out in cases:
        f = SecurityFinding(
            category=SecurityCategory.headers, severity=sev_in,
            title=f"x_{sev_in.value}", url="https://x",
        )
        r = security_finding_to_check_result(f, weight=1.0)
        assert r.severity == sev_out, f"{sev_in} -> {sev_out} expected, got {r.severity}"
