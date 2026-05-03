"""Tests for the scorecard aggregator (Block 2)."""

from __future__ import annotations

import pytest

from webprobe.models import (
    CheckMode,
    CheckResult,
    CheckSeverity,
    CheckStatus,
    DimensionId,
    Fix,
    FixActionType,
    HttpExchange,
    ScorecardBand,
)
from webprobe.scorecard import (
    DEFAULT_CRITICAL_DIMENSIONS,
    ScorecardConfig,
    aggregate,
)


def _check(
    dim: DimensionId,
    slug: str,
    status: CheckStatus,
    weight: float,
    *,
    mode: CheckMode = CheckMode.mechanical,
    severity: CheckSeverity = CheckSeverity.warning,
) -> CheckResult:
    fix = (
        Fix(action_type=FixActionType.other, target="https://x", payload={}, summary="x")
        if status == CheckStatus.fail
        else None
    )
    reason = "skipped:test" if status == CheckStatus.skipped else None
    if status == CheckStatus.not_detected:
        reason = "artifact_unavailable:test:simulated"  # upstream marker → no fix needed
    return CheckResult(
        dimension=dim,
        check_id=f"{dim.value}.{slug}",
        title=slug,
        goal="goal",
        status=status,
        severity=severity,
        mode=mode,
        weight=weight,
        evidence=HttpExchange(method="GET", url="https://x"),
        reason=reason,
        fix=fix,
    )


# ---- per-dimension subscore ----


def test_subscore_all_pass_is_100() -> None:
    results = [
        _check(DimensionId.discoverability, "a", CheckStatus.pass_, 0.5),
        _check(DimensionId.discoverability, "b", CheckStatus.pass_, 0.5),
    ]
    sc = aggregate(run_id="r", target_url="https://x", results=results)
    d = sc.dimensions[DimensionId.discoverability.value]
    assert d.subscore == pytest.approx(100.0)
    assert d.band == ScorecardBand.L5
    assert d.pass_count == 2
    assert d.fail_count == 0


def test_subscore_all_fail_is_0() -> None:
    results = [
        _check(DimensionId.discoverability, "a", CheckStatus.fail, 0.5),
        _check(DimensionId.discoverability, "b", CheckStatus.fail, 0.5),
    ]
    sc = aggregate(run_id="r", target_url="https://x", results=results)
    d = sc.dimensions[DimensionId.discoverability.value]
    assert d.subscore == pytest.approx(0.0)
    assert d.band == ScorecardBand.L1
    assert d.fail_count == 2


def test_subscore_weighted() -> None:
    """A pass with weight 0.7 + a fail with weight 0.3 -> 70."""
    results = [
        _check(DimensionId.discoverability, "a", CheckStatus.pass_, 0.7),
        _check(DimensionId.discoverability, "b", CheckStatus.fail, 0.3),
    ]
    sc = aggregate(run_id="r", target_url="https://x", results=results)
    assert sc.dimensions[DimensionId.discoverability.value].subscore == pytest.approx(70.0)


def test_skipped_excluded_from_denominator() -> None:
    """Mechanical-only mode: SKIPPED checks must not penalize the dimension subscore (CA007)."""
    results = [
        _check(DimensionId.public_facing_signals, "mech_a", CheckStatus.pass_, 0.4),
        _check(DimensionId.public_facing_signals, "mech_b", CheckStatus.pass_, 0.1),
        _check(
            DimensionId.public_facing_signals, "llm_a",
            CheckStatus.skipped, 0.5, mode=CheckMode.llm,
        ),
    ]
    sc = aggregate(run_id="r", target_url="https://x", results=results, mode="mechanical_only")
    d = sc.dimensions[DimensionId.public_facing_signals.value]
    # Active denominator = 0.5 (mech only); pass = 0.5 -> 100
    assert d.subscore == pytest.approx(100.0)
    assert d.skipped_count == 1
    assert d.mode_partial is True


def test_not_detected_counts_against_score() -> None:
    """NOT_DETECTED is not 'free' — feature absent = scored against."""
    results = [
        _check(DimensionId.discoverability, "a", CheckStatus.pass_, 0.5),
        _check(DimensionId.discoverability, "b", CheckStatus.not_detected, 0.5),
    ]
    sc = aggregate(run_id="r", target_url="https://x", results=results)
    d = sc.dimensions[DimensionId.discoverability.value]
    assert d.subscore == pytest.approx(50.0)
    assert d.not_detected_count == 1


# ---- per-dimension band thresholds ----


def test_band_thresholds() -> None:
    cases = [
        (1.0, ScorecardBand.L5),  # 100
        (0.85, ScorecardBand.L5),  # 85 -> L5
        (0.7, ScorecardBand.L4),  # 70 -> L4
        (0.5, ScorecardBand.L3),  # 50 -> L3
        (0.3, ScorecardBand.L2),  # 30 -> L2
        (0.1, ScorecardBand.L1),  # 10 -> L1
    ]
    for pass_weight, expected in cases:
        results = [
            _check(DimensionId.discoverability, "a", CheckStatus.pass_, pass_weight),
        ]
        if pass_weight < 1.0:
            results.append(_check(
                DimensionId.discoverability, "b", CheckStatus.fail, 1.0 - pass_weight,
            ))
        sc = aggregate(run_id="r", target_url="https://x", results=results)
        d = sc.dimensions[DimensionId.discoverability.value]
        assert d.band == expected, f"pass={pass_weight} -> {expected}, got {d.band}"


# ---- overall band (CA012, CA023) ----


def test_overall_band_l5_when_all_high() -> None:
    results = []
    for dim in [DimensionId.discoverability, DimensionId.bot_access]:
        results.append(_check(dim, "a", CheckStatus.pass_, 1.0))
    sc = aggregate(run_id="r", target_url="https://x", results=results)
    assert sc.overall_band == ScorecardBand.L5


def test_overall_band_floored_by_min_dimension() -> None:
    """CA012: overall cannot exceed the min dimension band."""
    results = [
        _check(DimensionId.discoverability, "a", CheckStatus.pass_, 1.0),  # 100 -> L5
        _check(DimensionId.bot_access, "a", CheckStatus.fail, 1.0),  # 0 -> L1
    ]
    sc = aggregate(run_id="r", target_url="https://x", results=results)
    assert sc.overall_band == ScorecardBand.L1  # floor applies


def test_overall_band_l3_no_dimension_below_40() -> None:
    results = [
        _check(DimensionId.discoverability, "a", CheckStatus.pass_, 0.5),  # 50 -> L3
        _check(DimensionId.discoverability, "b", CheckStatus.fail, 0.5),
        _check(DimensionId.bot_access, "a", CheckStatus.pass_, 0.5),  # 50 -> L3
        _check(DimensionId.bot_access, "b", CheckStatus.fail, 0.5),
    ]
    sc = aggregate(run_id="r", target_url="https://x", results=results)
    assert sc.overall_band == ScorecardBand.L3


def test_overall_band_l1_when_critical_below_20() -> None:
    """A critical dimension at <20 forces L1."""
    results = [
        _check(DimensionId.discoverability, "a", CheckStatus.pass_, 1.0),  # 100 -> L5
        _check(DimensionId.general_security, "a", CheckStatus.fail, 1.0),  # 0 -> L1, critical
    ]
    sc = aggregate(run_id="r", target_url="https://x", results=results)
    # general_security is in DEFAULT_CRITICAL_DIMENSIONS; subscore 0 forces L1 floor
    assert DimensionId.general_security.value in DEFAULT_CRITICAL_DIMENSIONS
    assert sc.overall_band == ScorecardBand.L1


def test_custom_band_rule() -> None:
    """Operators can supply their own band rule."""
    def fixed_l3(_subscores: dict[str, float]) -> ScorecardBand:
        return ScorecardBand.L3

    results = [_check(DimensionId.discoverability, "a", CheckStatus.pass_, 1.0)]
    cfg = ScorecardConfig(band_rules=fixed_l3)
    sc = aggregate(run_id="r", target_url="https://x", results=results, config=cfg)
    # Discoverability subscore is 100 (L5), so floor is L5; custom rule said L3,
    # which is below the floor — overall should be L3.
    assert sc.overall_band == ScorecardBand.L3


# ---- empty + edge cases ----


def test_empty_results() -> None:
    sc = aggregate(run_id="r", target_url="https://x", results=[])
    assert sc.dimensions == {}
    assert sc.overall_band == ScorecardBand.L1


def test_all_skipped_dimension() -> None:
    """A dimension where every check was SKIPPED has subscore 0 and weight_sum 0."""
    results = [
        _check(
            DimensionId.public_facing_signals, "a", CheckStatus.skipped, 1.0,
            mode=CheckMode.llm,
        ),
    ]
    sc = aggregate(run_id="r", target_url="https://x", results=results)
    d = sc.dimensions[DimensionId.public_facing_signals.value]
    assert d.subscore == 0.0
    assert d.weight_sum == 0.0
    assert d.mode_partial is True


def test_mode_field_propagates_to_scorecard() -> None:
    sc = aggregate(
        run_id="r",
        target_url="https://x",
        results=[_check(DimensionId.discoverability, "a", CheckStatus.pass_, 1.0)],
        mode="mechanical_only",
    )
    assert sc.mode == "mechanical_only"
