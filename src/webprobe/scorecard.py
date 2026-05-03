"""Scorecard aggregation (CA010, CA011, CA012, CA023).

Aggregates a flat ``list[CheckResult]`` (the scheduler output) into a
:class:`Scorecard` with per-dimension subscores, per-dimension bands, and
one overall band. Never produces a single rolled-up overall numeric score.

Default band mapping (CA023):
  L5: every dimension >= 80
  L4: no dimension < 60 AND a majority >= 80
  L3: no dimension < 40
  L2: no critical dimension < 20
  L1: baseline (any check ran)

The mapping is operator-overridable via :class:`ScorecardConfig.band_rules`
to support per-org PR-gating policy. The overall band is floor-bounded by
the minimum dimension band (CA012).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Iterable

from webprobe.models import (
    CheckResult,
    CheckStatus,
    DimensionId,
    DimensionScore,
    SCHEMA_VERSION,
    Scorecard,
    ScorecardBand,
)

logger = logging.getLogger(__name__)


_BAND_ORDER: tuple[ScorecardBand, ...] = (
    ScorecardBand.L1,
    ScorecardBand.L2,
    ScorecardBand.L3,
    ScorecardBand.L4,
    ScorecardBand.L5,
)
_BAND_INDEX: dict[ScorecardBand, int] = {b: i for i, b in enumerate(_BAND_ORDER)}


# Dimensions classified as "critical" for the L2 floor in default rules.
# Operators override via ScorecardConfig.critical_dimensions.
DEFAULT_CRITICAL_DIMENSIONS: frozenset[str] = frozenset({
    DimensionId.general_security.value,
    DimensionId.api_surface.value,
    DimensionId.bot_access.value,
})


@dataclass
class ScorecardConfig:
    """Operator-overridable scoring policy."""

    critical_dimensions: frozenset[str] = DEFAULT_CRITICAL_DIMENSIONS
    # Custom band rule callable: (subscores: dict[dim, float]) -> ScorecardBand
    band_rules: Callable[[dict[str, float]], ScorecardBand] | None = None
    # Threshold for "majority" (default: > 0.5 of dimensions ≥ band_4_threshold)
    band_4_majority_threshold: float = 0.5
    # Numeric thresholds (CA023 default values; operator-overridable)
    band_5_floor: float = 80.0
    band_4_no_dimension_below: float = 60.0
    band_4_majority_floor: float = 80.0
    band_3_no_dimension_below: float = 40.0
    band_2_no_critical_below: float = 20.0


def _band_for_subscore(subscore: float) -> ScorecardBand:
    """Map a single dimension's subscore to its band (used per-dimension)."""
    if subscore >= 80.0:
        return ScorecardBand.L5
    if subscore >= 60.0:
        return ScorecardBand.L4
    if subscore >= 40.0:
        return ScorecardBand.L3
    if subscore >= 20.0:
        return ScorecardBand.L2
    return ScorecardBand.L1


def _per_dimension_score(
    dimension: DimensionId, results: list[CheckResult]
) -> DimensionScore:
    """Compute a DimensionScore from the CheckResults for one dimension.

    Subscore is the weighted PASS percentage:
        subscore = 100 * sum(w_i for r_i if PASS) / sum(w_i for r_i if not SKIPPED)

    SKIPPED checks are excluded from the denominator so mechanical-only mode
    isn't unduly penalized for LLM-only checks (CA007).

    NOT_DETECTED counts as a fail toward the dimension subscore (the page is
    measurably missing the feature) but is reported separately so the
    reporter can distinguish "fix this" from "missing artifact" upstream.
    """
    pass_count = 0
    fail_count = 0
    not_detected_count = 0
    skipped_count = 0
    weight_sum_active = 0.0  # PASS + FAIL + NOT_DETECTED weights
    weight_sum_pass = 0.0

    for r in results:
        if r.status == CheckStatus.skipped:
            skipped_count += 1
            continue
        weight_sum_active += r.weight
        if r.status == CheckStatus.pass_:
            pass_count += 1
            weight_sum_pass += r.weight
        elif r.status == CheckStatus.fail:
            fail_count += 1
        elif r.status == CheckStatus.not_detected:
            not_detected_count += 1

    if weight_sum_active <= 0.0:
        subscore = 0.0
    else:
        subscore = 100.0 * (weight_sum_pass / weight_sum_active)

    band = _band_for_subscore(subscore)
    mode_partial = skipped_count > 0

    return DimensionScore(
        dimension=dimension,
        subscore=subscore,
        band=band,
        pass_count=pass_count,
        fail_count=fail_count,
        not_detected_count=not_detected_count,
        skipped_count=skipped_count,
        mode_partial=mode_partial,
        weight_sum=weight_sum_active,
    )


def _default_overall_band(
    subscores: dict[str, float],
    *,
    critical_dimensions: frozenset[str],
    cfg: ScorecardConfig,
) -> ScorecardBand:
    """CA023 default mapping. See module docstring."""
    if not subscores:
        return ScorecardBand.L1

    values = list(subscores.values())

    # L5: every dimension >= band_5_floor
    if all(v >= cfg.band_5_floor for v in values):
        return ScorecardBand.L5

    # L4: no dimension < 60 AND majority >= 80
    if (
        all(v >= cfg.band_4_no_dimension_below for v in values)
        and (sum(1 for v in values if v >= cfg.band_4_majority_floor) / len(values))
        > cfg.band_4_majority_threshold
    ):
        return ScorecardBand.L4

    # L3: no dimension < 40
    if all(v >= cfg.band_3_no_dimension_below for v in values):
        return ScorecardBand.L3

    # L2: no critical dimension < 20
    crits_below = [
        v for k, v in subscores.items()
        if k in critical_dimensions and v < cfg.band_2_no_critical_below
    ]
    if not crits_below:
        return ScorecardBand.L2

    return ScorecardBand.L1


def aggregate(
    *,
    run_id: str,
    target_url: str,
    results: Iterable[CheckResult],
    mode: str = "full",
    config: ScorecardConfig | None = None,
) -> Scorecard:
    """Aggregate CheckResults into a Scorecard (CA010/011/012/023).

    Per-dimension subscore + band (and an overall band floor-bounded by the
    minimum dimension band, CA012). The overall band rule is configurable
    via ``config.band_rules`` if the operator needs custom PR-gating policy.
    """
    cfg = config or ScorecardConfig()

    # Group results by dimension.
    by_dim: dict[DimensionId, list[CheckResult]] = {}
    for r in results:
        by_dim.setdefault(r.dimension, []).append(r)

    dimensions: dict[str, DimensionScore] = {}
    for dim, dim_results in by_dim.items():
        score = _per_dimension_score(dim, dim_results)
        dimensions[dim.value] = score

    # Compute overall band from subscores.
    subscores = {k: v.subscore for k, v in dimensions.items()}
    if cfg.band_rules is not None:
        overall = cfg.band_rules(subscores)
    else:
        overall = _default_overall_band(
            subscores,
            critical_dimensions=cfg.critical_dimensions,
            cfg=cfg,
        )

    # Floor-bound overall by minimum dimension band (CA012).
    if dimensions:
        min_band = min(dimensions.values(), key=lambda d: _BAND_INDEX[d.band]).band
        if _BAND_INDEX[overall] > _BAND_INDEX[min_band]:
            overall = min_band

    return Scorecard(
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        target_url=target_url,
        mode=mode,  # type: ignore[arg-type]
        dimensions=dimensions,
        overall_band=overall,
    )


__all__ = [
    "DEFAULT_CRITICAL_DIMENSIONS",
    "ScorecardConfig",
    "aggregate",
]
