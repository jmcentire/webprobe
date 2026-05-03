"""Tests for the audit scheduler (Block 2)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

from webprobe.artifact_store import ArtifactStore
from webprobe.models import (
    CheckMode,
    CheckResult,
    CheckSeverity,
    CheckStatus,
    DimensionId,
    HttpExchange,
)
from webprobe.scheduler import (
    Analyzer,
    CycleError,
    SchedulerConfig,
    SyncAnalyzer,
    run_audit,
    run_audit_sync,
)


def _make_check(dim: DimensionId, slug: str, status: CheckStatus = CheckStatus.pass_) -> CheckResult:
    return CheckResult(
        dimension=dim,
        check_id=f"{dim.value}.{slug}",
        title=slug,
        goal=f"goal {slug}",
        status=status,
        severity=CheckSeverity.info,
        mode=CheckMode.mechanical,
        weight=1.0,
        evidence=HttpExchange(method="GET", url="https://x"),
    )


def _mech_analyzer(name: str, dim: DimensionId, slugs: list[str]) -> SyncAnalyzer:
    def fn(store: ArtifactStore, cfg: dict) -> list[CheckResult]:
        # Slugs run with equal weight summing to 1.0
        results = []
        n = len(slugs)
        for s in slugs:
            r = _make_check(dim, s)
            r.weight = 1.0 / n
            results.append(r)
        return results
    return SyncAnalyzer(name=name, mode_class=CheckMode.mechanical, fn=fn)


# ---- basic execution ----


def test_runs_single_analyzer() -> None:
    store = ArtifactStore()
    analyzers = [_mech_analyzer("disc", DimensionId.discoverability, ["a", "b"])]
    result = run_audit_sync(store, analyzers)
    assert len(result.check_results) == 2
    assert result.analyzers_run == ["disc"]
    assert result.analyzers_skipped == []


def test_runs_multiple_analyzers_independent() -> None:
    store = ArtifactStore()
    analyzers = [
        _mech_analyzer("disc", DimensionId.discoverability, ["a"]),
        _mech_analyzer("bot", DimensionId.bot_access, ["x", "y"]),
    ]
    result = run_audit_sync(store, analyzers)
    dims = {r.dimension for r in result.check_results}
    assert dims == {DimensionId.discoverability, DimensionId.bot_access}
    assert set(result.analyzers_run) == {"disc", "bot"}


# ---- mode filtering (CA007) ----


def test_mechanical_only_skips_llm_analyzers() -> None:
    store = ArtifactStore()
    mech = _mech_analyzer("mech", DimensionId.discoverability, ["a"])
    llm = SyncAnalyzer(
        name="llm-only",
        mode_class=CheckMode.llm,
        fn=lambda s, c: [_make_check(DimensionId.public_facing_signals, "copy")],
    )
    result = run_audit_sync(store, [mech, llm], SchedulerConfig(mode="mechanical_only"))
    assert "mech" in result.analyzers_run
    assert "llm-only" not in result.analyzers_run
    assert ("llm-only", "mechanical_only_mode") in result.analyzers_skipped


def test_full_mode_runs_llm_analyzers() -> None:
    store = ArtifactStore()
    llm = SyncAnalyzer(
        name="llm-only",
        mode_class=CheckMode.llm,
        fn=lambda s, c: [_make_check(DimensionId.public_facing_signals, "copy")],
    )
    result = run_audit_sync(store, [llm], SchedulerConfig(mode="full"))
    assert "llm-only" in result.analyzers_run


def test_mechanical_only_keeps_hybrid_analyzers() -> None:
    """Hybrid analyzers run in mechanical_only — they self-skip their LLM portion."""
    store = ArtifactStore()
    hybrid = SyncAnalyzer(
        name="hyb",
        mode_class=CheckMode.hybrid,
        fn=lambda s, c: [_make_check(DimensionId.api_surface, "h")],
    )
    result = run_audit_sync(store, [hybrid], SchedulerConfig(mode="mechanical_only"))
    assert "hyb" in result.analyzers_run


def test_runtime_analyzers_run_in_both_modes() -> None:
    store = ArtifactStore()
    rt = SyncAnalyzer(
        name="rt",
        mode_class=CheckMode.runtime,
        fn=lambda s, c: [_make_check(DimensionId.agent_surface, "webmcp")],
    )
    for mode in ("mechanical_only", "full"):
        result = run_audit_sync(store, [rt], SchedulerConfig(mode=mode))  # type: ignore[arg-type]
        assert "rt" in result.analyzers_run, f"runtime should run in {mode}"


# ---- only / skip filters ----


def test_only_filter() -> None:
    store = ArtifactStore()
    a = _mech_analyzer("a", DimensionId.discoverability, ["x"])
    b = _mech_analyzer("b", DimensionId.bot_access, ["y"])
    result = run_audit_sync(store, [a, b], SchedulerConfig(only=("a",)))
    assert result.analyzers_run == ["a"]
    assert ("b", "not_in_only") in result.analyzers_skipped


def test_skip_filter() -> None:
    store = ArtifactStore()
    a = _mech_analyzer("a", DimensionId.discoverability, ["x"])
    b = _mech_analyzer("b", DimensionId.bot_access, ["y"])
    result = run_audit_sync(store, [a, b], SchedulerConfig(skip=("b",)))
    assert result.analyzers_run == ["a"]
    assert ("b", "in_skip_set") in result.analyzers_skipped


# ---- dependency ordering ----


def test_dep_order_prior_results_passed_through() -> None:
    """Analyzer B with depends_on_analyzers=('A',) sees A's results in prior_results."""
    store = ArtifactStore()
    a_called = {"count": 0}
    b_seen: list[CheckResult] = []

    def a_fn(s, c):
        a_called["count"] += 1
        return [_make_check(DimensionId.discoverability, "from_a")]

    @dataclass
    class B:
        name: str = "B"
        mode_class: CheckMode = CheckMode.mechanical
        depends_on_analyzers: tuple[str, ...] = ("A",)

        async def run(self, store, *, mode, prior_results, config=None):
            b_seen.extend(prior_results)
            return [_make_check(DimensionId.bot_access, "from_b")]

    a = SyncAnalyzer(name="A", mode_class=CheckMode.mechanical, fn=a_fn)
    b = B()
    result = run_audit_sync(store, [a, b])
    assert result.analyzers_run == ["A", "B"]  # A first, then B
    assert any(r.check_id == "discoverability.from_a" for r in b_seen)


def test_cycle_detection() -> None:
    @dataclass
    class A:
        name: str = "A"
        mode_class: CheckMode = CheckMode.mechanical
        depends_on_analyzers: tuple[str, ...] = ("B",)

        async def run(self, store, *, mode, prior_results, config=None):
            return []

    @dataclass
    class B:
        name: str = "B"
        mode_class: CheckMode = CheckMode.mechanical
        depends_on_analyzers: tuple[str, ...] = ("A",)

        async def run(self, store, *, mode, prior_results, config=None):
            return []

    with pytest.raises(CycleError):
        run_audit_sync(ArtifactStore(), [A(), B()])


# ---- error isolation (CO005) ----


def test_analyzer_crash_does_not_abort_run() -> None:
    """CO005: an analyzer crash is recorded as skipped; other analyzers still run."""
    store = ArtifactStore()

    def crash(s, c):
        raise RuntimeError("kaboom")

    crashing = SyncAnalyzer(name="boom", mode_class=CheckMode.mechanical, fn=crash)
    ok = _mech_analyzer("ok", DimensionId.discoverability, ["a"])

    result = run_audit_sync(store, [crashing, ok])
    assert "ok" in result.analyzers_run
    assert any(name == "boom" and "analyzer_error" in reason for name, reason in result.analyzers_skipped)


# ---- async path ----


def test_run_audit_async() -> None:
    async def go() -> int:
        store = ArtifactStore()
        analyzer = _mech_analyzer("a", DimensionId.discoverability, ["x"])
        result = await run_audit(store, [analyzer])
        return len(result.check_results)
    assert asyncio.run(go()) == 1
