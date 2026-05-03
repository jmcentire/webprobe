"""Phase 3.5 audit scheduler (CA006, CA007, CA013, CA014).

Runs registered dimension analyzers against a populated ArtifactStore and
returns the aggregated ``list[CheckResult]``. Mode-aware: in
``mechanical_only`` runs the scheduler short-circuits LLM analyzers and the
LLM portion of hybrid analyzers; mechanical/runtime checks run in both modes.

Cross-analyzer parallelism uses an asyncio semaphore. Cross-check
dependencies inside an LLM analyzer are the analyzer's responsibility (the
analyzer is given the previously-produced CheckResults as ``prior_results``).

The scheduler does not implement a global check-level DAG (CA013). Most
checks have no dependencies; the few that do (e.g. CTA-alignment depending
on value-prop extraction) live inside a single analyzer and are sequenced
there. Cross-analyzer dependencies are an explicit declared edge between
analyzers.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable, Literal, Protocol

from webprobe.artifact_store import ArtifactStore
from webprobe.models import CheckMode, CheckResult, CheckStatus

logger = logging.getLogger(__name__)


SchedulerMode = Literal["mechanical_only", "full"]


class Analyzer(Protocol):
    """Protocol every dimension analyzer must implement.

    Attributes:
      name: dimension slug (e.g. "discoverability")
      mode_class: which CheckMode this analyzer's checks predominantly use.
        The scheduler uses this to decide whether to run the analyzer at all
        in mechanical_only mode. Hybrid analyzers run in both modes (their
        internal LLM portions self-skip).
      depends_on_analyzers: optional list of analyzer names this one needs
        to run AFTER (their CheckResults are passed in as prior_results).
    """

    name: str
    mode_class: CheckMode
    depends_on_analyzers: tuple[str, ...]

    async def run(
        self,
        store: ArtifactStore,
        *,
        mode: SchedulerMode,
        prior_results: list[CheckResult],
        config: dict | None = None,
    ) -> list[CheckResult]:
        ...


@dataclass
class SchedulerConfig:
    """Runtime knobs for the scheduler."""

    mode: SchedulerMode = "full"
    concurrency: int = 8
    analyzer_config: dict[str, dict] = field(default_factory=dict)
    # Names of analyzers to skip entirely (e.g. via CLI --dimension flag).
    only: tuple[str, ...] | None = None
    skip: tuple[str, ...] = ()


@dataclass
class SchedulerResult:
    """Outcome of a scheduler run."""

    check_results: list[CheckResult]
    elapsed_ms: float
    analyzers_run: list[str]
    analyzers_skipped: list[tuple[str, str]]  # (name, reason)


class CycleError(ValueError):
    """Raised when analyzer dependency declarations form a cycle."""


def _topological_order(analyzers: Iterable[Analyzer]) -> list[Analyzer]:
    """Topologically sort analyzers by depends_on_analyzers; raise on cycles."""
    by_name = {a.name: a for a in analyzers}
    indeg: dict[str, int] = {n: 0 for n in by_name}
    edges: dict[str, list[str]] = {n: [] for n in by_name}
    for a in by_name.values():
        for dep in a.depends_on_analyzers:
            if dep not in by_name:
                # Unknown dep is non-fatal — treat as no edge. The dependent
                # analyzer will see prior_results=[] for that dep.
                continue
            edges[dep].append(a.name)
            indeg[a.name] += 1

    queue: list[str] = sorted(n for n, d in indeg.items() if d == 0)
    out: list[Analyzer] = []
    while queue:
        n = queue.pop(0)
        out.append(by_name[n])
        for nxt in edges[n]:
            indeg[nxt] -= 1
            if indeg[nxt] == 0:
                queue.append(nxt)
    if len(out) != len(by_name):
        unresolved = [n for n, d in indeg.items() if d > 0]
        raise CycleError(f"Analyzer dependency cycle involving: {unresolved}")
    return out


def _should_skip_for_mode(
    analyzer: Analyzer, mode: SchedulerMode
) -> tuple[bool, str]:
    """Decide whether to skip this analyzer in the given mode (CA007).

    Returns (skip, reason). LLM-class analyzers are skipped in mechanical_only
    mode; mechanical/runtime/hybrid run in both modes (the hybrid analyzer
    self-skips its LLM portion).
    """
    if mode == "mechanical_only" and analyzer.mode_class == CheckMode.llm:
        return True, "mechanical_only_mode"
    return False, ""


async def run_audit(
    store: ArtifactStore,
    analyzers: list[Analyzer],
    config: SchedulerConfig | None = None,
) -> SchedulerResult:
    """Run the audit pipeline. Returns aggregated CheckResults + timing.

    Order: analyzers are sorted topologically by `depends_on_analyzers`; each
    analyzer receives the CheckResults produced so far via `prior_results`.
    Independent analyzers run in parallel up to `concurrency`.
    """
    cfg = config or SchedulerConfig()
    started = time.perf_counter()

    only = set(cfg.only) if cfg.only else None
    skip = set(cfg.skip)

    ordered = _topological_order(analyzers)

    # Group into "waves" by topological depth: each wave can run in parallel.
    # An analyzer is in wave N if max depth of its deps is N-1.
    depth: dict[str, int] = {}
    by_name = {a.name: a for a in ordered}
    for a in ordered:
        d = 0
        for dep in a.depends_on_analyzers:
            if dep in by_name:
                d = max(d, depth[dep] + 1)
        depth[a.name] = d
    waves: list[list[Analyzer]] = []
    for a in ordered:
        idx = depth[a.name]
        while len(waves) <= idx:
            waves.append([])
        waves[idx].append(a)

    aggregated: list[CheckResult] = []
    skipped: list[tuple[str, str]] = []
    ran: list[str] = []

    semaphore = asyncio.Semaphore(cfg.concurrency)

    async def _run_one(analyzer: Analyzer) -> list[CheckResult]:
        if only is not None and analyzer.name not in only:
            skipped.append((analyzer.name, "not_in_only"))
            return []
        if analyzer.name in skip:
            skipped.append((analyzer.name, "in_skip_set"))
            return []
        skip_mode, reason = _should_skip_for_mode(analyzer, cfg.mode)
        if skip_mode:
            skipped.append((analyzer.name, reason))
            return []
        async with semaphore:
            t0 = time.perf_counter()
            try:
                results = await analyzer.run(
                    store,
                    mode=cfg.mode,
                    prior_results=list(aggregated),
                    config=cfg.analyzer_config.get(analyzer.name, {}),
                )
            except Exception as e:
                logger.exception(
                    "scheduler.analyzer_error",
                    extra={"analyzer": analyzer.name, "error": repr(e)},
                )
                # Per CO005, an analyzer crash must not abort the run.
                skipped.append((analyzer.name, f"analyzer_error:{type(e).__name__}"))
                return []
            elapsed = (time.perf_counter() - t0) * 1000.0
            logger.info(
                "scheduler.analyzer_complete",
                extra={
                    "analyzer": analyzer.name,
                    "checks": len(results),
                    "elapsed_ms": elapsed,
                },
            )
            ran.append(analyzer.name)
            return results

    for wave in waves:
        wave_results = await asyncio.gather(*(_run_one(a) for a in wave))
        for results in wave_results:
            aggregated.extend(results)

    return SchedulerResult(
        check_results=aggregated,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
        analyzers_run=ran,
        analyzers_skipped=skipped,
    )


def run_audit_sync(
    store: ArtifactStore,
    analyzers: list[Analyzer],
    config: SchedulerConfig | None = None,
) -> SchedulerResult:
    """Synchronous wrapper for run_audit. Convenience for non-async callers."""
    return asyncio.run(run_audit(store, analyzers, config))


# ---- Helper for test/Block-3 use: a thin sync analyzer adapter ----


@dataclass
class SyncAnalyzer:
    """Adapter that wraps a synchronous run() into the Analyzer protocol.

    Useful for purely-mechanical analyzers (most of them) that don't need
    asyncio. The scheduler awaits the wrapped function in a thread pool only
    if it actually blocks; in practice mechanical analyzers are fast and
    just run in the event loop.
    """

    name: str
    mode_class: CheckMode
    fn: Callable[[ArtifactStore, dict], list[CheckResult]]
    depends_on_analyzers: tuple[str, ...] = ()

    async def run(
        self,
        store: ArtifactStore,
        *,
        mode: SchedulerMode,
        prior_results: list[CheckResult],
        config: dict | None = None,
    ) -> list[CheckResult]:
        # Run the sync function inline. Mechanical checks are fast; if a
        # specific analyzer ever blocks long enough to matter, it should be
        # written as a true async Analyzer.
        return self.fn(store, config or {})


__all__ = [
    "Analyzer",
    "CycleError",
    "SchedulerConfig",
    "SchedulerMode",
    "SchedulerResult",
    "SyncAnalyzer",
    "run_audit",
    "run_audit_sync",
]
