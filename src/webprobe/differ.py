"""Cross-run diffing and trending."""

from __future__ import annotations

import json
from pathlib import Path

from webprobe.models import (
    AuthBoundaryViolation,
    BrokenLink,
    Edge,
    NodeDiff,
    Run,
    RunDiff,
    SCHEMA_VERSION,
)


def load_run(run_dir: Path) -> Run:
    """Load a Run from a run directory's report.json."""
    report_path = run_dir / "report.json"
    if not report_path.exists():
        raise FileNotFoundError(f"No report.json in {run_dir}")
    data = json.loads(report_path.read_text())
    return Run.model_validate(data)


def diff_runs(run_a: Run, run_b: Run) -> RunDiff:
    """Compare two runs and produce a diff."""
    if run_a.schema_version != run_b.schema_version:
        raise ValueError(
            f"Schema version mismatch: {run_a.schema_version} vs {run_b.schema_version}"
        )

    nodes_a = set(run_a.graph.nodes.keys())
    nodes_b = set(run_b.graph.nodes.keys())

    # Node set diffs
    nodes_added = sorted(nodes_b - nodes_a)
    nodes_removed = sorted(nodes_a - nodes_b)

    # Edge set diffs (by source+target)
    def edge_key(e: Edge) -> tuple[str, str]:
        return (e.source, e.target)

    edges_a = {edge_key(e): e for e in run_a.graph.edges}
    edges_b = {edge_key(e): e for e in run_b.graph.edges}
    edges_added = [edges_b[k] for k in sorted(set(edges_b) - set(edges_a))]
    edges_removed = [edges_a[k] for k in sorted(set(edges_a) - set(edges_b))]

    # Status changes for nodes in both runs
    status_changes: list[NodeDiff] = []
    for nid in nodes_a & nodes_b:
        node_a = run_a.graph.nodes[nid]
        node_b = run_b.graph.nodes[nid]
        # Compare first capture's HTTP status
        status_a = node_a.captures[0].http_status if node_a.captures else None
        status_b = node_b.captures[0].http_status if node_b.captures else None
        if status_a != status_b:
            status_changes.append(NodeDiff(
                url=nid,
                change="changed",
                details={"http_status": {"before": status_a, "after": status_b}},
            ))

    # Timing changes (> 20% delta)
    timing_changes: list[NodeDiff] = []
    for nid in nodes_a & nodes_b:
        node_a = run_a.graph.nodes[nid]
        node_b = run_b.graph.nodes[nid]
        if node_a.captures and node_b.captures:
            t_a = node_a.captures[0].timing
            t_b = node_b.captures[0].timing
            if t_a and t_b and t_a.duration_ms > 0:
                delta_pct = abs(t_b.duration_ms - t_a.duration_ms) / t_a.duration_ms
                if delta_pct > 0.20:
                    timing_changes.append(NodeDiff(
                        url=nid,
                        change="changed",
                        details={
                            "duration_ms": {
                                "before": t_a.duration_ms,
                                "after": t_b.duration_ms,
                                "delta_pct": round(delta_pct * 100, 1),
                            }
                        },
                    ))

    # Broken link diffs
    def bl_key(bl: BrokenLink) -> tuple[str, str]:
        return (bl.source, bl.target)

    bls_a = set()
    bls_b = set()
    bl_map_a: dict[tuple[str, str], BrokenLink] = {}
    bl_map_b: dict[tuple[str, str], BrokenLink] = {}
    if run_a.analysis:
        for bl in run_a.analysis.broken_links:
            k = bl_key(bl)
            bls_a.add(k)
            bl_map_a[k] = bl
    if run_b.analysis:
        for bl in run_b.analysis.broken_links:
            k = bl_key(bl)
            bls_b.add(k)
            bl_map_b[k] = bl

    new_broken = [bl_map_b[k] for k in sorted(bls_b - bls_a)]
    resolved_broken = [bl_map_a[k] for k in sorted(bls_a - bls_b)]

    # Auth violation diffs
    av_a = set()
    av_b = set()
    av_map_a: dict[str, AuthBoundaryViolation] = {}
    av_map_b: dict[str, AuthBoundaryViolation] = {}
    if run_a.analysis:
        for av in run_a.analysis.auth_violations:
            av_a.add(av.url)
            av_map_a[av.url] = av
    if run_b.analysis:
        for av in run_b.analysis.auth_violations:
            av_b.add(av.url)
            av_map_b[av.url] = av

    new_auth = [av_map_b[k] for k in sorted(av_b - av_a)]
    resolved_auth = [av_map_a[k] for k in sorted(av_a - av_b)]

    return RunDiff(
        run_a_id=run_a.run_id,
        run_b_id=run_b.run_id,
        nodes_added=nodes_added,
        nodes_removed=nodes_removed,
        edges_added=edges_added,
        edges_removed=edges_removed,
        status_changes=status_changes,
        timing_changes=timing_changes,
        new_broken_links=new_broken,
        resolved_broken_links=resolved_broken,
        new_auth_violations=new_auth,
        resolved_auth_violations=resolved_auth,
    )
