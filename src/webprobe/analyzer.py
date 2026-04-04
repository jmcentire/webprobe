"""Phase 3: Graph analysis -- metrics, broken links, auth violations, timing outliers, prime paths."""

from __future__ import annotations

import math
import time
from datetime import datetime, timezone

import networkx as nx

from webprobe.models import (
    AnalysisResult,
    AuthBoundaryViolation,
    AuthContext,
    BrokenLink,
    GraphMetrics,
    PhaseStatus,
    PrimePath,
    SiteGraph,
    TimingOutlier,
)


def _build_nx_graph(graph: SiteGraph) -> nx.DiGraph:
    """Convert SiteGraph to a networkx DiGraph."""
    G = nx.DiGraph()
    for node_id in graph.nodes:
        G.add_node(node_id)
    for edge in graph.edges:
        G.add_edge(edge.source, edge.target)
    return G


def _compute_graph_metrics(graph: SiteGraph, G: nx.DiGraph) -> GraphMetrics:
    """Compute structural metrics on the graph."""
    root = graph.root_url

    # Orphan nodes: in-degree 0 (excluding root)
    orphans = [n for n in G.nodes if G.in_degree(n) == 0 and n != root]

    # Dead ends: out-degree 0
    dead_ends = [n for n in G.nodes if G.out_degree(n) == 0]

    # Unreachable from root
    if root in G:
        reachable = nx.descendants(G, root) | {root}
        unreachable = [n for n in G.nodes if n not in reachable]
    else:
        unreachable = list(G.nodes)

    # Strongly connected components
    sccs = list(nx.strongly_connected_components(G))

    # Cyclomatic complexity: E - N + 2P (P = number of connected components)
    n_nodes = G.number_of_nodes()
    n_edges = G.number_of_edges()
    n_components = nx.number_weakly_connected_components(G)
    cyclomatic = n_edges - n_nodes + 2 * n_components

    # Max depth from root
    max_depth = 0
    for node in graph.nodes.values():
        if node.depth > max_depth:
            max_depth = node.depth

    # Edge coverage: fraction of edges verified during capture
    verified = sum(1 for e in graph.edges if e.verified)
    total = len(graph.edges)
    edge_coverage = verified / total if total > 0 else 0.0

    return GraphMetrics(
        total_nodes=n_nodes,
        total_edges=n_edges,
        orphan_nodes=orphans,
        dead_end_nodes=dead_ends,
        unreachable_nodes=unreachable,
        strongly_connected_components=len(sccs),
        cyclomatic_complexity=cyclomatic,
        max_depth=max_depth,
        edge_coverage=edge_coverage,
    )


def _find_broken_links(graph: SiteGraph) -> list[BrokenLink]:
    """Find edges whose target has a failing HTTP status or no successful capture.

    External links (targets not in graph) are skipped -- they're out of scope,
    not broken. Only same-origin links that fail are reported.
    """
    broken: list[BrokenLink] = []
    for edge in graph.edges:
        target_node = graph.nodes.get(edge.target)
        if target_node is None:
            # External or excluded link -- not a "broken" link, just out of scope
            continue
        # Check if any capture has a success status or rendered content
        has_success = False
        worst_status: int | None = None
        for capture in target_node.captures:
            if capture.http_status is not None:
                if 200 <= capture.http_status < 400:
                    has_success = True
                    break
                worst_status = capture.http_status
            elif capture.page_text and capture.page_text.strip():
                # Page rendered content despite missing http_status (e.g. timeout)
                has_success = True
                break
        if not has_success and target_node.captures:
            broken.append(BrokenLink(
                source=edge.source,
                target=edge.target,
                status_code=worst_status,
                error=f"HTTP {worst_status}" if worst_status else "No successful response",
            ))
    return broken


def _find_auth_violations(graph: SiteGraph) -> list[AuthBoundaryViolation]:
    """Find pages that should require auth but are accessible anonymously."""
    violations: list[AuthBoundaryViolation] = []
    for node in graph.nodes.values():
        if not node.requires_auth:
            continue
        # Check if any anonymous capture returned HTTP 200
        for capture in node.captures:
            if (
                capture.auth_context == AuthContext.anonymous
                and capture.http_status is not None
                and 200 <= capture.http_status < 300
            ):
                violations.append(AuthBoundaryViolation(
                    url=node.id,
                    expected_auth=True,
                    actual_accessible_anonymous=True,
                    evidence=f"Anonymous access returned HTTP {capture.http_status}",
                ))
                break
    return violations


def _find_timing_outliers(graph: SiteGraph) -> list[TimingOutlier]:
    """Find nodes with timing significantly above the mean (z-score > 2)."""
    metrics_by_name: dict[str, list[tuple[str, AuthContext, float]]] = {}

    for node in graph.nodes.values():
        for capture in node.captures:
            if capture.timing and capture.timing.duration_ms > 0:
                metrics_by_name.setdefault("duration_ms", []).append(
                    (node.id, capture.auth_context, capture.timing.duration_ms)
                )
            if capture.timing and capture.timing.ttfb_ms is not None and capture.timing.ttfb_ms > 0:
                metrics_by_name.setdefault("ttfb_ms", []).append(
                    (node.id, capture.auth_context, capture.timing.ttfb_ms)
                )
            if capture.dom_content_loaded_ms is not None and capture.dom_content_loaded_ms > 0:
                metrics_by_name.setdefault("dom_content_loaded_ms", []).append(
                    (node.id, capture.auth_context, capture.dom_content_loaded_ms)
                )
            if capture.load_event_ms is not None and capture.load_event_ms > 0:
                metrics_by_name.setdefault("load_event_ms", []).append(
                    (node.id, capture.auth_context, capture.load_event_ms)
                )

    outliers: list[TimingOutlier] = []
    for metric_name, values in metrics_by_name.items():
        if len(values) < 3:
            continue
        nums = [v[2] for v in values]
        mean = sum(nums) / len(nums)
        variance = sum((x - mean) ** 2 for x in nums) / len(nums)
        stddev = math.sqrt(variance)
        if stddev == 0:
            continue
        for url, auth_ctx, val in values:
            z = (val - mean) / stddev
            if abs(z) > 2.0:
                outliers.append(TimingOutlier(
                    url=url,
                    auth_context=auth_ctx,
                    metric=metric_name,
                    value_ms=val,
                    mean_ms=mean,
                    stddev_ms=stddev,
                    z_score=z,
                ))
    return outliers


def _enumerate_prime_paths(G: nx.DiGraph, max_loop: int = 2, max_paths: int = 1000, max_seconds: float = 30.0) -> list[PrimePath]:
    """Enumerate prime paths via incremental extension.

    A prime path is a simple path that cannot be extended (the first or last node
    would create a repeat). We build paths incrementally: start with single-edge
    paths, extend by one node at a time, and keep only maximal (non-extendable) ones.

    Bounded by max_paths and max_seconds to stay tractable on dense graphs.
    """
    if G.number_of_nodes() == 0:
        return []

    deadline = time.monotonic() + max_seconds

    # Start with all edges as seed paths of length 2
    active: list[list[str]] = []
    for u, v in G.edges:
        active.append([u, v])

    prime: list[PrimePath] = []
    seen: set[tuple[str, ...]] = set()

    while active:
        if time.monotonic() > deadline or len(prime) >= max_paths:
            break

        next_active: list[list[str]] = []
        for path in active:
            if time.monotonic() > deadline or len(prime) >= max_paths:
                break

            extended = False
            last = path[-1]
            for succ in G.successors(last):
                if succ not in path:  # Keep it simple (no repeated nodes)
                    next_active.append(path + [succ])
                    extended = True

            if not extended:
                # Can't extend forward -- this is a candidate prime path
                path_tuple = tuple(path)
                if path_tuple not in seen:
                    seen.add(path_tuple)
                    prime.append(PrimePath(
                        path=list(path_tuple),
                        length=len(path_tuple),
                        contains_loop=(path[0] == path[-1]),
                    ))

        active = next_active

    return prime


def analyze(graph: SiteGraph, config: "WebprobeConfig | None" = None) -> tuple[AnalysisResult, PhaseStatus]:
    """Phase 3: Analyze the site graph."""
    phase = PhaseStatus(
        phase="analyze",
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    start = time.monotonic()

    from webprobe.security import scan_graph

    G = _build_nx_graph(graph)
    metrics = _compute_graph_metrics(graph, G)
    broken = _find_broken_links(graph)
    auth_violations = _find_auth_violations(graph)
    timing_outliers = _find_timing_outliers(graph)
    prime_paths = _enumerate_prime_paths(G)
    security_findings = scan_graph(graph, config)

    result = AnalysisResult(
        graph_metrics=metrics,
        broken_links=broken,
        auth_violations=auth_violations,
        timing_outliers=timing_outliers,
        prime_paths=prime_paths,
        security_findings=security_findings,
    )

    # Compliance annotation
    compliance_summary = None
    if config and config.compliance.enabled:
        try:
            from webprobe.compliance import annotate_findings, load_mappings
            mappings = load_mappings(custom_path=config.compliance.custom_mappings_path)
            enabled = [s for s in config.compliance.standards if s not in config.compliance.skip_standards]
            compliance_summary = annotate_findings(security_findings, mappings, enabled)
        except Exception:
            import logging
            logging.getLogger(__name__).warning("Compliance annotation failed", exc_info=True)
    result.compliance = compliance_summary

    duration = (time.monotonic() - start) * 1000
    phase.status = "completed"
    phase.completed_at = datetime.now(timezone.utc).isoformat()
    phase.duration_ms = duration

    return result, phase
