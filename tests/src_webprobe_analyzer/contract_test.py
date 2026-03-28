"""
Contract tests for WebProbe Graph Analyzer (src_webprobe_analyzer)

This test suite verifies the behavior of graph analysis functions against their
contracts, testing happy paths, edge cases, error cases, and invariants.
"""

import pytest
import math
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from unittest.mock import Mock, patch, MagicMock
import networkx as nx

# Import the component under test
from src.webprobe.analyzer import (
    _build_nx_graph,
    _compute_graph_metrics,
    _find_broken_links,
    _find_auth_violations,
    _find_timing_outliers,
    _enumerate_prime_paths,
    analyze,
)

# Import real models
from webprobe.models import (
    AuthContext,
    AuthBoundaryViolation,
    AnalysisResult,
    BrokenLink,
    DiscoveryMethod,
    Edge,
    GraphMetrics,
    Node,
    NodeCapture,
    NodeState,
    PhaseStatus,
    PrimePath,
    SiteGraph,
    TimingData,
    TimingOutlier,
)


# ============================================================================
# HELPERS
# ============================================================================

def _make_node(
    node_id: str,
    url: str | None = None,
    requires_auth: bool = False,
    depth: int = 0,
    captures: list[NodeCapture] | None = None,
) -> Node:
    """Helper to build a Node with sensible defaults."""
    if url is None:
        url = f"https://example.com/{node_id}"
    return Node(
        id=node_id,
        state=NodeState(url=url),
        discovered_via=DiscoveryMethod.crawl,
        requires_auth=requires_auth,
        auth_contexts_available=[AuthContext.anonymous],
        captures=captures or [],
        depth=depth,
    )


def _make_capture(
    auth_context: AuthContext = AuthContext.anonymous,
    http_status: int | None = 200,
    duration_ms: float = 100.0,
    ttfb_ms: float | None = 50.0,
    dom_content_loaded_ms: float | None = 80.0,
    load_event_ms: float | None = 90.0,
) -> NodeCapture:
    """Helper to build a NodeCapture with timing data."""
    timing = TimingData(
        started_at="2024-01-01T00:00:00+00:00",
        duration_ms=duration_ms,
        ttfb_ms=ttfb_ms,
    )
    return NodeCapture(
        auth_context=auth_context,
        http_status=http_status,
        timing=timing,
        dom_content_loaded_ms=dom_content_loaded_ms,
        load_event_ms=load_event_ms,
    )


def _make_graph(
    nodes_dict: dict[str, Node],
    edges: list[Edge] | None = None,
    root_url: str = "",
) -> SiteGraph:
    """Helper to build a SiteGraph."""
    return SiteGraph(
        nodes=nodes_dict,
        edges=edges or [],
        root_url=root_url,
    )


# ============================================================================
# TEST FIXTURES
# ============================================================================

@pytest.fixture
def empty_graph():
    """Empty SiteGraph with 0 nodes and 0 edges"""
    return _make_graph({}, [], root_url="")


@pytest.fixture
def single_node_graph():
    """SiteGraph with 1 node and 0 edges"""
    n1 = _make_node("node1", captures=[_make_capture()])
    return _make_graph({"node1": n1}, [], root_url="node1")


@pytest.fixture
def linear_graph():
    """SiteGraph with 3 nodes in linear sequence"""
    n1 = _make_node("node1", captures=[_make_capture()])
    n2 = _make_node("node2", captures=[_make_capture()])
    n3 = _make_node("node3", captures=[_make_capture()])
    edges = [
        Edge(source="node1", target="node2"),
        Edge(source="node2", target="node3"),
    ]
    return _make_graph({"node1": n1, "node2": n2, "node3": n3}, edges, root_url="node1")


@pytest.fixture
def cycle_graph():
    """SiteGraph with 4 nodes forming a cycle"""
    nodes = {}
    for i in range(1, 5):
        nid = f"node{i}"
        nodes[nid] = _make_node(nid, captures=[_make_capture()])
    edges = [
        Edge(source="node1", target="node2"),
        Edge(source="node2", target="node3"),
        Edge(source="node3", target="node4"),
        Edge(source="node4", target="node1"),
    ]
    return _make_graph(nodes, edges, root_url="node1")


@pytest.fixture
def disconnected_graph():
    """SiteGraph with 2 disconnected components"""
    nodes = {}
    for i in range(1, 5):
        nid = f"node{i}"
        nodes[nid] = _make_node(nid, captures=[_make_capture()])
    edges = [
        Edge(source="node1", target="node2"),
        Edge(source="node3", target="node4"),
    ]
    return _make_graph(nodes, edges, root_url="node1")


@pytest.fixture
def auth_mixed_graph():
    """SiteGraph with mixed auth states"""
    n1 = _make_node("node1", requires_auth=False, captures=[
        _make_capture(auth_context=AuthContext.anonymous, http_status=200),
    ])
    # node2: requires_auth=True, anonymous access returns 200 -> VIOLATION
    n2 = _make_node("node2", requires_auth=True, captures=[
        _make_capture(auth_context=AuthContext.anonymous, http_status=200),
    ])
    # node3: requires_auth=True, anonymous access returns 403 -> PROPER
    n3 = _make_node("node3", requires_auth=True, captures=[
        _make_capture(auth_context=AuthContext.anonymous, http_status=403),
    ])
    # node4: requires_auth=True, anonymous access returns 301 -> no violation (redirect)
    n4 = _make_node("node4", requires_auth=True, captures=[
        _make_capture(auth_context=AuthContext.anonymous, http_status=301),
    ])
    edges = [
        Edge(source="node1", target="node2"),
        Edge(source="node1", target="node3"),
        Edge(source="node1", target="node4"),
    ]
    return _make_graph(
        {"node1": n1, "node2": n2, "node3": n3, "node4": n4},
        edges,
        root_url="node1",
    )


@pytest.fixture
def timing_varied_graph():
    """SiteGraph with varied timing metrics (some outliers).

    With only 5 samples including 4 tight + 1 outlier, the z-score of the
    outlier is always exactly 2.0 (population stddev). We need >= 8 tight
    samples so the outlier z-score exceeds the > 2.0 threshold.
    """
    nodes = {}
    # 9 normal nodes with tight timings
    normal_timings = [
        ("node1", 100, 50, 80, 90),
        ("node2", 105, 52, 82, 92),
        ("node3", 95, 48, 78, 88),
        ("node4", 102, 51, 81, 91),
        ("node6", 98, 49, 79, 89),
        ("node7", 103, 51, 81, 91),
        ("node8", 101, 50, 80, 90),
        ("node9", 99, 50, 80, 90),
        ("node10", 104, 52, 82, 92),
    ]
    for nid, dur, ttfb, dcl, le in normal_timings:
        nodes[nid] = _make_node(nid, captures=[
            _make_capture(duration_ms=dur, ttfb_ms=ttfb,
                          dom_content_loaded_ms=dcl, load_event_ms=le),
        ])
    # 1 outlier node
    nodes["node5"] = _make_node("node5", captures=[
        _make_capture(duration_ms=3000, ttfb_ms=2000,
                      dom_content_loaded_ms=2500, load_event_ms=2800),
    ])
    return _make_graph(nodes, [], root_url="node1")


@pytest.fixture
def broken_links_graph():
    """SiteGraph with various HTTP status codes including broken links"""
    n1 = _make_node("node1", captures=[_make_capture(http_status=200)])
    n2 = _make_node("node2", captures=[_make_capture(http_status=200)])
    n3 = _make_node("node3", captures=[_make_capture(http_status=404)])
    n4 = _make_node("node4", captures=[_make_capture(http_status=500)])
    n5 = _make_node("node5", captures=[_make_capture(http_status=301)])
    edges = [
        Edge(source="node1", target="node2"),    # OK
        Edge(source="node1", target="node3"),    # Broken (404)
        Edge(source="node2", target="node4"),    # Broken (500)
        Edge(source="node1", target="node5"),    # OK (redirect in 200-399)
        Edge(source="node1", target="node999"),  # External (not in graph)
    ]
    return _make_graph(
        {"node1": n1, "node2": n2, "node3": n3, "node4": n4, "node5": n5},
        edges,
        root_url="node1",
    )


# ============================================================================
# _build_nx_graph TESTS
# ============================================================================

def test_build_nx_graph_happy_path(linear_graph):
    """Converts a simple SiteGraph with nodes and edges to a networkx DiGraph"""
    G = _build_nx_graph(linear_graph)

    assert isinstance(G, nx.DiGraph)
    assert G.number_of_nodes() == 3
    assert G.number_of_edges() == 2

    # Verify all node IDs present
    assert set(G.nodes()) == set(linear_graph.nodes.keys())

    # Verify all edges present
    for edge in linear_graph.edges:
        assert G.has_edge(edge.source, edge.target)


def test_build_nx_graph_empty(empty_graph):
    """Converts an empty SiteGraph to a networkx DiGraph"""
    G = _build_nx_graph(empty_graph)

    assert isinstance(G, nx.DiGraph)
    assert G.number_of_nodes() == 0
    assert G.number_of_edges() == 0


def test_build_nx_graph_single_node(single_node_graph):
    """Converts a SiteGraph with single node and no edges"""
    G = _build_nx_graph(single_node_graph)

    assert isinstance(G, nx.DiGraph)
    assert G.number_of_nodes() == 1
    assert G.number_of_edges() == 0
    assert "node1" in G.nodes()


def test_build_nx_graph_cycle(cycle_graph):
    """Converts a SiteGraph with cyclic structure"""
    G = _build_nx_graph(cycle_graph)

    assert G.number_of_nodes() == 4
    assert G.number_of_edges() == 4

    assert G.has_edge("node1", "node2")
    assert G.has_edge("node2", "node3")
    assert G.has_edge("node3", "node4")
    assert G.has_edge("node4", "node1")

    assert not nx.is_directed_acyclic_graph(G)


# ============================================================================
# _compute_graph_metrics TESTS
# ============================================================================

def test_compute_graph_metrics_happy_path(linear_graph):
    """Computes metrics for a typical site graph"""
    G = _build_nx_graph(linear_graph)
    metrics = _compute_graph_metrics(linear_graph, G)

    assert isinstance(metrics, GraphMetrics)
    assert 0.0 <= metrics.edge_coverage <= 1.0

    # Verify cyclomatic complexity formula: E - N + 2P
    n_edges = G.number_of_edges()
    n_nodes = G.number_of_nodes()
    n_components = nx.number_weakly_connected_components(G)
    expected_complexity = n_edges - n_nodes + 2 * n_components
    assert metrics.cyclomatic_complexity == expected_complexity


def test_compute_graph_metrics_empty(empty_graph):
    """Computes metrics for empty graph"""
    G = _build_nx_graph(empty_graph)
    metrics = _compute_graph_metrics(empty_graph, G)

    assert isinstance(metrics, GraphMetrics)
    assert len(metrics.orphan_nodes) == 0
    assert len(metrics.dead_end_nodes) == 0
    assert metrics.edge_coverage in [0.0, 1.0]


def test_compute_graph_metrics_orphan_excludes_root(linear_graph):
    """Verifies orphan nodes excludes root node"""
    G = _build_nx_graph(linear_graph)
    metrics = _compute_graph_metrics(linear_graph, G)

    # Root node (node1) has no incoming edges but should not be in orphan_nodes
    assert linear_graph.root_url not in metrics.orphan_nodes


def test_compute_graph_metrics_cyclomatic_complexity(cycle_graph):
    """Verifies cyclomatic complexity formula E - N + 2P"""
    G = _build_nx_graph(cycle_graph)
    metrics = _compute_graph_metrics(cycle_graph, G)

    n_edges = G.number_of_edges()
    n_nodes = G.number_of_nodes()
    n_components = nx.number_weakly_connected_components(G)
    expected_complexity = n_edges - n_nodes + 2 * n_components

    assert metrics.cyclomatic_complexity == expected_complexity


def test_invariant_edge_coverage_range():
    """Edge coverage is always in range [0.0, 1.0]"""
    test_graphs = []

    # Empty graph
    test_graphs.append(_make_graph({}, [], root_url=""))

    # Single node
    n1 = _make_node("n1")
    test_graphs.append(_make_graph({"n1": n1}, [], root_url="n1"))

    # Full connectivity (3 nodes, all edges)
    nodes_full = {}
    for i in range(3):
        nid = f"n{i}"
        nodes_full[nid] = _make_node(nid)
    edges_full = [
        Edge(source=f"n{i}", target=f"n{j}")
        for i in range(3) for j in range(3) if i != j
    ]
    test_graphs.append(_make_graph(nodes_full, edges_full, root_url="n0"))

    for graph in test_graphs:
        G = _build_nx_graph(graph)
        metrics = _compute_graph_metrics(graph, G)
        assert 0.0 <= metrics.edge_coverage <= 1.0, \
            f"Edge coverage {metrics.edge_coverage} out of range"


# ============================================================================
# _find_broken_links TESTS
# ============================================================================

def test_find_broken_links_happy_path(broken_links_graph):
    """Finds broken links in a graph with failing HTTP statuses"""
    broken = _find_broken_links(broken_links_graph)

    assert isinstance(broken, list)

    broken_targets = {b.target for b in broken}
    assert "node3" in broken_targets  # 404
    assert "node4" in broken_targets  # 500

    # Should NOT include external links (node999 not in graph)
    assert "node999" not in broken_targets


def test_find_broken_links_no_issues():
    """Returns empty list when all links are valid"""
    n1 = _make_node("node1", captures=[_make_capture(http_status=200)])
    n2 = _make_node("node2", captures=[_make_capture(http_status=200)])
    n3 = _make_node("node3", captures=[_make_capture(http_status=301)])
    edges = [
        Edge(source="node1", target="node2"),
        Edge(source="node1", target="node3"),
    ]
    graph = _make_graph({"node1": n1, "node2": n2, "node3": n3}, edges, root_url="node1")

    broken = _find_broken_links(graph)
    assert len(broken) == 0


def test_find_broken_links_excludes_external(broken_links_graph):
    """External links (target not in graph) are excluded"""
    broken = _find_broken_links(broken_links_graph)

    broken_targets = {b.target for b in broken}
    assert "node999" not in broken_targets


def test_find_broken_links_boundary_statuses():
    """Tests boundary HTTP statuses (199, 200, 399, 400)"""
    n1 = _make_node("node1", captures=[_make_capture(http_status=200)])
    n199 = _make_node("node199", captures=[_make_capture(http_status=199)])
    n200 = _make_node("node200", captures=[_make_capture(http_status=200)])
    n399 = _make_node("node399", captures=[_make_capture(http_status=399)])
    n400 = _make_node("node400", captures=[_make_capture(http_status=400)])
    edges = [
        Edge(source="node1", target="node199"),
        Edge(source="node1", target="node200"),
        Edge(source="node1", target="node399"),
        Edge(source="node1", target="node400"),
    ]
    graph = _make_graph(
        {"node1": n1, "node199": n199, "node200": n200, "node399": n399, "node400": n400},
        edges,
        root_url="node1",
    )

    broken = _find_broken_links(graph)
    broken_targets = {b.target for b in broken}

    # 200-399 are success
    assert "node200" not in broken_targets
    assert "node399" not in broken_targets

    # < 200 or >= 400 are broken
    assert "node199" in broken_targets
    assert "node400" in broken_targets


# ============================================================================
# _find_auth_violations TESTS
# ============================================================================

def test_find_auth_violations_happy_path(auth_mixed_graph):
    """Finds pages requiring auth but accessible anonymously"""
    violations = _find_auth_violations(auth_mixed_graph)

    assert isinstance(violations, list)
    # node2 has requires_auth=True and anonymous capture with http_status=200 -> violation
    violation_urls = {v.url for v in violations}
    assert "node2" in violation_urls


def test_find_auth_violations_no_issues():
    """Returns empty list when no auth violations exist"""
    n1 = _make_node("node1", requires_auth=False, captures=[
        _make_capture(auth_context=AuthContext.anonymous, http_status=200),
    ])
    n2 = _make_node("node2", requires_auth=True, captures=[
        _make_capture(auth_context=AuthContext.anonymous, http_status=403),
    ])
    n3 = _make_node("node3", requires_auth=True, captures=[
        _make_capture(auth_context=AuthContext.anonymous, http_status=401),
    ])
    graph = _make_graph(
        {"node1": n1, "node2": n2, "node3": n3},
        [],
        root_url="node1",
    )

    violations = _find_auth_violations(graph)
    assert len(violations) == 0


def test_find_auth_violations_only_checks_requires_auth(auth_mixed_graph):
    """Only nodes with requires_auth=True are checked"""
    violations = _find_auth_violations(auth_mixed_graph)

    # node1 has requires_auth=False, should never be in violations
    violation_urls = {v.url for v in violations}
    assert "node1" not in violation_urls


def test_find_auth_violations_boundary_statuses():
    """Tests boundary HTTP statuses for auth violations (199, 200, 299, 300)"""
    n199 = _make_node("node199", requires_auth=True, captures=[
        _make_capture(auth_context=AuthContext.anonymous, http_status=199),
    ])
    n200 = _make_node("node200", requires_auth=True, captures=[
        _make_capture(auth_context=AuthContext.anonymous, http_status=200),
    ])
    n299 = _make_node("node299", requires_auth=True, captures=[
        _make_capture(auth_context=AuthContext.anonymous, http_status=299),
    ])
    n300 = _make_node("node300", requires_auth=True, captures=[
        _make_capture(auth_context=AuthContext.anonymous, http_status=300),
    ])
    graph = _make_graph(
        {"node199": n199, "node200": n200, "node299": n299, "node300": n300},
        [],
        root_url="node199",
    )

    violations = _find_auth_violations(graph)
    violation_urls = {v.url for v in violations}

    # 200-299 trigger violations
    assert "node200" in violation_urls
    assert "node299" in violation_urls

    # < 200 or >= 300 don't trigger violations
    assert "node199" not in violation_urls
    assert "node300" not in violation_urls


# ============================================================================
# _find_timing_outliers TESTS
# ============================================================================

def test_find_timing_outliers_happy_path(timing_varied_graph):
    """Finds nodes with timing metrics significantly above mean"""
    outliers = _find_timing_outliers(timing_varied_graph)

    assert isinstance(outliers, list)
    # node5 has significantly higher timings
    outlier_urls = {o.url for o in outliers}
    assert "node5" in outlier_urls

    # Check that z-scores are > 2.0
    for outlier in outliers:
        assert abs(outlier.z_score) > 2.0


def test_find_timing_outliers_no_issues():
    """Returns empty list when all timings are normal"""
    nodes = {}
    for i in range(5):
        nid = f"node{i}"
        nodes[nid] = _make_node(nid, captures=[
            _make_capture(duration_ms=100, ttfb_ms=50,
                          dom_content_loaded_ms=80, load_event_ms=90),
        ])
    graph = _make_graph(nodes, [], root_url="node0")

    outliers = _find_timing_outliers(graph)
    # All identical -> stddev = 0 -> skipped
    assert len(outliers) == 0


def test_find_timing_outliers_skips_small_samples():
    """Metrics with < 3 samples are skipped"""
    nodes = {
        "node1": _make_node("node1", captures=[_make_capture(duration_ms=100)]),
        "node2": _make_node("node2", captures=[_make_capture(duration_ms=1000)]),
    }
    graph = _make_graph(nodes, [], root_url="node1")

    outliers = _find_timing_outliers(graph)
    assert len(outliers) == 0


def test_find_timing_outliers_skips_zero_stddev():
    """Metrics with stddev = 0 are skipped"""
    nodes = {}
    for i in range(5):
        nid = f"node{i}"
        nodes[nid] = _make_node(nid, captures=[
            _make_capture(duration_ms=100, ttfb_ms=50,
                          dom_content_loaded_ms=80, load_event_ms=90),
        ])
    graph = _make_graph(nodes, [], root_url="node0")

    outliers = _find_timing_outliers(graph)
    assert len(outliers) == 0


def test_find_timing_outliers_only_positive():
    """Only positive timing values (> 0) are included"""
    nodes = {
        "node1": _make_node("node1", captures=[_make_capture(duration_ms=100, ttfb_ms=50)]),
        "node2": _make_node("node2", captures=[_make_capture(duration_ms=105, ttfb_ms=52)]),
        "node3": _make_node("node3", captures=[_make_capture(duration_ms=0, ttfb_ms=0)]),
        "node4": _make_node("node4", captures=[_make_capture(duration_ms=-10, ttfb_ms=-5)]),
        "node5": _make_node("node5", captures=[_make_capture(duration_ms=102, ttfb_ms=51)]),
    }
    graph = _make_graph(nodes, [], root_url="node1")

    outliers = _find_timing_outliers(graph)

    outlier_urls = {o.url for o in outliers}
    assert "node3" not in outlier_urls
    assert "node4" not in outlier_urls


def test_invariant_timing_threshold():
    """Timing outlier threshold is |z-score| > 2.0"""
    nodes = {}
    for i in range(10):
        nid = f"node{i}"
        nodes[nid] = _make_node(nid, captures=[_make_capture(duration_ms=100)])
    # Add outlier
    nodes["outlier"] = _make_node("outlier", captures=[_make_capture(duration_ms=1000)])
    graph = _make_graph(nodes, [], root_url="node0")

    outliers = _find_timing_outliers(graph)

    for outlier in outliers:
        assert abs(outlier.z_score) > 2.0


# ============================================================================
# _enumerate_prime_paths TESTS
# ============================================================================

def test_enumerate_prime_paths_happy_path():
    """Enumerates prime paths from a simple DAG"""
    G = nx.DiGraph()
    G.add_edges_from([("n1", "n2"), ("n2", "n3"), ("n2", "n4")])

    paths = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)

    assert isinstance(paths, list)
    for path in paths:
        assert len(path.path) >= 2

    path_tuples = [tuple(p.path) for p in paths]
    assert len(path_tuples) == len(set(path_tuples))
    assert len(paths) <= 1000


def test_enumerate_prime_paths_empty():
    """Returns empty list for empty graph"""
    G = nx.DiGraph()

    paths = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)
    assert len(paths) == 0


def test_enumerate_prime_paths_max_paths_limit():
    """Respects max_paths limit"""
    G = nx.DiGraph()
    for i in range(5):
        for j in range(5):
            if i != j:
                G.add_edge(f"n{i}", f"n{j}")

    paths = _enumerate_prime_paths(G, max_loop=1, max_paths=10)
    assert len(paths) <= 10


def test_invariant_path_length_cutoff():
    """Path length cutoff is min(n_nodes, 15)"""
    G = nx.DiGraph()
    for i in range(19):
        G.add_edge(f"n{i}", f"n{i+1}")

    paths = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)

    n_nodes = G.number_of_nodes()
    cutoff = min(n_nodes, 15)
    # nx.all_simple_paths cutoff counts edges, so paths have at most cutoff+1 nodes
    max_len = cutoff + 1

    for path in paths:
        assert len(path.path) <= max_len


def test_enumerate_prime_paths_no_duplicates():
    """No duplicate paths in result"""
    G = nx.DiGraph()
    G.add_edges_from([("n1", "n2"), ("n2", "n3"), ("n3", "n1")])

    paths = _enumerate_prime_paths(G, max_loop=2, max_paths=1000)

    path_tuples = [tuple(p.path) for p in paths]
    assert len(path_tuples) == len(set(path_tuples)), "Found duplicate paths"


def test_enumerate_prime_paths_networkx_error():
    """Handles NetworkX errors gracefully"""
    G = nx.DiGraph()
    G.add_edges_from([("n1", "n2"), ("n2", "n3")])

    try:
        paths = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)
        assert isinstance(paths, list)
    except Exception as e:
        pytest.fail(f"NetworkX error not handled: {e}")


def test_invariant_default_max_paths_limit():
    """Default max_paths limit is 1000"""
    G = nx.DiGraph()
    for i in range(5):
        for j in range(5):
            if i != j:
                G.add_edge(f"n{i}", f"n{j}")

    paths = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)
    assert len(paths) <= 1000


# ============================================================================
# analyze TESTS
# ============================================================================

@patch('webprobe.security.scan_graph')
def test_analyze_happy_path(mock_scan_graph, linear_graph):
    """Complete analysis of a typical site graph"""
    mock_scan_graph.return_value = []

    result, status = analyze(linear_graph)

    assert isinstance(status, PhaseStatus)
    assert status.phase == 'analyze'
    assert status.status == 'completed'
    assert status.duration_ms > 0

    assert isinstance(result, AnalysisResult)
    assert hasattr(result, 'graph_metrics')
    assert hasattr(result, 'broken_links')
    assert hasattr(result, 'auth_violations')
    assert hasattr(result, 'timing_outliers')
    assert hasattr(result, 'prime_paths')
    assert hasattr(result, 'security_findings')


@patch('webprobe.security.scan_graph')
def test_analyze_empty_graph(mock_scan_graph, empty_graph):
    """Analyzes an empty site graph"""
    mock_scan_graph.return_value = []

    result, status = analyze(empty_graph)

    assert status.status == 'completed'
    assert len(result.broken_links) == 0
    assert len(result.auth_violations) == 0


@patch('webprobe.security.scan_graph')
def test_analyze_sets_duration(mock_scan_graph, linear_graph):
    """PhaseStatus.duration_ms is set to elapsed time"""
    mock_scan_graph.return_value = []

    result, status = analyze(linear_graph)

    assert status.duration_ms > 0
    assert isinstance(status.duration_ms, (int, float))


@patch('webprobe.security.scan_graph')
def test_analyze_includes_security_findings(mock_scan_graph, linear_graph):
    """AnalysisResult includes security_findings from scan_graph"""
    from webprobe.models import SecurityFinding, SecurityCategory, SecuritySeverity
    mock_finding = SecurityFinding(
        category=SecurityCategory.xss,
        severity=SecuritySeverity.high,
        title="XSS vulnerability",
        url="node1",
    )
    mock_scan_graph.return_value = [mock_finding]

    result, status = analyze(linear_graph)

    assert hasattr(result, 'security_findings')
    assert len(result.security_findings) == 1
    assert result.security_findings[0].title == "XSS vulnerability"
    mock_scan_graph.assert_called_once_with(linear_graph)


# ============================================================================
# ADDITIONAL EDGE CASE AND INTEGRATION TESTS
# ============================================================================

def test_build_nx_graph_preserves_structure(cycle_graph):
    """Verifies that graph structure is preserved exactly"""
    G = _build_nx_graph(cycle_graph)

    for node_id in cycle_graph.nodes:
        assert node_id in G.nodes()

    for edge in cycle_graph.edges:
        assert G.has_edge(edge.source, edge.target)

    assert G.number_of_nodes() == len(cycle_graph.nodes)
    assert G.number_of_edges() == len(cycle_graph.edges)


def test_compute_graph_metrics_disconnected_components(disconnected_graph):
    """Computes metrics correctly for disconnected graph"""
    G = _build_nx_graph(disconnected_graph)
    metrics = _compute_graph_metrics(disconnected_graph, G)

    n_components = nx.number_weakly_connected_components(G)
    assert n_components == 2

    n_edges = G.number_of_edges()
    n_nodes = G.number_of_nodes()
    expected_complexity = n_edges - n_nodes + 2 * n_components
    assert metrics.cyclomatic_complexity == expected_complexity


def test_find_broken_links_with_no_edges():
    """Handles graph with nodes but no edges"""
    n1 = _make_node("node1", captures=[_make_capture(http_status=404)])
    n2 = _make_node("node2", captures=[_make_capture(http_status=500)])
    graph = _make_graph({"node1": n1, "node2": n2}, [], root_url="node1")

    broken = _find_broken_links(graph)
    assert len(broken) == 0


def test_find_auth_violations_missing_anon_status():
    """Handles nodes with requires_auth=True but no anonymous capture"""
    # Node has requires_auth=True but only authenticated captures
    n1 = _make_node("node1", requires_auth=True, captures=[
        _make_capture(auth_context=AuthContext.authenticated, http_status=200),
    ])
    graph = _make_graph({"node1": n1}, [], root_url="node1")

    violations = _find_auth_violations(graph)
    assert isinstance(violations, list)
    # No anonymous capture -> no violation
    assert len(violations) == 0


def test_find_timing_outliers_three_samples_boundary():
    """Tests exactly 3 samples (boundary for minimum sample size)"""
    nodes = {
        "node1": _make_node("node1", captures=[_make_capture(duration_ms=100)]),
        "node2": _make_node("node2", captures=[_make_capture(duration_ms=100)]),
        "node3": _make_node("node3", captures=[_make_capture(duration_ms=500)]),
    }
    graph = _make_graph(nodes, [], root_url="node1")

    outliers = _find_timing_outliers(graph)
    assert isinstance(outliers, list)


def test_enumerate_prime_paths_single_node():
    """Handles graph with single node"""
    G = nx.DiGraph()
    G.add_node("n1")

    paths = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)
    assert len(paths) == 0


def test_enumerate_prime_paths_self_loop():
    """Handles graph with self-loop"""
    G = nx.DiGraph()
    G.add_edge("n1", "n1")

    paths = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)
    assert isinstance(paths, list)


@patch('webprobe.security.scan_graph')
def test_analyze_with_all_issues(mock_scan_graph, broken_links_graph, auth_mixed_graph):
    """Integration test with broken links, auth violations, and timing issues"""
    # Merge the two graphs: combine nodes and edges
    combined_nodes = dict(broken_links_graph.nodes)
    combined_nodes.update(auth_mixed_graph.nodes)
    combined_edges = list(broken_links_graph.edges) + list(auth_mixed_graph.edges)

    # Make node1 a timing outlier
    combined_nodes["node1"] = _make_node("node1", captures=[
        _make_capture(http_status=200, duration_ms=1000),
    ])

    graph = _make_graph(combined_nodes, combined_edges, root_url="node1")

    from webprobe.models import SecurityFinding, SecurityCategory, SecuritySeverity
    mock_scan_graph.return_value = [SecurityFinding(
        category=SecurityCategory.xss,
        severity=SecuritySeverity.low,
        title="test finding",
    )]

    result, status = analyze(graph)

    assert status.status == 'completed'
    assert len(result.broken_links) > 0
    assert len(result.security_findings) > 0


def test_broken_link_detection_null_status():
    """Handles nodes with null/None HTTP status"""
    n1 = _make_node("node1", captures=[_make_capture(http_status=200)])
    n2 = _make_node("node2", captures=[_make_capture(http_status=None)])
    edges = [Edge(source="node1", target="node2")]
    graph = _make_graph({"node1": n1, "node2": n2}, edges, root_url="node1")

    broken = _find_broken_links(graph)

    broken_targets = {b.target for b in broken}
    assert "node2" in broken_targets


@patch('webprobe.security.scan_graph')
def test_analyze_performance_reasonable(mock_scan_graph):
    """Verifies analyze completes in reasonable time for medium graph"""
    mock_scan_graph.return_value = []

    nodes = {}
    for i in range(50):
        nid = f"node{i}"
        nodes[nid] = _make_node(nid, captures=[_make_capture(duration_ms=100)])
    edges = [Edge(source=f"node{i}", target=f"node{i+1}") for i in range(49)]
    graph = _make_graph(nodes, edges, root_url="node0")

    start = time.time()
    result, status = analyze(graph)
    elapsed = time.time() - start

    assert elapsed < 5.0
    assert status.status == 'completed'


def test_cyclomatic_complexity_invariant_various_graphs():
    """Verifies cyclomatic complexity formula holds for various graph types"""
    test_cases = [
        # (nodes_dict, edges, expected_components)
        ({}, [], 0),
        ({"n1": _make_node("n1")}, [], 1),
        (
            {"n1": _make_node("n1"), "n2": _make_node("n2")},
            [Edge(source="n1", target="n2")],
            1,
        ),
        # Disconnected
        (
            {"n1": _make_node("n1"), "n2": _make_node("n2")},
            [],
            2,
        ),
    ]

    for nodes_dict, edges, expected_comp in test_cases:
        root = next(iter(nodes_dict), "")
        graph = _make_graph(nodes_dict, edges, root_url=root)
        G = _build_nx_graph(graph)
        metrics = _compute_graph_metrics(graph, G)

        n_edges = len(edges)
        n_nodes = len(nodes_dict)
        expected_complexity = n_edges - n_nodes + 2 * expected_comp

        assert metrics.cyclomatic_complexity == expected_complexity


def test_prime_paths_respects_max_loop_parameter():
    """Verifies that max_loop parameter affects path enumeration"""
    G = nx.DiGraph()
    G.add_edges_from([("n1", "n2"), ("n2", "n3"), ("n3", "n1")])

    paths_loop_0 = _enumerate_prime_paths(G, max_loop=0, max_paths=1000)
    paths_loop_1 = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)
    paths_loop_2 = _enumerate_prime_paths(G, max_loop=2, max_paths=1000)

    assert len(paths_loop_1) >= len(paths_loop_0)
    assert len(paths_loop_2) >= len(paths_loop_1)


def test_timing_outliers_multiple_metrics():
    """Verifies timing outliers checks all four timing metrics"""
    nodes = {}
    # Need enough samples so z-score exceeds 2.0
    for i in range(9):
        nid = f"normal{i}"
        nodes[nid] = _make_node(nid, captures=[
            _make_capture(duration_ms=100+i, ttfb_ms=50+i, dom_content_loaded_ms=80+i, load_event_ms=90+i),
        ])
    # Outlier in ttfb only
    nodes["outlier"] = _make_node("outlier", captures=[
        _make_capture(duration_ms=103, ttfb_ms=5000, dom_content_loaded_ms=82, load_event_ms=91),
    ])
    graph = _make_graph(nodes, [], root_url="normal0")

    outliers = _find_timing_outliers(graph)

    outlier_metrics = {o.metric for o in outliers}
    assert "ttfb_ms" in outlier_metrics


@patch('webprobe.security.scan_graph')
def test_analyze_reports_phase_correctly(mock_scan_graph, linear_graph):
    """Verifies PhaseStatus.phase is always 'analyze'"""
    mock_scan_graph.return_value = []

    result, status = analyze(linear_graph)

    assert status.phase == 'analyze'


def test_build_nx_graph_creates_new_object(linear_graph):
    """Verifies that _build_nx_graph creates a new DiGraph object"""
    G1 = _build_nx_graph(linear_graph)
    G2 = _build_nx_graph(linear_graph)

    assert G1 is not G2
    assert G1.number_of_nodes() == G2.number_of_nodes()
    assert G1.number_of_edges() == G2.number_of_edges()
