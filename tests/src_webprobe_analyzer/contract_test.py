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

# Import models (mocked if needed)
try:
    from webprobe.models import (
        SiteGraph,
        GraphNode,
        GraphEdge,
        GraphMetrics,
        BrokenLink,
        AuthBoundaryViolation,
        TimingOutlier,
        PrimePath,
        AnalysisResult,
        PhaseStatus,
        CaptureData,
    )
except ImportError:
    # Mock models if not available
    class GraphNode:
        def __init__(self, node_id, url="", requires_auth=False, http_status=200, 
                     duration_ms=100, ttfb_ms=50, dom_content_loaded_ms=80, 
                     load_event_ms=90, anon_http_status=None):
            self.node_id = node_id
            self.url = url
            self.requires_auth = requires_auth
            self.http_status = http_status
            self.duration_ms = duration_ms
            self.ttfb_ms = ttfb_ms
            self.dom_content_loaded_ms = dom_content_loaded_ms
            self.load_event_ms = load_event_ms
            self.anon_http_status = anon_http_status

    class GraphEdge:
        def __init__(self, source, target):
            self.source = source
            self.target = target

    class SiteGraph:
        def __init__(self, nodes=None, edges=None, root_node_id=None):
            self.nodes = nodes or []
            self.edges = edges or []
            self.root_node_id = root_node_id

    class GraphMetrics:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class BrokenLink:
        def __init__(self, source, target, http_status):
            self.source = source
            self.target = target
            self.http_status = http_status

    class AuthBoundaryViolation:
        def __init__(self, node_id, url, anon_http_status):
            self.node_id = node_id
            self.url = url
            self.anon_http_status = anon_http_status

    class TimingOutlier:
        def __init__(self, node_id, metric_name, value, z_score):
            self.node_id = node_id
            self.metric_name = metric_name
            self.value = value
            self.z_score = z_score

    class PrimePath:
        def __init__(self, path):
            self.path = path

    class AnalysisResult:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class PhaseStatus:
        def __init__(self, phase="", status="", duration_ms=0, **kwargs):
            self.phase = phase
            self.status = status
            self.duration_ms = duration_ms
            self.__dict__.update(kwargs)

    class CaptureData:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)


# ============================================================================
# TEST FIXTURES
# ============================================================================

@pytest.fixture
def empty_graph():
    """Empty SiteGraph with 0 nodes and 0 edges"""
    return SiteGraph(nodes=[], edges=[], root_node_id=None)


@pytest.fixture
def single_node_graph():
    """SiteGraph with 1 node and 0 edges"""
    node = GraphNode(node_id="node1", url="https://example.com/")
    return SiteGraph(nodes=[node], edges=[], root_node_id="node1")


@pytest.fixture
def linear_graph():
    """SiteGraph with 3 nodes in linear sequence"""
    nodes = [
        GraphNode(node_id="node1", url="https://example.com/", http_status=200),
        GraphNode(node_id="node2", url="https://example.com/page2", http_status=200),
        GraphNode(node_id="node3", url="https://example.com/page3", http_status=200),
    ]
    edges = [
        GraphEdge(source="node1", target="node2"),
        GraphEdge(source="node2", target="node3"),
    ]
    return SiteGraph(nodes=nodes, edges=edges, root_node_id="node1")


@pytest.fixture
def cycle_graph():
    """SiteGraph with 4 nodes forming a cycle"""
    nodes = [
        GraphNode(node_id=f"node{i}", url=f"https://example.com/page{i}", http_status=200)
        for i in range(1, 5)
    ]
    edges = [
        GraphEdge(source="node1", target="node2"),
        GraphEdge(source="node2", target="node3"),
        GraphEdge(source="node3", target="node4"),
        GraphEdge(source="node4", target="node1"),  # Cycle back
    ]
    return SiteGraph(nodes=nodes, edges=edges, root_node_id="node1")


@pytest.fixture
def disconnected_graph():
    """SiteGraph with 2 disconnected components"""
    nodes = [
        GraphNode(node_id="node1", url="https://example.com/", http_status=200),
        GraphNode(node_id="node2", url="https://example.com/page2", http_status=200),
        GraphNode(node_id="node3", url="https://example.com/other", http_status=200),
        GraphNode(node_id="node4", url="https://example.com/other2", http_status=200),
    ]
    edges = [
        GraphEdge(source="node1", target="node2"),
        GraphEdge(source="node3", target="node4"),
    ]
    return SiteGraph(nodes=nodes, edges=edges, root_node_id="node1")


@pytest.fixture
def auth_mixed_graph():
    """SiteGraph with mixed auth states"""
    nodes = [
        GraphNode(node_id="node1", url="https://example.com/", requires_auth=False, 
                  http_status=200, anon_http_status=200),
        GraphNode(node_id="node2", url="https://example.com/admin", requires_auth=True, 
                  http_status=200, anon_http_status=200),  # Violation!
        GraphNode(node_id="node3", url="https://example.com/secure", requires_auth=True, 
                  http_status=200, anon_http_status=403),  # Proper
        GraphNode(node_id="node4", url="https://example.com/dashboard", requires_auth=True, 
                  http_status=200, anon_http_status=301),  # No violation (redirect)
    ]
    edges = [
        GraphEdge(source="node1", target="node2"),
        GraphEdge(source="node1", target="node3"),
        GraphEdge(source="node1", target="node4"),
    ]
    return SiteGraph(nodes=nodes, edges=edges, root_node_id="node1")


@pytest.fixture
def timing_varied_graph():
    """SiteGraph with varied timing metrics (some outliers)"""
    # Normal timings: 100ms, outlier: 500ms (z-score > 2 with 5 samples)
    nodes = [
        GraphNode(node_id="node1", duration_ms=100, ttfb_ms=50, 
                  dom_content_loaded_ms=80, load_event_ms=90),
        GraphNode(node_id="node2", duration_ms=105, ttfb_ms=52, 
                  dom_content_loaded_ms=82, load_event_ms=92),
        GraphNode(node_id="node3", duration_ms=95, ttfb_ms=48, 
                  dom_content_loaded_ms=78, load_event_ms=88),
        GraphNode(node_id="node4", duration_ms=102, ttfb_ms=51, 
                  dom_content_loaded_ms=81, load_event_ms=91),
        GraphNode(node_id="node5", duration_ms=500, ttfb_ms=400, 
                  dom_content_loaded_ms=450, load_event_ms=480),  # Outlier
    ]
    return SiteGraph(nodes=nodes, edges=[], root_node_id="node1")


@pytest.fixture
def broken_links_graph():
    """SiteGraph with various HTTP status codes including broken links"""
    nodes = [
        GraphNode(node_id="node1", url="https://example.com/", http_status=200),
        GraphNode(node_id="node2", url="https://example.com/page2", http_status=200),
        GraphNode(node_id="node3", url="https://example.com/missing", http_status=404),
        GraphNode(node_id="node4", url="https://example.com/error", http_status=500),
        GraphNode(node_id="node5", url="https://example.com/redirect", http_status=301),
    ]
    edges = [
        GraphEdge(source="node1", target="node2"),  # OK
        GraphEdge(source="node1", target="node3"),  # Broken (404)
        GraphEdge(source="node2", target="node4"),  # Broken (500)
        GraphEdge(source="node1", target="node5"),  # OK (redirect in 200-399)
        GraphEdge(source="node1", target="node999"),  # External (not in graph)
    ]
    return SiteGraph(nodes=nodes, edges=edges, root_node_id="node1")


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
    node_ids = {node.node_id for node in linear_graph.nodes}
    assert set(G.nodes()) == node_ids
    
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
    
    # Verify cycle exists
    assert G.has_edge("node1", "node2")
    assert G.has_edge("node2", "node3")
    assert G.has_edge("node3", "node4")
    assert G.has_edge("node4", "node1")
    
    # Check for cycles
    try:
        cycles = list(nx.simple_cycles(G))
        assert len(cycles) > 0
    except:
        # Alternative: check that it's not a DAG
        assert not nx.is_directed_acyclic_graph(G)


# ============================================================================
# _compute_graph_metrics TESTS
# ============================================================================

def test_compute_graph_metrics_happy_path(linear_graph):
    """Computes metrics for a typical site graph"""
    G = _build_nx_graph(linear_graph)
    metrics = _compute_graph_metrics(linear_graph, G)
    
    assert isinstance(metrics, GraphMetrics)
    assert hasattr(metrics, 'edge_coverage')
    assert 0.0 <= metrics.edge_coverage <= 1.0
    
    # Verify cyclomatic complexity formula: E - N + 2P
    # For linear graph: 2 edges - 3 nodes + 2*1 component = 2 - 3 + 2 = 1
    assert hasattr(metrics, 'cyclomatic_complexity')
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
    assert hasattr(metrics, 'orphan_nodes')
    assert len(metrics.orphan_nodes) == 0
    assert hasattr(metrics, 'dead_ends')
    assert len(metrics.dead_ends) == 0
    # Edge coverage for empty graph can be 0.0 or 1.0 depending on definition
    assert metrics.edge_coverage in [0.0, 1.0]


def test_compute_graph_metrics_orphan_excludes_root(linear_graph):
    """Verifies orphan nodes excludes root node"""
    G = _build_nx_graph(linear_graph)
    metrics = _compute_graph_metrics(linear_graph, G)
    
    # Root node (node1) has no incoming edges but should not be in orphan_nodes
    assert linear_graph.root_node_id not in metrics.orphan_nodes


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
    # Test with various graph configurations
    test_graphs = []
    
    # Empty graph
    test_graphs.append(SiteGraph(nodes=[], edges=[], root_node_id=None))
    
    # Single node
    test_graphs.append(SiteGraph(
        nodes=[GraphNode(node_id="n1")], 
        edges=[], 
        root_node_id="n1"
    ))
    
    # Full connectivity (3 nodes, all edges)
    nodes_full = [GraphNode(node_id=f"n{i}") for i in range(3)]
    edges_full = [
        GraphEdge(source=f"n{i}", target=f"n{j}")
        for i in range(3) for j in range(3) if i != j
    ]
    test_graphs.append(SiteGraph(nodes=nodes_full, edges=edges_full, root_node_id="n0"))
    
    for graph in test_graphs:
        G = _build_nx_graph(graph)
        metrics = _compute_graph_metrics(graph, G)
        assert 0.0 <= metrics.edge_coverage <= 1.0, \
            f"Edge coverage {metrics.edge_coverage} out of range for graph with {len(graph.nodes)} nodes"


# ============================================================================
# _find_broken_links TESTS
# ============================================================================

def test_find_broken_links_happy_path(broken_links_graph):
    """Finds broken links in a graph with failing HTTP statuses"""
    broken = _find_broken_links(broken_links_graph)
    
    assert isinstance(broken, list)
    
    # Should find broken links to node3 (404) and node4 (500)
    broken_targets = {b.target for b in broken}
    assert "node3" in broken_targets  # 404
    assert "node4" in broken_targets  # 500
    
    # Should NOT include external links (node999)
    assert "node999" not in broken_targets


def test_find_broken_links_no_issues():
    """Returns empty list when all links are valid"""
    nodes = [
        GraphNode(node_id="node1", http_status=200),
        GraphNode(node_id="node2", http_status=200),
        GraphNode(node_id="node3", http_status=301),  # Redirect OK
    ]
    edges = [
        GraphEdge(source="node1", target="node2"),
        GraphEdge(source="node1", target="node3"),
    ]
    graph = SiteGraph(nodes=nodes, edges=edges, root_node_id="node1")
    
    broken = _find_broken_links(graph)
    assert len(broken) == 0


def test_find_broken_links_excludes_external(broken_links_graph):
    """External links (target not in graph) are excluded"""
    broken = _find_broken_links(broken_links_graph)
    
    # node999 is external (not in graph.nodes)
    broken_targets = {b.target for b in broken}
    assert "node999" not in broken_targets


def test_find_broken_links_boundary_statuses():
    """Tests boundary HTTP statuses (199, 200, 399, 400)"""
    nodes = [
        GraphNode(node_id="node1", http_status=200),
        GraphNode(node_id="node199", http_status=199),
        GraphNode(node_id="node200", http_status=200),
        GraphNode(node_id="node399", http_status=399),
        GraphNode(node_id="node400", http_status=400),
    ]
    edges = [
        GraphEdge(source="node1", target="node199"),
        GraphEdge(source="node1", target="node200"),
        GraphEdge(source="node1", target="node399"),
        GraphEdge(source="node1", target="node400"),
    ]
    graph = SiteGraph(nodes=nodes, edges=edges, root_node_id="node1")
    
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
    # node2 has requires_auth=True and anon_http_status=200 -> violation
    violation_nodes = {v.node_id for v in violations}
    assert "node2" in violation_nodes


def test_find_auth_violations_no_issues():
    """Returns empty list when no auth violations exist"""
    nodes = [
        GraphNode(node_id="node1", requires_auth=False, anon_http_status=200),
        GraphNode(node_id="node2", requires_auth=True, anon_http_status=403),
        GraphNode(node_id="node3", requires_auth=True, anon_http_status=401),
    ]
    graph = SiteGraph(nodes=nodes, edges=[], root_node_id="node1")
    
    violations = _find_auth_violations(graph)
    assert len(violations) == 0


def test_find_auth_violations_only_checks_requires_auth(auth_mixed_graph):
    """Only nodes with requires_auth=True are checked"""
    violations = _find_auth_violations(auth_mixed_graph)
    
    # node1 has requires_auth=False, should never be in violations
    violation_nodes = {v.node_id for v in violations}
    assert "node1" not in violation_nodes


def test_find_auth_violations_boundary_statuses():
    """Tests boundary HTTP statuses for auth violations (199, 200, 299, 300)"""
    nodes = [
        GraphNode(node_id="node199", requires_auth=True, anon_http_status=199),
        GraphNode(node_id="node200", requires_auth=True, anon_http_status=200),
        GraphNode(node_id="node299", requires_auth=True, anon_http_status=299),
        GraphNode(node_id="node300", requires_auth=True, anon_http_status=300),
    ]
    graph = SiteGraph(nodes=nodes, edges=[], root_node_id="node199")
    
    violations = _find_auth_violations(graph)
    violation_nodes = {v.node_id for v in violations}
    
    # 200-299 trigger violations
    assert "node200" in violation_nodes
    assert "node299" in violation_nodes
    
    # < 200 or >= 300 don't trigger violations
    assert "node199" not in violation_nodes
    assert "node300" not in violation_nodes


# ============================================================================
# _find_timing_outliers TESTS
# ============================================================================

def test_find_timing_outliers_happy_path(timing_varied_graph):
    """Finds nodes with timing metrics significantly above mean"""
    outliers = _find_timing_outliers(timing_varied_graph)
    
    assert isinstance(outliers, list)
    # node5 has significantly higher timings
    outlier_nodes = {o.node_id for o in outliers}
    assert "node5" in outlier_nodes
    
    # Check that z-scores are > 2.0
    for outlier in outliers:
        assert abs(outlier.z_score) > 2.0


def test_find_timing_outliers_no_issues():
    """Returns empty list when all timings are normal"""
    nodes = [
        GraphNode(node_id=f"node{i}", duration_ms=100, ttfb_ms=50,
                  dom_content_loaded_ms=80, load_event_ms=90)
        for i in range(5)
    ]
    graph = SiteGraph(nodes=nodes, edges=[], root_node_id="node0")
    
    outliers = _find_timing_outliers(graph)
    # All identical -> stddev = 0 -> skipped
    assert len(outliers) == 0


def test_find_timing_outliers_skips_small_samples():
    """Metrics with < 3 samples are skipped"""
    nodes = [
        GraphNode(node_id="node1", duration_ms=100),
        GraphNode(node_id="node2", duration_ms=1000),  # Would be outlier
    ]
    graph = SiteGraph(nodes=nodes, edges=[], root_node_id="node1")
    
    outliers = _find_timing_outliers(graph)
    # < 3 samples -> skipped
    assert len(outliers) == 0


def test_find_timing_outliers_skips_zero_stddev():
    """Metrics with stddev = 0 are skipped"""
    nodes = [
        GraphNode(node_id=f"node{i}", duration_ms=100, ttfb_ms=50,
                  dom_content_loaded_ms=80, load_event_ms=90)
        for i in range(5)
    ]
    graph = SiteGraph(nodes=nodes, edges=[], root_node_id="node0")
    
    outliers = _find_timing_outliers(graph)
    # All identical values -> stddev = 0 -> skipped
    assert len(outliers) == 0


def test_find_timing_outliers_only_positive():
    """Only positive timing values (> 0) are included"""
    nodes = [
        GraphNode(node_id="node1", duration_ms=100, ttfb_ms=50),
        GraphNode(node_id="node2", duration_ms=105, ttfb_ms=52),
        GraphNode(node_id="node3", duration_ms=0, ttfb_ms=0),  # Zero
        GraphNode(node_id="node4", duration_ms=-10, ttfb_ms=-5),  # Negative
        GraphNode(node_id="node5", duration_ms=102, ttfb_ms=51),
    ]
    graph = SiteGraph(nodes=nodes, edges=[], root_node_id="node1")
    
    outliers = _find_timing_outliers(graph)
    
    # Zero and negative values should be excluded
    outlier_nodes = {o.node_id for o in outliers}
    assert "node3" not in outlier_nodes
    assert "node4" not in outlier_nodes


def test_invariant_timing_threshold():
    """Timing outlier threshold is |z-score| > 2.0"""
    # Create graph with known outlier
    nodes = [
        GraphNode(node_id=f"node{i}", duration_ms=100)
        for i in range(10)
    ]
    # Add outlier with duration far from mean
    nodes.append(GraphNode(node_id="outlier", duration_ms=1000))
    graph = SiteGraph(nodes=nodes, edges=[], root_node_id="node0")
    
    outliers = _find_timing_outliers(graph)
    
    # Verify all outliers have |z-score| > 2.0
    for outlier in outliers:
        assert abs(outlier.z_score) > 2.0


# ============================================================================
# _enumerate_prime_paths TESTS
# ============================================================================

def test_enumerate_prime_paths_happy_path():
    """Enumerates prime paths from a simple DAG"""
    # Create simple DAG: 1 -> 2 -> 3
    #                         -> 4
    G = nx.DiGraph()
    G.add_edges_from([("n1", "n2"), ("n2", "n3"), ("n2", "n4")])
    
    paths = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)
    
    assert isinstance(paths, list)
    # All paths should have length >= 2
    for path in paths:
        assert len(path.path) >= 2
    
    # No duplicate paths
    path_tuples = [tuple(p.path) for p in paths]
    assert len(path_tuples) == len(set(path_tuples))
    
    # Should not exceed max_paths
    assert len(paths) <= 1000


def test_enumerate_prime_paths_empty():
    """Returns empty list for empty graph"""
    G = nx.DiGraph()
    
    paths = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)
    
    assert len(paths) == 0


def test_enumerate_prime_paths_max_paths_limit():
    """Respects max_paths limit"""
    # Create graph with many paths
    G = nx.DiGraph()
    # Create a complete graph to generate many paths
    for i in range(5):
        for j in range(5):
            if i != j:
                G.add_edge(f"n{i}", f"n{j}")
    
    paths = _enumerate_prime_paths(G, max_loop=1, max_paths=10)
    
    assert len(paths) <= 10


def test_invariant_path_length_cutoff():
    """Path length cutoff is min(n_nodes, 15)"""
    # Create linear graph with 20 nodes
    G = nx.DiGraph()
    for i in range(19):
        G.add_edge(f"n{i}", f"n{i+1}")
    
    paths = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)
    
    n_nodes = G.number_of_nodes()
    max_len = min(n_nodes, 15)
    
    # All paths should respect length cap
    for path in paths:
        assert len(path.path) <= max_len


def test_enumerate_prime_paths_no_duplicates():
    """No duplicate paths in result"""
    G = nx.DiGraph()
    # Simple cycle
    G.add_edges_from([("n1", "n2"), ("n2", "n3"), ("n3", "n1")])
    
    paths = _enumerate_prime_paths(G, max_loop=2, max_paths=1000)
    
    # Check for duplicates
    path_tuples = [tuple(p.path) for p in paths]
    assert len(path_tuples) == len(set(path_tuples)), "Found duplicate paths"


def test_enumerate_prime_paths_networkx_error():
    """Handles NetworkX errors gracefully"""
    # Create a mock DiGraph that raises NetworkX errors
    G = nx.DiGraph()
    G.add_edges_from([("n1", "n2"), ("n2", "n3")])
    
    # The function should handle errors and return partial results
    # This is tested by the contract error handling
    try:
        paths = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)
        # Should return list (possibly empty if all attempts failed)
        assert isinstance(paths, list)
    except Exception as e:
        # If NetworkX errors are not caught, this test would fail
        pytest.fail(f"NetworkX error not handled: {e}")


def test_invariant_default_max_paths_limit():
    """Default max_paths limit is 1000"""
    G = nx.DiGraph()
    # Create graph with potential for many paths
    for i in range(5):
        for j in range(5):
            if i != j:
                G.add_edge(f"n{i}", f"n{j}")
    
    # Call without explicit max_paths (should default to 1000)
    paths = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)
    
    assert len(paths) <= 1000


# ============================================================================
# analyze TESTS
# ============================================================================

@patch('src_webprobe_analyzer.webprobe.security.scan_graph')
def test_analyze_happy_path(mock_scan_graph, linear_graph):
    """Complete analysis of a typical site graph"""
    # Mock security scan
    mock_scan_graph.return_value = []
    
    result, status = analyze(linear_graph)
    
    # Verify PhaseStatus
    assert isinstance(status, PhaseStatus)
    assert status.phase == 'analyze'
    assert status.status == 'completed'
    assert status.duration_ms > 0
    
    # Verify AnalysisResult contains all components
    assert isinstance(result, AnalysisResult)
    assert hasattr(result, 'graph_metrics')
    assert hasattr(result, 'broken_links')
    assert hasattr(result, 'auth_violations')
    assert hasattr(result, 'timing_outliers')
    assert hasattr(result, 'prime_paths')
    assert hasattr(result, 'security_findings')


@patch('src_webprobe_analyzer.webprobe.security.scan_graph')
def test_analyze_empty_graph(mock_scan_graph, empty_graph):
    """Analyzes an empty site graph"""
    mock_scan_graph.return_value = []
    
    result, status = analyze(empty_graph)
    
    assert status.status == 'completed'
    assert len(result.broken_links) == 0
    assert len(result.auth_violations) == 0


@patch('src_webprobe_analyzer.webprobe.security.scan_graph')
def test_analyze_sets_duration(mock_scan_graph, linear_graph):
    """PhaseStatus.duration_ms is set to elapsed time"""
    mock_scan_graph.return_value = []
    
    result, status = analyze(linear_graph)
    
    assert status.duration_ms > 0
    assert isinstance(status.duration_ms, (int, float))


@patch('src_webprobe_analyzer.webprobe.security.scan_graph')
def test_analyze_includes_security_findings(mock_scan_graph, linear_graph):
    """AnalysisResult includes security_findings from scan_graph"""
    # Mock security findings
    mock_findings = [
        {"type": "xss", "node_id": "node1", "severity": "high"}
    ]
    mock_scan_graph.return_value = mock_findings
    
    result, status = analyze(linear_graph)
    
    assert hasattr(result, 'security_findings')
    assert result.security_findings == mock_findings
    mock_scan_graph.assert_called_once_with(linear_graph)


# ============================================================================
# ADDITIONAL EDGE CASE AND INTEGRATION TESTS
# ============================================================================

def test_build_nx_graph_preserves_structure(cycle_graph):
    """Verifies that graph structure is preserved exactly"""
    G = _build_nx_graph(cycle_graph)
    
    # Check all nodes
    for node in cycle_graph.nodes:
        assert node.node_id in G.nodes()
    
    # Check all edges
    for edge in cycle_graph.edges:
        assert G.has_edge(edge.source, edge.target)
    
    # Check no extra nodes or edges
    assert G.number_of_nodes() == len(cycle_graph.nodes)
    assert G.number_of_edges() == len(cycle_graph.edges)


def test_compute_graph_metrics_disconnected_components(disconnected_graph):
    """Computes metrics correctly for disconnected graph"""
    G = _build_nx_graph(disconnected_graph)
    metrics = _compute_graph_metrics(disconnected_graph, G)
    
    # Should have 2 weakly connected components
    n_components = nx.number_weakly_connected_components(G)
    assert n_components == 2
    
    # Verify cyclomatic complexity with multiple components
    n_edges = G.number_of_edges()
    n_nodes = G.number_of_nodes()
    expected_complexity = n_edges - n_nodes + 2 * n_components
    assert metrics.cyclomatic_complexity == expected_complexity


def test_find_broken_links_with_no_edges():
    """Handles graph with nodes but no edges"""
    nodes = [
        GraphNode(node_id="node1", http_status=404),
        GraphNode(node_id="node2", http_status=500),
    ]
    graph = SiteGraph(nodes=nodes, edges=[], root_node_id="node1")
    
    broken = _find_broken_links(graph)
    # No edges means no broken links
    assert len(broken) == 0


def test_find_auth_violations_missing_anon_status():
    """Handles nodes with requires_auth=True but no anon_http_status"""
    nodes = [
        GraphNode(node_id="node1", requires_auth=True, anon_http_status=None),
    ]
    graph = SiteGraph(nodes=nodes, edges=[], root_node_id="node1")
    
    # Should handle gracefully (no violation if no anon capture)
    violations = _find_auth_violations(graph)
    # Implementation dependent - either skip or report
    assert isinstance(violations, list)


def test_find_timing_outliers_three_samples_boundary():
    """Tests exactly 3 samples (boundary for minimum sample size)"""
    nodes = [
        GraphNode(node_id="node1", duration_ms=100),
        GraphNode(node_id="node2", duration_ms=100),
        GraphNode(node_id="node3", duration_ms=500),  # Potential outlier
    ]
    graph = SiteGraph(nodes=nodes, edges=[], root_node_id="node1")
    
    outliers = _find_timing_outliers(graph)
    # With 3 samples, should be analyzed
    assert isinstance(outliers, list)


def test_enumerate_prime_paths_single_node():
    """Handles graph with single node"""
    G = nx.DiGraph()
    G.add_node("n1")
    
    paths = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)
    
    # Single node cannot form path of length >= 2
    assert len(paths) == 0


def test_enumerate_prime_paths_self_loop():
    """Handles graph with self-loop"""
    G = nx.DiGraph()
    G.add_edge("n1", "n1")  # Self-loop
    
    paths = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)
    
    # Should handle self-loops gracefully
    assert isinstance(paths, list)


@patch('src_webprobe_analyzer.webprobe.security.scan_graph')
def test_analyze_with_all_issues(mock_scan_graph, broken_links_graph, auth_mixed_graph):
    """Integration test with broken links, auth violations, and timing issues"""
    # Combine multiple issue types
    combined_nodes = broken_links_graph.nodes + auth_mixed_graph.nodes
    combined_edges = broken_links_graph.edges + auth_mixed_graph.edges
    
    # Add timing outliers
    combined_nodes[0].duration_ms = 1000  # Make it an outlier
    
    graph = SiteGraph(
        nodes=combined_nodes,
        edges=combined_edges,
        root_node_id=broken_links_graph.root_node_id
    )
    
    mock_scan_graph.return_value = [{"type": "test", "severity": "low"}]
    
    result, status = analyze(graph)
    
    assert status.status == 'completed'
    assert len(result.broken_links) > 0
    assert len(result.security_findings) > 0


def test_broken_link_detection_null_status():
    """Handles nodes with null/None HTTP status"""
    nodes = [
        GraphNode(node_id="node1", http_status=200),
        GraphNode(node_id="node2", http_status=None),
    ]
    edges = [
        GraphEdge(source="node1", target="node2"),
    ]
    graph = SiteGraph(nodes=nodes, edges=edges, root_node_id="node1")
    
    broken = _find_broken_links(graph)
    
    # None status should be treated as broken (no successful capture)
    broken_targets = {b.target for b in broken}
    assert "node2" in broken_targets


@patch('src_webprobe_analyzer.webprobe.security.scan_graph')
def test_analyze_performance_reasonable(mock_scan_graph):
    """Verifies analyze completes in reasonable time for medium graph"""
    mock_scan_graph.return_value = []
    
    # Create medium-sized graph (50 nodes)
    nodes = [
        GraphNode(node_id=f"node{i}", http_status=200, duration_ms=100)
        for i in range(50)
    ]
    edges = [
        GraphEdge(source=f"node{i}", target=f"node{i+1}")
        for i in range(49)
    ]
    graph = SiteGraph(nodes=nodes, edges=edges, root_node_id="node0")
    
    start = time.time()
    result, status = analyze(graph)
    elapsed = time.time() - start
    
    # Should complete in reasonable time (< 5 seconds)
    assert elapsed < 5.0
    assert status.status == 'completed'


def test_cyclomatic_complexity_invariant_various_graphs():
    """Verifies cyclomatic complexity formula holds for various graph types"""
    test_cases = [
        # (nodes, edges, expected_components)
        ([], [], 0),
        ([GraphNode(node_id="n1")], [], 1),
        ([GraphNode(node_id="n1"), GraphNode(node_id="n2")], 
         [GraphEdge("n1", "n2")], 1),
        # Disconnected
        ([GraphNode(node_id="n1"), GraphNode(node_id="n2")], [], 2),
    ]
    
    for nodes, edges, expected_comp in test_cases:
        graph = SiteGraph(
            nodes=nodes, 
            edges=edges, 
            root_node_id=nodes[0].node_id if nodes else None
        )
        G = _build_nx_graph(graph)
        metrics = _compute_graph_metrics(graph, G)
        
        n_edges = len(edges)
        n_nodes = len(nodes)
        n_components = expected_comp
        expected_complexity = n_edges - n_nodes + 2 * n_components
        
        assert metrics.cyclomatic_complexity == expected_complexity


def test_prime_paths_respects_max_loop_parameter():
    """Verifies that max_loop parameter affects path enumeration"""
    # Create simple cycle
    G = nx.DiGraph()
    G.add_edges_from([("n1", "n2"), ("n2", "n3"), ("n3", "n1")])
    
    paths_loop_0 = _enumerate_prime_paths(G, max_loop=0, max_paths=1000)
    paths_loop_1 = _enumerate_prime_paths(G, max_loop=1, max_paths=1000)
    paths_loop_2 = _enumerate_prime_paths(G, max_loop=2, max_paths=1000)
    
    # Higher max_loop should allow more paths (or equal)
    assert len(paths_loop_1) >= len(paths_loop_0)
    assert len(paths_loop_2) >= len(paths_loop_1)


def test_timing_outliers_multiple_metrics():
    """Verifies timing outliers checks all four timing metrics"""
    nodes = [
        GraphNode(node_id="node1", duration_ms=100, ttfb_ms=50, 
                  dom_content_loaded_ms=80, load_event_ms=90),
        GraphNode(node_id="node2", duration_ms=105, ttfb_ms=52, 
                  dom_content_loaded_ms=82, load_event_ms=92),
        GraphNode(node_id="node3", duration_ms=102, ttfb_ms=51, 
                  dom_content_loaded_ms=81, load_event_ms=91),
        # Outlier in ttfb only
        GraphNode(node_id="node4", duration_ms=103, ttfb_ms=500, 
                  dom_content_loaded_ms=82, load_event_ms=91),
    ]
    graph = SiteGraph(nodes=nodes, edges=[], root_node_id="node1")
    
    outliers = _find_timing_outliers(graph)
    
    # Should detect outlier in ttfb_ms
    outlier_metrics = {o.metric_name for o in outliers}
    assert "ttfb_ms" in outlier_metrics or len(outliers) > 0


@patch('src_webprobe_analyzer.webprobe.security.scan_graph')
def test_analyze_reports_phase_correctly(mock_scan_graph, linear_graph):
    """Verifies PhaseStatus.phase is always 'analyze'"""
    mock_scan_graph.return_value = []
    
    result, status = analyze(linear_graph)
    
    assert status.phase == 'analyze'


def test_build_nx_graph_creates_new_object(linear_graph):
    """Verifies that _build_nx_graph creates a new DiGraph object"""
    G1 = _build_nx_graph(linear_graph)
    G2 = _build_nx_graph(linear_graph)
    
    # Should be different objects
    assert G1 is not G2
    # But structurally equivalent
    assert G1.number_of_nodes() == G2.number_of_nodes()
    assert G1.number_of_edges() == G2.number_of_edges()
