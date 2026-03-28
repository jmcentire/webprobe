"""
Contract tests for WebProbe Differ component.

This module tests the load_run() and diff_runs() functions according to
their contract specifications, covering happy paths, edge cases, and error cases.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open, MagicMock
from typing import Any, Dict, List

# Import the component under test
from src.webprobe.differ import load_run, diff_runs
from webprobe.models import Edge, BrokenLink, AuthBoundaryViolation


# ============================================================================
# HELPERS - Build mock Run objects matching the real model structure
# ============================================================================

def _make_timing(duration_ms):
    """Create a mock TimingData with the given duration."""
    t = Mock()
    t.duration_ms = duration_ms
    t.ttfb_ms = None
    return t


def _make_capture(http_status=200, duration_ms=100):
    """Create a mock NodeCapture matching the real model."""
    cap = Mock()
    cap.http_status = http_status
    cap.timing = _make_timing(duration_ms)
    return cap


def _make_node(node_id, captures=None):
    """Create a mock Node matching the real model."""
    node = Mock()
    node.id = node_id
    node.captures = captures if captures is not None else []
    return node


def _make_edge(source, target):
    """Create a real Edge model instance."""
    return Edge(source=source, target=target)


def _make_broken_link(source, target):
    """Create a real BrokenLink model instance."""
    return BrokenLink(source=source, target=target)


def _make_auth_violation(url):
    """Create a real AuthBoundaryViolation model instance."""
    return AuthBoundaryViolation(
        url=url,
        expected_auth=True,
        actual_accessible_anonymous=True,
    )


def _make_run(schema_version="1.0", nodes_dict=None, edges=None,
              analysis=None, run_id="run-001"):
    """Create a mock Run matching the real model.

    nodes_dict should be a dict mapping node_id -> Node mock.
    The real SiteGraph.nodes is dict[str, Node].
    """
    run = Mock()
    run.schema_version = schema_version
    run.run_id = run_id
    run.graph = Mock()
    run.graph.nodes = nodes_dict if nodes_dict is not None else {}
    run.graph.edges = edges if edges is not None else []
    run.analysis = analysis
    return run


# ============================================================================
# FIXTURES - Test Data Builders
# ============================================================================

@pytest.fixture
def valid_run_data() -> Dict[str, Any]:
    """Valid Run object data structure."""
    return {
        "id": "run-001",
        "schema_version": "1.0",
        "timestamp": "2024-01-01T00:00:00Z",
        "graph": {
            "nodes": [
                {
                    "id": "node1",
                    "url": "https://example.com/page1",
                    "captures": [
                        {
                            "status_code": 200,
                            "duration_ms": 100
                        }
                    ]
                },
                {
                    "id": "node2",
                    "url": "https://example.com/page2",
                    "captures": [
                        {
                            "status_code": 404,
                            "duration_ms": 50
                        }
                    ]
                }
            ],
            "edges": [
                {"source": "node1", "target": "node2"}
            ]
        },
        "broken_links": [],
        "auth_violations": []
    }


@pytest.fixture
def valid_run_b_data() -> Dict[str, Any]:
    """Valid Run object data structure for run_b with some differences."""
    return {
        "id": "run-002",
        "schema_version": "1.0",
        "timestamp": "2024-01-02T00:00:00Z",
        "graph": {
            "nodes": [
                {
                    "id": "node1",
                    "url": "https://example.com/page1",
                    "captures": [
                        {
                            "status_code": 200,
                            "duration_ms": 150
                        }
                    ]
                },
                {
                    "id": "node3",
                    "url": "https://example.com/page3",
                    "captures": [
                        {
                            "status_code": 200,
                            "duration_ms": 75
                        }
                    ]
                }
            ],
            "edges": [
                {"source": "node1", "target": "node3"}
            ]
        },
        "broken_links": [],
        "auth_violations": []
    }


# ============================================================================
# TESTS - load_run() - Happy Path
# ============================================================================

def test_load_run_happy_path(tmp_path, valid_run_data):
    """Successfully load a valid Run object from a directory with report.json."""
    run_dir = tmp_path / "test_run"
    run_dir.mkdir()
    report_file = run_dir / "report.json"

    with open(report_file, 'w') as f:
        json.dump(valid_run_data, f)

    with patch('src.webprobe.differ.Run') as MockRun:
        mock_run_instance = Mock()
        MockRun.model_validate.return_value = mock_run_instance

        result = load_run(run_dir)

        assert result == mock_run_instance
        MockRun.model_validate.assert_called_once()


def test_load_run_valid_json_structure(tmp_path, valid_run_data):
    """Load correctly parses and validates the JSON structure."""
    run_dir = tmp_path / "test_run"
    run_dir.mkdir()
    report_file = run_dir / "report.json"

    with open(report_file, 'w') as f:
        json.dump(valid_run_data, f)

    with patch('src.webprobe.differ.Run') as MockRun:
        mock_run = Mock()
        MockRun.model_validate.return_value = mock_run

        result = load_run(run_dir)

        # Verify the data passed to model_validate matches our input
        call_args = MockRun.model_validate.call_args[0][0]
        assert call_args["id"] == "run-001"
        assert call_args["schema_version"] == "1.0"


# ============================================================================
# TESTS - load_run() - Error Cases
# ============================================================================

def test_load_run_missing_report_file(tmp_path):
    """Error when report.json does not exist in the run directory."""
    run_dir = tmp_path / "test_run"
    run_dir.mkdir()

    # report.json does not exist
    with pytest.raises((FileNotFoundError, Exception)) as exc_info:
        load_run(run_dir)

    # Verify the error is related to missing file
    assert "report.json" in str(exc_info.value).lower() or "not found" in str(exc_info.value).lower() or isinstance(exc_info.value, FileNotFoundError)


def test_load_run_directory_does_not_exist(tmp_path):
    """Error when the directory itself does not exist."""
    run_dir = tmp_path / "nonexistent_dir"

    with pytest.raises((FileNotFoundError, Exception)):
        load_run(run_dir)


def test_load_run_invalid_json_syntax(tmp_path):
    """Error when report.json contains malformed JSON."""
    run_dir = tmp_path / "test_run"
    run_dir.mkdir()
    report_file = run_dir / "report.json"

    # Write invalid JSON
    with open(report_file, 'w') as f:
        f.write('{"invalid": json syntax}')

    with pytest.raises((json.JSONDecodeError, Exception)) as exc_info:
        load_run(run_dir)

    assert isinstance(exc_info.value, (json.JSONDecodeError, Exception))


def test_load_run_truncated_json(tmp_path):
    """Error when report.json is truncated."""
    run_dir = tmp_path / "test_run"
    run_dir.mkdir()
    report_file = run_dir / "report.json"

    with open(report_file, 'w') as f:
        f.write('{"id": "run-001", "schema_version": ')

    with pytest.raises((json.JSONDecodeError, Exception)):
        load_run(run_dir)


def test_load_run_not_json_object(tmp_path):
    """Error when report.json contains array or primitive instead of object."""
    run_dir = tmp_path / "test_run"
    run_dir.mkdir()
    report_file = run_dir / "report.json"

    # Write JSON array instead of object
    with open(report_file, 'w') as f:
        json.dump([1, 2, 3], f)

    with patch('src.webprobe.differ.Run') as MockRun:
        MockRun.model_validate.side_effect = ValueError("Expected dict")

        with pytest.raises((ValueError, Exception)):
            load_run(run_dir)


def test_load_run_validation_error_missing_fields(tmp_path):
    """Error when JSON does not match Run model schema - missing required fields."""
    run_dir = tmp_path / "test_run"
    run_dir.mkdir()
    report_file = run_dir / "report.json"

    # Missing required fields
    invalid_data = {"schema_version": "1.0"}  # missing id, timestamp, etc.

    with open(report_file, 'w') as f:
        json.dump(invalid_data, f)

    with patch('src.webprobe.differ.Run') as MockRun:
        MockRun.model_validate.side_effect = ValueError("Validation error: missing required field")

        with pytest.raises((ValueError, Exception)) as exc_info:
            load_run(run_dir)

        assert "validation" in str(exc_info.value).lower() or isinstance(exc_info.value, ValueError)


def test_load_run_validation_error_wrong_types(tmp_path):
    """Error when JSON has type mismatches."""
    run_dir = tmp_path / "test_run"
    run_dir.mkdir()
    report_file = run_dir / "report.json"

    # Wrong type for schema_version
    invalid_data = {
        "id": "run-001",
        "schema_version": 123,  # should be string
        "timestamp": "2024-01-01T00:00:00Z"
    }

    with open(report_file, 'w') as f:
        json.dump(invalid_data, f)

    with patch('src.webprobe.differ.Run') as MockRun:
        MockRun.model_validate.side_effect = TypeError("Type mismatch")

        with pytest.raises((TypeError, Exception)):
            load_run(run_dir)


# ============================================================================
# TESTS - diff_runs() - Happy Path
# ============================================================================

def test_diff_runs_happy_path():
    """Successfully compare two compatible Run objects."""
    run_a = _make_run(
        nodes_dict={"node1": _make_node("node1")},
        edges=[_make_edge("node1", "node2")],
        run_id="run-a",
    )
    run_b = _make_run(
        nodes_dict={
            "node1": _make_node("node1"),
            "node3": _make_node("node3"),
        },
        edges=[_make_edge("node1", "node3")],
        run_id="run-b",
    )

    result = diff_runs(run_a, run_b)
    assert result is not None


def test_diff_runs_nodes_added():
    """Detect nodes added in run_b."""
    run_a = _make_run(
        nodes_dict={
            "node1": _make_node("node1"),
            "node2": _make_node("node2"),
        },
    )
    run_b = _make_run(
        nodes_dict={
            "node1": _make_node("node1"),
            "node2": _make_node("node2"),
            "node3": _make_node("node3"),
            "node4": _make_node("node4"),
        },
    )

    result = diff_runs(run_a, run_b)

    assert result is not None
    assert result.nodes_added == ["node3", "node4"]


def test_diff_runs_nodes_removed():
    """Detect nodes removed from run_a."""
    run_a = _make_run(
        nodes_dict={
            "node1": _make_node("node1"),
            "node2": _make_node("node2"),
            "node3": _make_node("node3"),
        },
    )
    run_b = _make_run(
        nodes_dict={"node1": _make_node("node1")},
    )

    result = diff_runs(run_a, run_b)

    assert result is not None
    assert result.nodes_removed == ["node2", "node3"]


def test_diff_runs_status_changes():
    """Detect HTTP status code changes between runs."""
    run_a = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=200)]),
        },
    )
    run_b = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=404)]),
        },
    )

    result = diff_runs(run_a, run_b)

    assert result is not None
    assert len(result.status_changes) == 1
    assert result.status_changes[0].url == "node1"


def test_diff_runs_timing_changes_above_threshold():
    """Detect timing changes above 20% threshold."""
    run_a = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=200, duration_ms=100)]),
        },
    )
    run_b = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=200, duration_ms=150)]),
        },
    )

    result = diff_runs(run_a, run_b)

    assert result is not None
    assert len(result.timing_changes) == 1


def test_diff_runs_edges_added_removed():
    """Detect edges added and removed."""
    run_a = _make_run(
        nodes_dict={
            "node1": _make_node("node1"),
            "node2": _make_node("node2"),
        },
        edges=[_make_edge("node1", "node2"), _make_edge("node2", "node3")],
    )
    run_b = _make_run(
        nodes_dict={
            "node1": _make_node("node1"),
            "node3": _make_node("node3"),
        },
        edges=[_make_edge("node1", "node3"), _make_edge("node3", "node4")],
    )

    result = diff_runs(run_a, run_b)

    assert result is not None
    assert len(result.edges_added) == 2
    assert len(result.edges_removed) == 2


# ============================================================================
# TESTS - diff_runs() - Edge Cases
# ============================================================================

def test_diff_runs_identical_runs():
    """Diff of identical runs produces empty changes."""
    node_a = _make_node("node1", [_make_capture(http_status=200, duration_ms=100)])
    node_b = _make_node("node1", [_make_capture(http_status=200, duration_ms=100)])
    run_a = _make_run(nodes_dict={"node1": node_a})
    run_b = _make_run(nodes_dict={"node1": node_b})

    result = diff_runs(run_a, run_b)

    assert result is not None
    assert result.nodes_added == []
    assert result.nodes_removed == []
    assert result.status_changes == []
    assert result.timing_changes == []


def test_diff_runs_empty_runs():
    """Diff of two empty runs."""
    run_a = _make_run()
    run_b = _make_run()

    result = diff_runs(run_a, run_b)

    assert result is not None
    assert result.nodes_added == []
    assert result.nodes_removed == []


def test_diff_runs_timing_changes_below_threshold():
    """No timing changes when delta is below 20%."""
    run_a = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=200, duration_ms=100)]),
        },
    )
    run_b = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=200, duration_ms=110)]),
        },
    )

    result = diff_runs(run_a, run_b)

    assert result is not None
    assert len(result.timing_changes) == 0


def test_diff_runs_timing_changes_exactly_at_threshold():
    """Timing change exactly at 20% threshold."""
    run_a = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=200, duration_ms=100)]),
        },
    )
    run_b = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=200, duration_ms=120)]),
        },
    )

    result = diff_runs(run_a, run_b)

    # Exactly at 20% -- implementation uses > 0.20, so should NOT be included
    assert result is not None
    assert len(result.timing_changes) == 0


# ============================================================================
# TESTS - diff_runs() - Error Cases
# ============================================================================

def test_diff_runs_schema_version_mismatch():
    """Error when comparing runs with different schema versions."""
    run_a = _make_run(schema_version="1.0")
    run_b = _make_run(schema_version="2.0")

    with pytest.raises(Exception) as exc_info:
        diff_runs(run_a, run_b)

    assert "schema" in str(exc_info.value).lower() or "version" in str(exc_info.value).lower() or "mismatch" in str(exc_info.value).lower()


def test_diff_runs_missing_graph_attribute_run_a():
    """Error when run_a lacks graph attribute."""
    run_a = Mock(spec=['schema_version'])
    run_a.schema_version = "1.0"
    # No graph attribute

    run_b = _make_run(schema_version="1.0")

    with pytest.raises(AttributeError):
        diff_runs(run_a, run_b)


def test_diff_runs_missing_graph_attribute_run_b():
    """Error when run_b lacks graph attribute."""
    run_a = _make_run(schema_version="1.0")

    run_b = Mock(spec=['schema_version'])
    run_b.schema_version = "1.0"
    # No graph attribute

    with pytest.raises(AttributeError):
        diff_runs(run_a, run_b)


def test_diff_runs_empty_captures_handled_gracefully():
    """Empty captures list is handled gracefully (not IndexError)."""
    run_a = _make_run(
        nodes_dict={"node1": _make_node("node1", captures=[])},
    )
    run_b = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=200)]),
        },
    )

    # Implementation guards against empty captures; should not raise
    result = diff_runs(run_a, run_b)
    assert result is not None


def test_diff_runs_zero_duration_handled_gracefully():
    """Zero duration_ms is handled gracefully (not ZeroDivisionError)."""
    run_a = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=200, duration_ms=0)]),
        },
    )
    run_b = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=200, duration_ms=100)]),
        },
    )

    # Implementation guards against zero duration; should not raise
    result = diff_runs(run_a, run_b)
    assert result is not None
    # With zero base duration, no timing change should be reported
    assert len(result.timing_changes) == 0


# ============================================================================
# TESTS - diff_runs() - Invariants
# ============================================================================

def test_diff_runs_delta_percentage_rounded():
    """Timing delta percentage is rounded to 1 decimal place."""
    run_a = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=200, duration_ms=100)]),
        },
    )
    run_b = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=200, duration_ms=133)]),
        },
    )

    result = diff_runs(run_a, run_b)

    assert result is not None
    assert len(result.timing_changes) == 1
    delta_pct = result.timing_changes[0].details["duration_ms"]["delta_pct"]
    assert delta_pct == 33.0


def test_diff_runs_deterministic_output():
    """Multiple diffs of same inputs produce identical sorted output."""
    run_a = _make_run(
        nodes_dict={
            "node1": _make_node("node1"),
            "node2": _make_node("node2"),
        },
        edges=[_make_edge("node1", "node2")],
    )
    run_b = _make_run(
        nodes_dict={
            "node3": _make_node("node3"),
            "node1": _make_node("node1"),
        },
        edges=[_make_edge("node1", "node3")],
    )

    result1 = diff_runs(run_a, run_b)
    result2 = diff_runs(run_a, run_b)

    assert result1 is not None
    assert result2 is not None
    assert result1.nodes_added == result2.nodes_added
    assert result1.nodes_removed == result2.nodes_removed


def test_diff_runs_broken_links_sorted():
    """new_broken_links and resolved_broken_links are sorted by (source, target)."""
    analysis_a = Mock()
    analysis_a.broken_links = [
        _make_broken_link("page2", "page3"),
        _make_broken_link("page1", "page2"),
    ]
    analysis_a.auth_violations = []

    analysis_b = Mock()
    analysis_b.broken_links = [
        _make_broken_link("page3", "page4"),
        _make_broken_link("page1", "page2"),
    ]
    analysis_b.auth_violations = []

    run_a = _make_run(analysis=analysis_a)
    run_b = _make_run(analysis=analysis_b)

    result = diff_runs(run_a, run_b)

    assert result is not None
    # new_broken should have page3->page4 (sorted)
    assert len(result.new_broken_links) == 1
    assert result.new_broken_links[0].source == "page3"
    # resolved should have page2->page3 (sorted)
    assert len(result.resolved_broken_links) == 1
    assert result.resolved_broken_links[0].source == "page2"


def test_diff_runs_auth_violations_sorted():
    """new_auth_violations and resolved_auth_violations are sorted by URL."""
    analysis_a = Mock()
    analysis_a.broken_links = []
    analysis_a.auth_violations = [
        _make_auth_violation("https://example.com/page2"),
        _make_auth_violation("https://example.com/page1"),
    ]

    analysis_b = Mock()
    analysis_b.broken_links = []
    analysis_b.auth_violations = [
        _make_auth_violation("https://example.com/page3"),
        _make_auth_violation("https://example.com/page1"),
    ]

    run_a = _make_run(analysis=analysis_a)
    run_b = _make_run(analysis=analysis_b)

    result = diff_runs(run_a, run_b)

    assert result is not None
    assert len(result.new_auth_violations) == 1
    assert result.new_auth_violations[0].url == "https://example.com/page3"
    assert len(result.resolved_auth_violations) == 1
    assert result.resolved_auth_violations[0].url == "https://example.com/page2"


def test_diff_runs_all_lists_sorted():
    """All diff output lists are sorted for deterministic output."""
    run_a = _make_run(
        nodes_dict={
            "node3": _make_node("node3"),
            "node1": _make_node("node1"),
            "node2": _make_node("node2"),
        },
        edges=[
            _make_edge("node3", "node1"),
            _make_edge("node1", "node2"),
        ],
    )
    run_b = _make_run(
        nodes_dict={
            "node5": _make_node("node5"),
            "node4": _make_node("node4"),
            "node1": _make_node("node1"),
        },
        edges=[
            _make_edge("node5", "node4"),
            _make_edge("node4", "node1"),
        ],
    )

    result = diff_runs(run_a, run_b)

    assert result is not None
    assert result.nodes_added == ["node4", "node5"]
    assert result.nodes_removed == ["node2", "node3"]


# ============================================================================
# TESTS - Parameterized Tests
# ============================================================================

@pytest.mark.parametrize("invalid_json", [
    '{"incomplete": ',
    '{invalid json}',
    '["array", "not", "object"]',
    'null',
    '123',
    '"string"',
    '',
])
def test_load_run_various_invalid_json(tmp_path, invalid_json):
    """Test various forms of invalid JSON."""
    run_dir = tmp_path / "test_run"
    run_dir.mkdir()
    report_file = run_dir / "report.json"

    with open(report_file, 'w') as f:
        f.write(invalid_json)

    with pytest.raises((json.JSONDecodeError, Exception)):
        load_run(run_dir)


@pytest.mark.parametrize("version_a,version_b", [
    ("1.0", "2.0"),
    ("1.5", "2.0"),
    ("2.0", "1.0"),
    ("1.0", "1.1"),
])
def test_diff_runs_various_schema_mismatches(version_a, version_b):
    """Test various schema version mismatches."""
    run_a = _make_run(schema_version=version_a)
    run_b = _make_run(schema_version=version_b)

    if version_a != version_b:
        with pytest.raises(Exception):
            diff_runs(run_a, run_b)


@pytest.mark.parametrize("duration_a,duration_b,should_detect", [
    (100, 121, True),   # 21% increase - above threshold
    (100, 150, True),   # 50% increase - above threshold
    (100, 80, False),   # 20% decrease - at threshold (> not >=)
    (100, 110, False),  # 10% increase - below threshold
    (100, 119, False),  # 19% increase - below threshold
    (100, 200, True),   # 100% increase - well above threshold
])
def test_diff_runs_timing_threshold_boundaries(duration_a, duration_b, should_detect):
    """Test timing change detection at various thresholds."""
    run_a = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=200, duration_ms=duration_a)]),
        },
    )
    run_b = _make_run(
        nodes_dict={
            "node1": _make_node("node1", [_make_capture(http_status=200, duration_ms=duration_b)]),
        },
    )

    result = diff_runs(run_a, run_b)

    assert result is not None
    if should_detect:
        assert len(result.timing_changes) == 1
    else:
        assert len(result.timing_changes) == 0


# ============================================================================
# TESTS - Additional Edge Cases
# ============================================================================

def test_diff_runs_large_node_set():
    """Test diff with large number of nodes for performance."""
    nodes_a = {f"node{i}": _make_node(f"node{i}") for i in range(100)}
    nodes_b = {f"node{i}": _make_node(f"node{i}") for i in range(50, 150)}

    run_a = _make_run(nodes_dict=nodes_a)
    run_b = _make_run(nodes_dict=nodes_b)

    result = diff_runs(run_a, run_b)

    assert result is not None
    assert len(result.nodes_added) == 50   # node100..node149
    assert len(result.nodes_removed) == 50  # node0..node49


def test_diff_runs_single_node_each():
    """Test diff with minimal graphs (single node each)."""
    run_a = _make_run(nodes_dict={"node1": _make_node("node1")})
    run_b = _make_run(nodes_dict={"node2": _make_node("node2")})

    result = diff_runs(run_a, run_b)

    assert result is not None
    assert result.nodes_added == ["node2"]
    assert result.nodes_removed == ["node1"]


def test_load_run_with_nested_graph_structure(tmp_path):
    """Test loading run with complex nested graph structure."""
    run_dir = tmp_path / "test_run"
    run_dir.mkdir()
    report_file = run_dir / "report.json"

    complex_data = {
        "id": "run-complex",
        "schema_version": "1.0",
        "timestamp": "2024-01-01T00:00:00Z",
        "graph": {
            "nodes": [
                {
                    "id": "node1",
                    "url": "https://example.com",
                    "captures": [
                        {
                            "status_code": 200,
                            "duration_ms": 100,
                            "headers": {"Content-Type": "text/html"},
                            "body": "Sample content"
                        }
                    ],
                    "metadata": {
                        "depth": 0,
                        "parent": None
                    }
                }
            ],
            "edges": []
        }
    }

    with open(report_file, 'w') as f:
        json.dump(complex_data, f)

    with patch('src.webprobe.differ.Run') as MockRun:
        MockRun.model_validate.return_value = Mock()

        result = load_run(run_dir)

        assert result is not None
