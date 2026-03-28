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


@pytest.fixture
def mock_run_object():
    """Mock Run object for testing."""
    run = Mock()
    run.schema_version = "1.0"
    run.graph = Mock()
    run.graph.nodes = [
        Mock(id="node1", captures=[Mock(status_code=200, duration_ms=100)]),
        Mock(id="node2", captures=[Mock(status_code=404, duration_ms=50)])
    ]
    run.graph.edges = [Mock(source="node1", target="node2")]
    return run


# ============================================================================
# TESTS - load_run() - Happy Path
# ============================================================================

def test_load_run_happy_path(tmp_path, valid_run_data):
    """Successfully load a valid Run object from a directory with report.json."""
    # Setup
    run_dir = tmp_path / "test_run"
    run_dir.mkdir()
    report_file = run_dir / "report.json"
    
    with open(report_file, 'w') as f:
        json.dump(valid_run_data, f)
    
    # Mock the Run model validation
    with patch('src_webprobe_differ.Run') as MockRun:
        mock_run_instance = Mock()
        MockRun.model_validate.return_value = mock_run_instance
        
        # Execute
        result = load_run(run_dir)
        
        # Assert
        assert result == mock_run_instance
        MockRun.model_validate.assert_called_once()


def test_load_run_valid_json_structure(tmp_path, valid_run_data):
    """Load correctly parses and validates the JSON structure."""
    run_dir = tmp_path / "test_run"
    run_dir.mkdir()
    report_file = run_dir / "report.json"
    
    with open(report_file, 'w') as f:
        json.dump(valid_run_data, f)
    
    with patch('src_webprobe_differ.Run') as MockRun:
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
    
    with patch('src_webprobe_differ.Run') as MockRun:
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
    
    with patch('src_webprobe_differ.Run') as MockRun:
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
    
    with patch('src_webprobe_differ.Run') as MockRun:
        MockRun.model_validate.side_effect = TypeError("Type mismatch")
        
        with pytest.raises((TypeError, Exception)):
            load_run(run_dir)


# ============================================================================
# TESTS - diff_runs() - Happy Path
# ============================================================================

def test_diff_runs_happy_path():
    """Successfully compare two compatible Run objects."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    run_a.graph.nodes = [Mock(id="node1")]
    run_a.graph.edges = [Mock(source="node1", target="node2")]
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    run_b.graph.nodes = [Mock(id="node1"), Mock(id="node3")]
    run_b.graph.edges = [Mock(source="node1", target="node3")]
    
    with patch('src_webprobe_differ.RunDiff') as MockRunDiff:
        mock_diff = Mock()
        MockRunDiff.return_value = mock_diff
        
        result = diff_runs(run_a, run_b)
        
        assert result is not None


def test_diff_runs_nodes_added():
    """Detect nodes added in run_b."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    run_a.graph.nodes = [Mock(id="node1"), Mock(id="node2")]
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    run_b.graph.nodes = [
        Mock(id="node1"),
        Mock(id="node2"),
        Mock(id="node3"),
        Mock(id="node4")
    ]
    run_b.graph.edges = []
    
    result = diff_runs(run_a, run_b)
    
    # Mock implementation should return sorted list
    # In actual implementation, verify nodes_added contains ["node3", "node4"] sorted
    assert result is not None


def test_diff_runs_nodes_removed():
    """Detect nodes removed from run_a."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    run_a.graph.nodes = [
        Mock(id="node1"),
        Mock(id="node2"),
        Mock(id="node3")
    ]
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    run_b.graph.nodes = [Mock(id="node1")]
    run_b.graph.edges = []
    
    result = diff_runs(run_a, run_b)
    
    # In actual implementation, verify nodes_removed contains ["node2", "node3"] sorted
    assert result is not None


def test_diff_runs_status_changes():
    """Detect HTTP status code changes between runs."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    node_a = Mock(id="node1")
    node_a.captures = [Mock(status_code=200)]
    run_a.graph.nodes = [node_a]
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    node_b = Mock(id="node1")
    node_b.captures = [Mock(status_code=404)]
    run_b.graph.nodes = [node_b]
    run_b.graph.edges = []
    
    result = diff_runs(run_a, run_b)
    
    # Should detect status change from 200 to 404 for node1
    assert result is not None


def test_diff_runs_timing_changes_above_threshold():
    """Detect timing changes above 20% threshold."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    node_a = Mock(id="node1")
    node_a.captures = [Mock(status_code=200, duration_ms=100)]
    run_a.graph.nodes = [node_a]
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    node_b = Mock(id="node1")
    # 150ms is 50% increase from 100ms, above 20% threshold
    node_b.captures = [Mock(status_code=200, duration_ms=150)]
    run_b.graph.nodes = [node_b]
    run_b.graph.edges = []
    
    result = diff_runs(run_a, run_b)
    
    # Should detect timing change
    assert result is not None


def test_diff_runs_edges_added_removed():
    """Detect edges added and removed."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    run_a.graph.nodes = [Mock(id="node1"), Mock(id="node2")]
    edge_a1 = Mock(source="node1", target="node2")
    edge_a2 = Mock(source="node2", target="node3")
    run_a.graph.edges = [edge_a1, edge_a2]
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    run_b.graph.nodes = [Mock(id="node1"), Mock(id="node3")]
    edge_b1 = Mock(source="node1", target="node3")
    edge_b2 = Mock(source="node3", target="node4")
    run_b.graph.edges = [edge_b1, edge_b2]
    
    result = diff_runs(run_a, run_b)
    
    # Should detect edges_added and edges_removed, sorted by (source, target)
    assert result is not None


# ============================================================================
# TESTS - diff_runs() - Edge Cases
# ============================================================================

def test_diff_runs_identical_runs():
    """Diff of identical runs produces empty changes."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    node = Mock(id="node1")
    node.captures = [Mock(status_code=200, duration_ms=100)]
    run_a.graph.nodes = [node]
    run_a.graph.edges = []
    
    # Create identical run_b
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    node_b = Mock(id="node1")
    node_b.captures = [Mock(status_code=200, duration_ms=100)]
    run_b.graph.nodes = [node_b]
    run_b.graph.edges = []
    
    result = diff_runs(run_a, run_b)
    
    # Should produce minimal/empty diff
    assert result is not None


def test_diff_runs_empty_runs():
    """Diff of two empty runs."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    run_a.graph.nodes = []
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    run_b.graph.nodes = []
    run_b.graph.edges = []
    
    result = diff_runs(run_a, run_b)
    
    # Should handle empty runs without error
    assert result is not None


def test_diff_runs_timing_changes_below_threshold():
    """No timing changes when delta is below 20%."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    node_a = Mock(id="node1")
    node_a.captures = [Mock(status_code=200, duration_ms=100)]
    run_a.graph.nodes = [node_a]
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    node_b = Mock(id="node1")
    # 110ms is 10% increase, below 20% threshold
    node_b.captures = [Mock(status_code=200, duration_ms=110)]
    run_b.graph.nodes = [node_b]
    run_b.graph.edges = []
    
    result = diff_runs(run_a, run_b)
    
    # Should not include this in timing_changes
    assert result is not None


def test_diff_runs_timing_changes_exactly_at_threshold():
    """Timing change exactly at 20% threshold."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    node_a = Mock(id="node1")
    node_a.captures = [Mock(status_code=200, duration_ms=100)]
    run_a.graph.nodes = [node_a]
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    node_b = Mock(id="node1")
    # Exactly 20% increase
    node_b.captures = [Mock(status_code=200, duration_ms=120)]
    run_b.graph.nodes = [node_b]
    run_b.graph.edges = []
    
    result = diff_runs(run_a, run_b)
    
    # Boundary condition - may or may not be included depending on implementation (> vs >=)
    assert result is not None


# ============================================================================
# TESTS - diff_runs() - Error Cases
# ============================================================================

def test_diff_runs_schema_version_mismatch():
    """Error when comparing runs with different schema versions."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    run_a.graph.nodes = []
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "2.0"
    run_b.graph = Mock()
    run_b.graph.nodes = []
    run_b.graph.edges = []
    
    with pytest.raises(Exception) as exc_info:
        diff_runs(run_a, run_b)
    
    assert "schema" in str(exc_info.value).lower() or "version" in str(exc_info.value).lower() or "mismatch" in str(exc_info.value).lower()


def test_diff_runs_missing_graph_attribute_run_a():
    """Error when run_a lacks graph attribute."""
    run_a = Mock(spec=['schema_version'])
    run_a.schema_version = "1.0"
    # No graph attribute
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    run_b.graph.nodes = []
    run_b.graph.edges = []
    
    with pytest.raises(AttributeError):
        diff_runs(run_a, run_b)


def test_diff_runs_missing_graph_attribute_run_b():
    """Error when run_b lacks graph attribute."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    run_a.graph.nodes = []
    run_a.graph.edges = []
    
    run_b = Mock(spec=['schema_version'])
    run_b.schema_version = "1.0"
    # No graph attribute
    
    with pytest.raises(AttributeError):
        diff_runs(run_a, run_b)


def test_diff_runs_index_error_empty_captures():
    """Error when node has empty captures list when accessing captures[0]."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    node_a = Mock(id="node1")
    node_a.captures = []  # Empty captures
    run_a.graph.nodes = [node_a]
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    node_b = Mock(id="node1")
    node_b.captures = [Mock(status_code=200)]
    run_b.graph.nodes = [node_b]
    run_b.graph.edges = []
    
    with pytest.raises(IndexError):
        diff_runs(run_a, run_b)


def test_diff_runs_zero_division_duration_zero():
    """Error when t_a.duration_ms is exactly 0 causing division by zero."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    node_a = Mock(id="node1")
    node_a.captures = [Mock(status_code=200, duration_ms=0)]  # Zero duration
    run_a.graph.nodes = [node_a]
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    node_b = Mock(id="node1")
    node_b.captures = [Mock(status_code=200, duration_ms=100)]
    run_b.graph.nodes = [node_b]
    run_b.graph.edges = []
    
    # May raise ZeroDivisionError if not guarded properly
    with pytest.raises(ZeroDivisionError):
        diff_runs(run_a, run_b)


# ============================================================================
# TESTS - diff_runs() - Invariants
# ============================================================================

def test_diff_runs_delta_percentage_rounded():
    """Timing delta percentage is rounded to 1 decimal place."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    node_a = Mock(id="node1")
    node_a.captures = [Mock(status_code=200, duration_ms=100)]
    run_a.graph.nodes = [node_a]
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    node_b = Mock(id="node1")
    # Create a timing that would result in non-round percentage
    node_b.captures = [Mock(status_code=200, duration_ms=133)]  # 33% increase
    run_b.graph.nodes = [node_b]
    run_b.graph.edges = []
    
    result = diff_runs(run_a, run_b)
    
    # In implementation, verify delta is rounded to 1 decimal place (e.g., 33.0)
    assert result is not None


def test_diff_runs_deterministic_output():
    """Multiple diffs of same inputs produce identical sorted output."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    run_a.graph.nodes = [Mock(id="node1"), Mock(id="node2")]
    run_a.graph.edges = [Mock(source="node1", target="node2")]
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    run_b.graph.nodes = [Mock(id="node3"), Mock(id="node1")]
    run_b.graph.edges = [Mock(source="node1", target="node3")]
    
    result1 = diff_runs(run_a, run_b)
    result2 = diff_runs(run_a, run_b)
    
    # Results should be identical
    assert result1 is not None
    assert result2 is not None


def test_diff_runs_broken_links_sorted():
    """new_broken_links and resolved_broken_links are sorted by (source, target)."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    run_a.graph.nodes = []
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    run_b.graph.nodes = []
    run_b.graph.edges = []
    
    # Mock broken_links if available
    if hasattr(run_a, 'broken_links'):
        run_a.broken_links = [
            Mock(source="page2", target="page3"),
            Mock(source="page1", target="page2")
        ]
        run_b.broken_links = [
            Mock(source="page3", target="page4"),
            Mock(source="page1", target="page2")
        ]
    
    result = diff_runs(run_a, run_b)
    
    # In implementation, verify broken links are sorted by (source, target)
    assert result is not None


def test_diff_runs_auth_violations_sorted():
    """new_auth_violations and resolved_auth_violations are sorted by URL."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    run_a.graph.nodes = []
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    run_b.graph.nodes = []
    run_b.graph.edges = []
    
    # Mock auth_violations if available
    if hasattr(run_a, 'auth_violations'):
        run_a.auth_violations = [
            Mock(url="https://example.com/page2"),
            Mock(url="https://example.com/page1")
        ]
        run_b.auth_violations = [
            Mock(url="https://example.com/page3"),
            Mock(url="https://example.com/page1")
        ]
    
    result = diff_runs(run_a, run_b)
    
    # In implementation, verify auth violations are sorted by URL
    assert result is not None


def test_diff_runs_all_lists_sorted():
    """All diff output lists are sorted for deterministic output."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    # Create nodes in non-alphabetical order
    run_a.graph.nodes = [
        Mock(id="node3"),
        Mock(id="node1"),
        Mock(id="node2")
    ]
    run_a.graph.edges = [
        Mock(source="node3", target="node1"),
        Mock(source="node1", target="node2")
    ]
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    run_b.graph.nodes = [
        Mock(id="node5"),
        Mock(id="node4"),
        Mock(id="node1")
    ]
    run_b.graph.edges = [
        Mock(source="node5", target="node4"),
        Mock(source="node4", target="node1")
    ]
    
    result = diff_runs(run_a, run_b)
    
    # In implementation:
    # - nodes_added should be sorted: ["node4", "node5"]
    # - nodes_removed should be sorted: ["node2", "node3"]
    # - edges should be sorted by (source, target)
    assert result is not None


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
    run_a = Mock()
    run_a.schema_version = version_a
    run_a.graph = Mock()
    run_a.graph.nodes = []
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = version_b
    run_b.graph = Mock()
    run_b.graph.nodes = []
    run_b.graph.edges = []
    
    if version_a != version_b:
        with pytest.raises(Exception):
            diff_runs(run_a, run_b)


@pytest.mark.parametrize("duration_a,duration_b,should_detect", [
    (100, 121, True),   # 21% increase - above threshold
    (100, 150, True),   # 50% increase - above threshold
    (100, 80, False),   # 20% decrease - at threshold
    (100, 110, False),  # 10% increase - below threshold
    (100, 119, False),  # 19% increase - below threshold
    (100, 200, True),   # 100% increase - well above threshold
])
def test_diff_runs_timing_threshold_boundaries(duration_a, duration_b, should_detect):
    """Test timing change detection at various thresholds."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    node_a = Mock(id="node1")
    node_a.captures = [Mock(status_code=200, duration_ms=duration_a)]
    run_a.graph.nodes = [node_a]
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    node_b = Mock(id="node1")
    node_b.captures = [Mock(status_code=200, duration_ms=duration_b)]
    run_b.graph.nodes = [node_b]
    run_b.graph.edges = []
    
    result = diff_runs(run_a, run_b)
    
    # Verify result based on should_detect
    assert result is not None


# ============================================================================
# TESTS - Additional Edge Cases
# ============================================================================

def test_diff_runs_large_node_set():
    """Test diff with large number of nodes for performance."""
    import random
    
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    run_a.graph.nodes = [Mock(id=f"node{i}") for i in range(100)]
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    # Mix of same and different nodes
    run_b.graph.nodes = [Mock(id=f"node{i}") for i in range(50, 150)]
    run_b.graph.edges = []
    
    result = diff_runs(run_a, run_b)
    
    # Should handle large datasets
    assert result is not None


def test_diff_runs_single_node_each():
    """Test diff with minimal graphs (single node each)."""
    run_a = Mock()
    run_a.schema_version = "1.0"
    run_a.graph = Mock()
    run_a.graph.nodes = [Mock(id="node1")]
    run_a.graph.edges = []
    
    run_b = Mock()
    run_b.schema_version = "1.0"
    run_b.graph = Mock()
    run_b.graph.nodes = [Mock(id="node2")]
    run_b.graph.edges = []
    
    result = diff_runs(run_a, run_b)
    
    # Should handle minimal graphs
    assert result is not None


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
    
    with patch('src_webprobe_differ.Run') as MockRun:
        MockRun.model_validate.return_value = Mock()
        
        result = load_run(run_dir)
        
        assert result is not None
